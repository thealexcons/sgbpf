#include "Service.h"

namespace sgbpf 
{

// Helper functions
namespace {

enum {
    IO_READ,
    IO_WRITE,
};

typedef struct __attribute__((packed)) conn_info  {
    int      fd;
    uint16_t type;
    uint16_t bgid;
} conn_info_t;

// Add a socket read operation to the IO ring
inline void addSocketRead(io_uring *ring, int fd, uint16_t bgid, size_t message_size, unsigned flags) {
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv(sqe, fd, NULL, message_size, 0);
    io_uring_sqe_set_flags(sqe, flags);
    sqe->buf_group = bgid;
    sqe->ioprio = IORING_RECVSEND_POLL_FIRST;

    conn_info_t conn_i = {
        .fd = fd,
        .type = IO_READ,
        .bgid = bgid,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_info_t));
}


// Add a scatter send request to the IO ring
inline void addScatterSend(io_uring* ring, int skfd, const msghdr* msgh) {
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_sendmsg(sqe, skfd, msgh, 0);
    io_uring_sqe_set_flags(sqe, 0);

    conn_info_t conn_i = {
        .fd = skfd,
        .type = IO_WRITE,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_info_t));
}


// Open a socket for a worker, returning the FD and port number
std::pair<int, uint16_t> openWorkerSocket() {
    sockaddr_in workerAddr;
    memset(&workerAddr, 0, sizeof(sockaddr_in));
    workerAddr.sin_family = AF_INET;
    workerAddr.sin_port = 0;    // use any
    workerAddr.sin_addr.s_addr = 0;

    int workerSk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( bind(workerSk, (const struct sockaddr *) &workerAddr, sizeof(workerAddr)) < 0 )
        throw std::runtime_error{"Failed bind() on a worker socket"};

    // Get the port assigned
    socklen_t namelen = sizeof(sockaddr_in);
    if (getsockname(workerSk, (struct sockaddr *) &workerAddr, &namelen) < 0)
        throw std::runtime_error{"Failed getsockname() on a worker socket"};

    return { workerSk, workerAddr.sin_port };
}

inline uint32_t getRequestMapIdx(uint32_t reqID) {
    return reqID & (MAX_ACTIVE_REQUESTS_ALLOWED - 1);
}

} // close anonymous namespce


uint32_t Service::s_nextRequestID = 0;


int handleRingBufEpollEvent(void* ctx, void* data, size_t data_sz);


Service::Service(Context& ctx, 
                 const std::vector<Worker>& workers,
                 PacketAction packetAction,
                 CtrlSockMode ctrlSockMode) 
    : d_ctx{ctx}
    , d_workers{workers}
    , d_ioCtx{(uint32_t) d_workers.size() * 4}
    , d_numSkReads{0}
    , d_packetAction{packetAction}
    , d_ctrlSockMode{ctrlSockMode}
{
    if (d_workers.size() > MAX_SOCKETS_ALLOWED)
        throw std::invalid_argument{"Exceeded max number of workers allowed"};

    // d_activeRequests.reserve(MAX_ACTIVE_REQUESTS_ALLOWED);
    d_activeRequests = new Request[MAX_ACTIVE_REQUESTS_ALLOWED];

    // Provide an initial buffer for packets
    provideBuffers(true);

    // Prepare epoll-based method for ringbuf
    if (d_ctrlSockMode == CtrlSockMode::Epoll) {
        // d_ctrlSkRingBuf = ring_buffer__new(d_ctx.ctrlSkRingBufMap().fd(), handleRingBufEpollEvent, &d_notificationRingBufCallback, NULL);
        d_ctrlSkRingBuf = ring_buffer__new(d_ctx.ctrlSkRingBufMap().fd(), handleRingBufEpollEvent, this, NULL);
    }

    // Configure the worker sockets
    int workerFds[MAX_SOCKETS_ALLOWED];
    for (auto i = 0u; i < d_workers.size(); ++i) {
        const auto [ workerSkFd, workerLocalPort ] = openWorkerSocket();
        d_workers[i].setSocketFd(workerSkFd);
        workerFds[i] = workerSkFd;
        
        worker_info_t wi = {
            .worker_ip = d_workers[i].ipAddressNet(),
            .worker_port = d_workers[i].portNet(),
            .app_port = workerLocalPort,
        };
        d_ctx.workersMap().update(&i, &wi);

        const worker_resp_status_t resp_status = WAITING_FOR_RESPONSE;
        d_ctx.workersHashMap().update(&wi, &resp_status);
    }
    io_uring_register_files(&d_ioCtx.ring, workerFds, d_workers.size());
    
    // Configure the gather-control socket
    d_ctrlSkFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  
    if (d_ctrlSkFd < 0)
        throw std::runtime_error{"Failed socket() on gather-control socket"}; 

    uint16_t ctrlPort = 9999; // TODO use any
    sockaddr_in ctrlSkAddr;
    memset(&ctrlSkAddr, 0, sizeof(ctrlSkAddr));
    ctrlSkAddr.sin_family = AF_INET;
    ctrlSkAddr.sin_port = htons(ctrlPort);    
    ctrlSkAddr.sin_addr.s_addr = 0;
    if ( bind(d_ctrlSkFd, (const struct sockaddr *) &ctrlSkAddr, sizeof(sockaddr_in)) < 0 )
        throw std::runtime_error{"Failed bind() on gather-control socket"};

    d_ctx.setGatherControlPort(ctrlPort, d_ctrlSockMode == CtrlSockMode::Epoll);


    // Configure the scatter socket for sending
    d_scatterSkFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  
    if (d_scatterSkFd < 0)
        throw std::runtime_error{"Failed socket() on scatter socket"};

    memset(&d_scatterSkAddr, 0, sizeof(d_scatterSkAddr));
    d_scatterSkAddr.sin_family = AF_INET;
    d_scatterSkAddr.sin_port = htons(PORT);
    d_scatterSkAddr.sin_addr.s_addr = INADDR_ANY;
    if (bind(d_scatterSkFd, (const struct sockaddr *) &d_scatterSkAddr, sizeof(sockaddr_in)) < 0)
        throw std::runtime_error{"Failed bind() on scatter socket"};

    d_ctx.setScatterPort(PORT);
}

Service::~Service()
{
    delete[] d_activeRequests;

    if (d_ctrlSockMode == CtrlSockMode::Epoll) {
        ring_buffer__free(d_ctrlSkRingBuf);
    }

    // Free all the allocated memory used for storing packets 
    for (auto i = 0u; i < d_packetBufferPool.size(); ++i) {
        auto buffer = d_packetBufferPool[i];
        io_uring_sqe* sqe = io_uring_get_sqe(&d_ioCtx.ring);
        io_uring_prep_remove_buffers(sqe, NUM_BUFFERS, i);
        delete[] buffer;
    }
    io_uring_submit(&d_ioCtx.ring);

    // Close all sockets
    close(d_scatterSkFd);
    close(d_ctrlSkFd);
    for (auto w : d_workers)
        close(w.socketFd());
}


Request* Service::scatter(const char* msg, size_t len, ReqParams params)
{
    if (params.completionPolicy == sgbpf::GatherCompletionPolicy::WaitN && params.numWorkersToWait == 0) {
        throw std::invalid_argument{"The numWorkersToWait field in RequestParams must be set if using GatherCompletionPolicy::WaitN"};
    }

    unsigned char msgFlags = static_cast<int>(params.completionPolicy);
    uint32_t num_pks = 1; // the num of workers to wait for (default is 1)
    if (params.completionPolicy == GatherCompletionPolicy::WaitN) {
        params.numWorkersToWait = std::min(params.numWorkersToWait, (uint32_t) d_workers.size());
        num_pks = params.numWorkersToWait;
    } else if (params.completionPolicy == GatherCompletionPolicy::WaitAll) {
        num_pks = d_workers.size();
    }

    bool allowPks = d_packetAction == PacketAction::Allow;

    int reqId = s_nextRequestID++;
    auto idx = getRequestMapIdx(reqId);
    Request* req = new (d_activeRequests + idx) Request{reqId, params, &d_packetBufferPool, &d_workers, d_packetAction, d_ctrlSockMode};

    // Register response packet buffers for this SG request
    // Every ScatterGatherRequest instance allocates a set of buffers to store the
    // received packet contents. These buffers are registered with io_uring so that
    // the buffers are populated automatically using "automatic buffer selection".
    // Each request defines a group of buffers (hence the group buffer ID is equivalent
    // to the request ID) and the buffer ID is automatically set by io_uring and obtained
    // in the completion queue. This ID can be used by the developer
    // as a pointer into the buffer to read the packet contents.
    // req->registerBuffers(&d_ioCtx.ring);

    // Add IO operations to the ring and submit as batch to io_uring
    sg_msg_t scatter_msg;
    scatter_msg.hdr.req_id = reqId;
    scatter_msg.hdr.seq_num = 0;
    scatter_msg.hdr.num_pks = num_pks; 
    scatter_msg.hdr.body_len = std::min(len, BODY_LEN);
    scatter_msg.hdr.msg_type = SCATTER_MSG;
    scatter_msg.hdr.flags = msgFlags;
    strncpy(scatter_msg.body, msg, scatter_msg.hdr.body_len);

    struct iovec iov = {
		.iov_base = &scatter_msg,
		.iov_len = sizeof(sg_msg_t),
	};
	struct msghdr msgh;
    memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name = &d_scatterSkAddr;
	msgh.msg_namelen = sizeof(sockaddr_in);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

    addScatterSend(&d_ioCtx.ring, d_scatterSkFd, &msgh);

    if (allowPks) {
        auto bgid = d_packetBufferPool.size() - 1; // use the most recent bgid
        for (auto w : d_workers) {
            for (auto i = 0u; i < params.numPksPerRespMsg; i++) {
                // check for re-allocation of buffers
                if (d_numSkReads == NUM_BUFFERS) {
                    bgid = provideBuffers();
                    d_numSkReads = 0;
                }
                d_numSkReads++;
                addSocketRead(&d_ioCtx.ring, w.socketFd(), bgid, Request::MaxBufferSize, IOSQE_BUFFER_SELECT);
            }
        }
    }

    if (d_ctrlSockMode == CtrlSockMode::Block) {
        io_uring_sqe *sqe = io_uring_get_sqe(&d_ioCtx.ring);
        io_uring_prep_recv(sqe, d_ctrlSkFd, &req->d_ctrlSkBuf, Request::MaxBufferSize, 0);
        io_uring_sqe_set_flags(sqe, 0);

        conn_info_t conn_i;
        conn_i.fd = d_ctrlSkFd;
        // For ctrl sk events, use the final 32 bits to represent the request ID
        auto reqIdField = (uint32_t*) (((char*)&conn_i) + sizeof(uint32_t));
        *reqIdField = reqId; 
        memcpy(&sqe->user_data, &conn_i, sizeof(conn_info_t));

        auto waitFor = 2 + allowPks * d_workers.size() * params.numPksPerRespMsg;
        req->startTimer();
        io_uring_submit_and_wait(&d_ioCtx.ring, waitFor);
        return req;
    }

    io_uring_submit(&d_ioCtx.ring);
    req->startTimer();
    return req;
}


void Service::processEvents(int requestID) {
    processPendingEvents(requestID);
}



void Service::processPendingEvents(int requestID) {
    bool processOnlyGivenReq = (requestID != DEFAULT_REQUEST_ID);

    io_uring_cqe *cqe;
    unsigned count = 0;
    unsigned head;
    bool submitPendingReads = false;

    io_uring_for_each_cqe(&d_ioCtx.ring, head, cqe) {   
        ++count;
        if (cqe->res == -ENOBUFS) {
            // should not happen
            throw std::runtime_error{"FATAL: no buffers available to read packet data."};
        }

        const auto conn_i = reinterpret_cast<conn_info_t*>(&cqe->user_data);

        // If this is a cqe for the ctrl sk, just continue
        if (d_ctrlSockMode == CtrlSockMode::Block && conn_i->fd == d_ctrlSkFd) {
            const auto reqID = reinterpret_cast<uint32_t*>(((char*)conn_i) + sizeof(uint32_t));
            #ifdef DEBUG_PRINT
            std::cout << "got control socket cqe for reqID " << *reqID << std::endl; 
            #endif

            auto req = &d_activeRequests[getRequestMapIdx(*reqID)];
            if (!req->isActive()) {
                continue;
            }
            req->d_ctrlSockReady = true;
            if (d_packetAction == PacketAction::Discard) {
                req->d_status = Request::Status::Ready;
            }
            continue;
        }
        
        if (conn_i->type == IO_READ && cqe->res > 0) {
            auto bgid = conn_i->bgid;                               // the buffer group ID
            auto bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;       // the packet's buffer index within the group
            const auto resp = (sg_msg_t*) (d_packetBufferPool[bgid] + bid * Request::MaxBufferSize);
            auto req = &d_activeRequests[getRequestMapIdx(resp->hdr.req_id)];
            if (!req->isActive()) {
                continue;
            }

            // If we are only processing packets for a given request
            if (processOnlyGivenReq && (req->id() != requestID || resp->hdr.req_id != static_cast<uint32_t>(req->id()))) {
                #ifdef DEBUG_PRINT
                std::cout << "[DEBUG] Ignoring packet with ID " << req->id() << ", only processing pks from req " << requestID << '\n';                    
                std::cout << "\t hdr.req_id = " << resp->hdr.req_id << " req->id() = " << req->id() << " requestID = " << requestID << std::endl;
                #endif
                continue;
            }

            // Drop any unnecessary packets (for messages beyond N in waitN or 1 in waitAny)
            // this is currently the implementation
            if (req->d_status == Request::Status::Ready) {
                #ifdef DEBUG_PRINT
                std::cout << "[DEBUG] Dropping packet (request completed already)" << std::endl;
                #endif
                continue;
            }

            if (req->d_status == Request::Status::TimedOut || req->hasTimedOut()) {
                #ifdef DEBUG_PRINT
                std::cout << "[DEBUG] Request " << req->id() << " has timed out" << std::endl;                    
                #endif
                req->d_status = Request::Status::TimedOut;
                continue;
            }
            
            #ifdef DEBUG_PRINT
            std::cout << "Got pk on fd " << conn_i->fd << " for req " << req->id() << std::endl;
            #endif

            req->addBufferPtr(conn_i->fd, bgid, bid);
            if (req->receivedSufficientPackets()) {
                #ifdef DEBUG_PRINT
                std::cout << "[DEBUG] Request " << req->id() << " is ready" << std::endl;
                #endif
                req->d_status = Request::Status::Ready;
                continue;
            }

            // check for multi-packet message and add more reads if necessary
            if (req->d_expectedPacketsPerMessage != resp->hdr.num_pks && resp->hdr.num_pks > 1) {
                req->d_expectedPacketsPerMessage = resp->hdr.num_pks;

                int remaining = 0;
                for (const auto& [wfd, ptrs] : req->d_workerBufferPtrs) {
                    auto pksRemainingForThisWorker = abs(req->d_expectedPacketsPerMessage - ptrs.size());
                    if (pksRemainingForThisWorker > 0) {
                        remaining += pksRemainingForThisWorker;

                        // Add the remaining socket read operations to the SQ
                        auto bgid = d_packetBufferPool.size() - 1;
                        for (auto i = 0; i < pksRemainingForThisWorker; i++) {
                            // check for re-allocation of buffers
                            if (d_numSkReads == NUM_BUFFERS) {
                                bgid = provideBuffers();
                                d_numSkReads = 0;
                            }
                            d_numSkReads++;
                            addSocketRead(&d_ioCtx.ring, wfd, bgid, Request::MaxBufferSize, IOSQE_BUFFER_SELECT);
                        }
                    }
                }
                submitPendingReads = (remaining > 0);
                // if (submitPendingReads) {
                //     std::cout << "remaining: " << remaining << std::endl;
                //     std::cout << "req " << req->id() << " has num_pks = " << resp->hdr.num_pks << std::endl;
                // }          
            }
        }
    }
    io_uring_cq_advance(&d_ioCtx.ring, count);

    if (submitPendingReads) {
        #ifdef DEBUG_PRINT
        std::cout << "submitting pending reads from event loop (mistmatch in expected number of packets in resp)" << std::endl;
        #endif
        io_uring_submit(&d_ioCtx.ring);
        submitPendingReads = false;
    }
}


void Service::freeRequest(Request* req, bool immediate) {
    // Send a clean up message to eBPF to reset any old state
    sg_clean_req_msg_t cleanMsg = {
        .magic = SG_CLEAN_REQ_MSG_MAGIC,
        .req_id = static_cast<unsigned int>(req->id()),
    };
    struct iovec iov = {
		.iov_base = &cleanMsg,
		.iov_len = sizeof(sg_clean_req_msg_t),
	};

	struct msghdr msgh;
    memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name = &d_scatterSkAddr;
	msgh.msg_namelen = sizeof(sockaddr_in);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

    io_uring_sqe *sqe = io_uring_get_sqe(&d_ioCtx.ring);
    io_uring_prep_sendmsg(sqe, d_scatterSkFd, &msgh, 0);
    io_uring_sqe_set_flags(sqe, 0);
    if (immediate)
        io_uring_submit(&d_ioCtx.ring);
}

uint16_t Service::provideBuffers(bool immediate) {
    // Register packet buffers for buffer selection
    char* buffer  = new char[NUM_BUFFERS * Request::MaxBufferSize];
    d_packetBufferPool.push_back(buffer);

    #ifdef DEBUG_PRINT
    std::cout << "[DEBUG] Providing buffers to the kernel (new bgid = "
              << d_packetBufferPool.size() - 1 << ") num reads = " << d_numSkReads << std::endl;
    #endif
    auto bgid = d_packetBufferPool.size() - 1;  // the idx of the buffer in the pool
    io_uring_sqe* sqe = io_uring_get_sqe(&d_ioCtx.ring);
    io_uring_prep_provide_buffers(sqe, buffer, Request::MaxBufferSize, NUM_BUFFERS, bgid, 0);

    if (immediate) {
        io_uring_submit(&d_ioCtx.ring);
        io_uring_cqe* cqe;
        io_uring_wait_cqe(&d_ioCtx.ring, &cqe);
        if (cqe->res < 0)
            throw std::runtime_error{"Failed to provide io_uring buffers to the kernel"};
        io_uring_cqe_seen(&d_ioCtx.ring, cqe);
    }
    return bgid;
}


int handleRingBufEpollEvent(void* ctx, void* data, size_t data_sz)
{
    auto service = (Service*) ctx;
    auto msg = (sg_msg_t*) data;

    if (service->d_notificationRingBufCallback) {
        service->d_notificationRingBufCallback(msg->body, msg->hdr.req_id);
        return 0;
    }

    #ifdef DEBUG_PRINT
    std::cerr << "WARNING: callback function not set for CtrlSockMode::Epoll" << std::endl;
    #endif
	return 0;
} 

} // close namespace sgbpf