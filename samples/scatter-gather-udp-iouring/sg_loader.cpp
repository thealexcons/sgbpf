#include <vector>
#include <chrono>
#include <unordered_map>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cassert>
#include <csignal>
#include <thread>

#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <liburing.h>

#include "ebpfpp/Program.h"
#include "ebpfpp/Map.h"
#include "ebpfpp/Object.h"
#include "ebpfpp/Util.h"
#include "ebpfpp/Hook.h"

#include "common.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define SQ_POLL_MODE_ENABLED 1

////////////////////////////
////////   Worker   //////// 
////////////////////////////

class Worker 
{
private:
    uint32_t    d_ipAddressNet;
    uint16_t    d_portNet;
    std::string d_ipAddress;
    uint16_t    d_port;
    int         d_skFd = -1;

public:

    // CONSTRUCTORS
    Worker(std::string ipAddress, uint16_t port);

    // SETTER
    void setSocketFd(int fd) { d_skFd = fd; };

    // GETTERS
    const uint32_t ipAddressNet() const { return d_ipAddressNet; }
    const uint16_t portNet() const { return d_portNet; }
    std::string ipAddress() const { return d_ipAddress; }
    uint16_t port() const { return d_port; }
    int socketFd() const { return d_skFd; }

    // STATIC METHODS
    static std::vector<Worker> fromFile(const std::string& filePath);
};

Worker::Worker(std::string ipAddress, uint16_t port)
    : d_ipAddress{std::move(ipAddress)}
    , d_port{port}
{
    if (!inet_pton(AF_INET, d_ipAddress.c_str(), &d_ipAddressNet))
        throw std::runtime_error{"Invalid IPv4 address in worker config"};
    
    d_portNet = htons(d_port);
}

std::vector<Worker> Worker::fromFile(const std::string& filePath)
{
    std::vector<Worker> dests;

    std::ifstream file(filePath);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line) && !line.empty() && line[0] != '#') {
            char *ptr;
            ptr = strtok(line.data(), ":");
            if (!ptr)
                throw std::runtime_error{"Invalid workers config file"};
                
            std::string ipStr{ptr, strlen(ptr)};

            ptr = strtok(NULL, ":");
            if (!ptr)
                throw std::runtime_error{"Invalid workers config file"};
            
            auto port = static_cast<uint16_t>(std::stoi(std::string{ptr, strlen(ptr)}));

            dests.emplace_back(ipStr, port);
        }
        file.close();
    }

    return dests;
}


namespace {

enum {
    IO_READ,
    IO_WRITE,
};

typedef struct conn_info {
    int   fd;
    __u16 type;
    __u16 bgid;    // reqID
} conn_info;

// void add_provide_buffers(struct io_uring* ring, void* buffers, int buffGroupID) {
//     // Register packet buffers for buffer selection for the given request (buffGroupID)
//     io_uring_sqe* sqe = io_uring_get_sqe(ring);
//     io_uring_prep_provide_buffers(
//         sqe, buffers, IOUringContext::MaxBufferSize, IOUringContext::NumBuffers, buffGroupID, 0
//     );
//     // io_uring_submit(ring);

//     // move this error handling somewhere else?    
//     // io_uring_cqe* cqe;
//     // io_uring_wait_cqe(ring, &cqe);
//     // if (cqe->res < 0)
//     //     throw std::runtime_error{"Failed to provide buffers during io_uring setup"};
//     // io_uring_cqe_seen(ring, cqe);
// }

void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t message_size, unsigned flags) {
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv(sqe, fd, NULL, message_size, MSG_WAITALL); // wait for all fragments to arrive
    io_uring_sqe_set_flags(sqe, flags);
    sqe->buf_group = gid;

    conn_info conn_i = {
        .fd = fd,
        .type = IO_READ,
        .bgid = gid,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_info));
}


void add_scatter_send(struct io_uring* ring, int skfd, int reqID, sockaddr_in* servAddr, const char* msg, size_t len) {
    // Send the message to itself
    sg_msg_t scatter_msg;
    memset(&scatter_msg, 0, sizeof(sg_msg_t));
    scatter_msg.hdr.req_id = reqID;
    scatter_msg.hdr.msg_type = SCATTER_MSG;
    scatter_msg.hdr.body_len = std::min(len, BODY_LEN);
    strncpy(scatter_msg.body, msg, scatter_msg.hdr.body_len);

    // this auxilary struct is needed for the sendmsg io_uring operation
    struct iovec iov = {
		.iov_base = &scatter_msg,
		.iov_len = sizeof(sg_msg_t),
	};

	struct msghdr msgh;
    memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name = servAddr;
	msgh.msg_namelen = sizeof(sockaddr_in);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

    // TODO look into sendmsg_zc (zero-copy), might be TCP only though...
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_sendmsg(sqe, skfd, &msgh, 0);
    io_uring_sqe_set_flags(sqe, 0);

    conn_info conn_i = {
        .fd = skfd,
        .type = IO_WRITE,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_info));
}

}



//////////////////////////////
///  ScatterGatherContext  /// 
//////////////////////////////

class ScatterGatherContext
{
private:
    // DATA
    ebpf::Object            d_object;
    ebpf::Object            d_aggregationProgObject;
    uint32_t                d_ifindex;
    std::vector<Worker>     d_workers;
    ebpf::Program           d_scatterProg;
    ebpf::Program           d_gatherNotifyProg;
    ebpf::Program           d_gatherProg;
    ebpf::TCHook::Handle    d_scatterProgHandle;
    ebpf::TCHook::Handle    d_gatherNotifyProgHandle;
    ebpf::XDPHook::Handle   d_gatherProgHandle;

    ebpf::Map               d_workersMap;   
    ebpf::Map               d_workersHashMap;   
    ebpf::Map               d_appPortMap;   
    ebpf::Map               d_gatherCtrlPortMap;   

    // Map names
    constexpr static const auto WORKERS_MAP_NAME = "map_workers";
    constexpr static const auto WORKERS_HASH_MAP_NAME = "map_workers_resp_status";
    constexpr static const auto APP_PORT_MAP_NAME = "map_application_port";
    constexpr static const auto GATHER_CTRL_PORT_MAP_NAME = "map_gather_ctrl_port";

    constexpr static const auto ZERO = 0;

public:
    // TODO eventually read from file
    ScatterGatherContext(const char* objFile, const char* ifname);
    ~ScatterGatherContext();

    void setScatterPort(uint16_t port);
    void setGatherControlPort(uint16_t port);

    ebpf::Map& workersMap() { return d_workersMap; };
    ebpf::Map& workersHashMap() { return d_workersHashMap; };
    ebpf::Map& appPortMap() { return d_appPortMap; };
};


ScatterGatherContext::ScatterGatherContext(const char* objFile, const char* ifname)
    : d_object{objFile}
    , d_aggregationProgObject{"aggregation.bpf.o"}
    , d_ifindex{::if_nametoindex(ifname)}
    , d_scatterProg{d_object.findProgramByName("scatter_prog").value()}
    , d_gatherNotifyProg{d_object.findProgramByName("notify_gather_ctrl_prog").value()}
    , d_gatherProg{d_object.findProgramByName("gather_prog").value()}
    , d_workersMap{d_object.findMapByName(WORKERS_MAP_NAME).value()}
    , d_workersHashMap{d_object.findMapByName(WORKERS_HASH_MAP_NAME).value()}
    , d_appPortMap{d_object.findMapByName(APP_PORT_MAP_NAME).value()}
    , d_gatherCtrlPortMap{d_object.findMapByName(GATHER_CTRL_PORT_MAP_NAME).value()}
{
    if (!d_ifindex)
        throw std::invalid_argument{"Cannot resolve interface index"};
    
    // d_scatterProg = d_object.findProgramByName("scatter_prog").value();
    d_scatterProgHandle = ebpf::TCHook::attach(d_ifindex, d_scatterProg, BPF_TC_EGRESS);

    // auto gatherNotifyProg = d_object.findProgramByName("notify_gather_ctrl_prog").value();
    d_gatherNotifyProgHandle = ebpf::TCHook::attach(d_ifindex, d_gatherNotifyProg, BPF_TC_INGRESS);

    // auto gatherProg = d_object.findProgramByName("gather_prog").value();
    d_gatherProgHandle = ebpf::XDPHook::attach(d_ifindex, d_gatherProg);

    // d_workersMap = d_object.findMapByName(WORKERS_MAP_NAME).value();
    // d_workersHashMap = d_object.findMapByName(WORKERS_HASH_MAP_NAME).value();
    // d_appPortMap = d_object.findMapByName(APP_PORT_MAP_NAME).value();
    // d_gatherCtrlPortMap = d_object.findMapByName(GATHER_CTRL_PORT_MAP_NAME).value();

    auto vecAggProgsMap = d_object.findMapByName("map_aggregation_progs").value();
    auto progIdx = CUSTOM_AGGREGATION_PROG;
    auto customAggregationProg = d_aggregationProgObject.findProgramByName("aggregation_prog").value();
    auto customAggregationProgFd = customAggregationProg.fd();
    vecAggProgsMap.update(&progIdx, &customAggregationProgFd);

    // progIdx = POST_AGGREGATION_PROG;
    // auto postAggregationProgFd = d_aggregationProgObject.findProgramByName("post_aggregation_prog").value().fd();
    // vecAggProgsMap.update(&progIdx, &postAggregationProgFd);
}

ScatterGatherContext::~ScatterGatherContext()
{
    ebpf::TCHook::detach(d_scatterProgHandle);
    ebpf::TCHook::detach(d_gatherNotifyProgHandle);
    ebpf::XDPHook::detach(d_gatherProgHandle);
}

void ScatterGatherContext::setScatterPort(uint16_t port)
{
    // Register the application's outgoing port
    const auto portNetBytes = htons(port);
    d_appPortMap.update(&ZERO, &portNetBytes);
}

void ScatterGatherContext::setGatherControlPort(uint16_t port)
{
    // Register the control socket port for the gather stage
    const auto portNetBytes = htons(port);
    d_gatherCtrlPortMap.update(&ZERO, &portNetBytes);
}

void print_sq_poll_kernel_thread_status() {

    if (system("ps --ppid 2 | grep io_uring-sq" ) == 0)
        printf("Kernel thread io_uring-sq found running...\n");
    else
        printf("Kernel thread io_uring-sq is not running.\n");
}

struct IOUringContext 
{
    constexpr static const auto NumBuffers    = 1024;
    constexpr static const auto MaxBufferSize = sizeof(sg_msg_t);
    constexpr static const auto BufferGroupID = 1338;   // why this? probably arbitrary

    io_uring ring;
    char buffers[NumBuffers][MaxBufferSize] = {0};

    IOUringContext(uint32_t numEntries) 
    {
        // Initialise io_uring
        io_uring_params params;
        memset(&params, 0, sizeof(params));

// #ifdef SQ_POLL_MODE_ENABLED
//         params.flags |= IORING_SETUP_SQPOLL;
//         params.sq_thread_idle = 2000;   // 2 seconds before sleeping
// #endif
        if (io_uring_queue_init_params(numEntries, &ring, &params) < 0)
            throw std::runtime_error{"Failed to initialise io_uring queue"}; 

        // print_sq_poll_kernel_thread_status();

        // // Register packet buffers for buffer selection 
        // io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        // io_uring_prep_provide_buffers(sqe, buffers, MaxBufferSize, NumBuffers, BufferGroupID, 0);
        // io_uring_submit(&ring);
        
        // io_uring_cqe* cqe;
        // io_uring_wait_cqe(&ring, &cqe);
        // if (cqe->res < 0)
        //     throw std::runtime_error{"Failed to provide buffers during io_uring setup"};
        // io_uring_cqe_seen(&ring, cqe);
    }

    ~IOUringContext() {
        io_uring_queue_exit(&ring);
    }
};

/////////////////////////////
///  ScatterGatherRequest  // 
/////////////////////////////

class ScatterGatherUDP;

enum class req_status {
    WAITING,
    READY,
    TIMED_OUT,
    ERROR
};


class ScatterGatherRequest
{
    // Manages the state and execution of a scatter gather request. Each invocation
    // of the scatter gather primitive creates an instance of this class.

private:
    // DATA MEMBERS
    int                     d_requestID;                    // The unique request ID
    std::vector<Worker>     d_workers;
    int                     d_expectedPacketsPerMessage = 1;    // The number of expected packets per response message
    req_status              d_status;
    std::chrono::microseconds d_timeOut;
    std::chrono::time_point<std::chrono::steady_clock> d_startTime;

    // TODO num buffers should be the max number of packets for an entire request
    // = max num packets per response * max num workers
    char d_buffers[IOUringContext::NumBuffers][IOUringContext::MaxBufferSize] = {0};

    // todo make the key Worker type, instead of the fd
    std::unordered_map<int, std::vector<int>> d_workerBufferPtrs;

public:

    ScatterGatherRequest() = default;

    ScatterGatherRequest(int requestID, 
                         std::vector<Worker> workers, 
                         int numPksPerMsg,
                         std::chrono::microseconds timeOut)
        : d_requestID{requestID}
        , d_workers{workers}
        , d_expectedPacketsPerMessage{numPksPerMsg}
        , d_status{req_status::ERROR}
        , d_timeOut{timeOut}
    {}

    int id() const { return d_requestID; }

    const std::vector<Worker>& workers() const { return d_workers; }

    const char* data(int packetIdx) const { return d_buffers[packetIdx]; }

    // TODO use Worker instance as key instead of FD
    const std::unordered_map<int, std::vector<int>>& bufferPointers() const { return d_workerBufferPtrs; };

    bool isReady() const {
        return d_status == req_status::READY;
    }

    bool isExpired() const {
        return d_status == req_status::TIMED_OUT;
    }

    bool hasTimedOut() const {
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - d_startTime);
        return duration >= d_timeOut; 
    }


protected:

    friend ScatterGatherUDP;

    void addBufferPtr(int workerFd, int ptr) {
        d_workerBufferPtrs[workerFd].push_back(ptr);
    }

    void start() {
        d_status = req_status::WAITING;
        d_startTime = std::chrono::steady_clock::now();
    }

    /* TODO check if policy has met based on num of workers */
    bool receivedAll() const { 
        if (d_expectedPacketsPerMessage == 1)
            return d_workerBufferPtrs.size() == d_workers.size();

        int numPacketsReceived = 0;
        for (const auto& [_, ptrs] : d_workerBufferPtrs)
            numPacketsReceived += ptrs.size();
        
        return numPacketsReceived == d_workers.size() * d_expectedPacketsPerMessage;
    };

    void updateStatus() {
        if (hasTimedOut()) {
            std::cout  << "DEBUGGING: request " << id() << " has timed out!!" << std::endl;
            d_status = req_status::TIMED_OUT;
            return;
        }

        if (receivedAll()) {
            d_status = req_status::READY;
            return;
        }
    }

    void registerBuffers(io_uring* ring, bool forceSubmit = false) {
        io_uring_sqe* sqe = io_uring_get_sqe(ring);
        io_uring_prep_provide_buffers(
            sqe, d_buffers, IOUringContext::MaxBufferSize, IOUringContext::NumBuffers, d_requestID, 0
        );
        if (forceSubmit)
            io_uring_submit(ring);
    }

    void freeBuffers(io_uring* ring, bool forceSubmit = false) {
        io_uring_sqe* sqe = io_uring_get_sqe(ring);
        io_uring_prep_remove_buffers(sqe, IOUringContext::NumBuffers, d_requestID);
        if (forceSubmit)
            io_uring_submit(ring);
    }
};


/////////////////////////////
/////  ScatterGatherUDP  //// 
/////////////////////////////


enum class GatherCompletionPolicy 
{
    WaitAll,
    WaitAny,
    WaitN
};


class ScatterGatherUDP 
{
private:
    // DATA MEMBERS
    int                     d_scatterSkFd;  // Scatter socket
    sockaddr_in             d_scatterSkAddr;
    int                     d_ctrlSkFd;     // Gather control socket
    ScatterGatherContext&   d_ctx;
    std::vector<Worker>     d_workers;

    const uint16_t PORT = 9225;    // just generate and add to map

    static uint32_t s_nextRequestID;

    std::unordered_map<int, ScatterGatherRequest>   d_activeRequests;

    // IO uring
    IOUringContext d_ioCtx;

public:

    ScatterGatherUDP(ScatterGatherContext& ctx,
                     const std::vector<Worker>& workers);

    ~ScatterGatherUDP();

    template <typename TIMEOUT_UNITS = std::chrono::microseconds,
              GatherCompletionPolicy POLICY = GatherCompletionPolicy::WaitAll>
    ScatterGatherRequest* scatter(const char* msg, size_t len, int numPksPerRespMsg = 1);
    ScatterGatherRequest* scatter(const std::string& msg, int numPksPerRespMsg = 1);

    int ctrlSkFd() const { return d_ctrlSkFd; }

    void processEvents();

    void processRequestEvents(int requestID);

private:

    constexpr static const int DEFAULT_REQUEST_ID = -1;
    void processPendingEvents(int requestID = DEFAULT_REQUEST_ID);

    // Helpers
    std::pair<int, uint16_t> openWorkerSocket();
};

uint32_t ScatterGatherUDP::s_nextRequestID = 0;

ScatterGatherUDP::ScatterGatherUDP(ScatterGatherContext& ctx, 
                                   const std::vector<Worker>& workers) 
    : d_ctx{ctx}
    , d_workers{workers}
    , d_ioCtx{2048}
{
    d_activeRequests.reserve(MAX_ACTIVE_REQUESTS_ALLOWED);

    d_ctx.setScatterPort(PORT);

    // Configure the worker sockets
    // TODO Maybe this can even be done in the Worker class itself?, to avoid setters
    for (auto i = 0u; i < d_workers.size(); ++i) {
        const auto [ workerSkFd, workerLocalPort ] = openWorkerSocket();
        d_workers[i].setSocketFd(workerSkFd);

        worker_info_t wi = {
            .worker_ip = d_workers[i].ipAddressNet(),
            .worker_port = d_workers[i].portNet(),
            .app_port = workerLocalPort,
        };
        d_ctx.workersMap().update(&i, &wi);

        const worker_resp_status_t resp_status = WAITING_FOR_RESPONSE;
        d_ctx.workersHashMap().update(&wi, &resp_status);
    }

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

    d_ctx.setGatherControlPort(ctrlPort);


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
}

std::pair<int, uint16_t> ScatterGatherUDP::openWorkerSocket() {
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

ScatterGatherUDP::~ScatterGatherUDP()
{
    // TODO rather than opening and closing a socket every time, we could keep
    // a global pool of reusable sockets to avoid this on every invokation of the primitive
    close(d_scatterSkFd);
    close(d_ctrlSkFd);
    for (auto w : d_workers)
        close(w.socketFd());
}


template <typename TIMEOUT_UNITS, GatherCompletionPolicy POLICY>
ScatterGatherRequest* ScatterGatherUDP::scatter(const char* msg, size_t len, int numPksPerRespMsg)
{
    // set the POLICY settings in a map for the ebpf program to decide when its done
    // set a timer...
    auto timeout = std::chrono::microseconds{50 * 1000}; // 1 ms

    // the timeout here doesn't make sense... it should be in ebpf code to avoid
    // extra work 

    // if this is less than the actual num of pks, another syscall
    // is required to submit the remaining socket read operations
    numPksPerRespMsg = 5;

    int reqId = s_nextRequestID++;
    ScatterGatherRequest* req = nullptr;
    {
        // TODO: this can be a fixed size array because we have a limit
        // on the maximum number of active requests
        d_activeRequests.emplace(std::piecewise_construct,
             std::forward_as_tuple(reqId),
             std::forward_as_tuple(reqId, d_workers, numPksPerRespMsg, timeout)
        );

        req = &d_activeRequests[reqId];
        // TODO need a garbage collection mechanism to free the memory used
        // by cancelled and old requests
        // How to handle this?? buffers can be recycled by submitting another provide_buffers
        // or can be freed by submitting remove_buffers ... 
        // when a request is considered done, call req->freeBuffers(&d_ioCtx.ring);
        // in destructor?? or manually?
    }

    // Register response packet buffers for this SG request
    // Every ScatterGatherRequest instance allocates a set of buffers to store the
    // received packet contents. These buffers are registered with io_uring so that
    // the buffers are populated automatically using "automatic buffer selection".
    // Each request defines a group of buffers (hence the group buffer ID is equivalent
    // to the request ID) and the buffer ID is automatically set by io_uring and obtained
    // in the completion queue. This ID can be used by the developer
    // as a pointer into the buffer to read the packet contents.
    req->registerBuffers(&d_ioCtx.ring);

    add_scatter_send(&d_ioCtx.ring, d_scatterSkFd, reqId, &d_scatterSkAddr, msg, len);

    for (auto w : d_workers) {
        for (auto i = 0u; i < numPksPerRespMsg; i++) {
            add_socket_read(&d_ioCtx.ring, w.socketFd(), reqId, IOUringContext::MaxBufferSize, IOSQE_BUFFER_SELECT);
        }
    }
    io_uring_submit(&d_ioCtx.ring);
    req->start();

    return req;
}

ScatterGatherRequest* ScatterGatherUDP::scatter(const std::string& msg, int numPksPerRespMsg)
{
    auto len = strnlen(msg.c_str(), msg.size() + 1);
    return scatter(msg.c_str(), len, numPksPerRespMsg);
}

void ScatterGatherUDP::processEvents() {
    processPendingEvents(DEFAULT_REQUEST_ID);
}

void ScatterGatherUDP::processRequestEvents(int requestID) {
    assert(requestID > DEFAULT_REQUEST_ID);
    processPendingEvents(requestID);
}

void ScatterGatherUDP::processPendingEvents(int requestID) {
    bool processOnlyGivenReq = (requestID != DEFAULT_REQUEST_ID);

    io_uring_cqe *cqe;
    unsigned count = 0;
    unsigned head;
    bool submitPendingReads = false;

    io_uring_for_each_cqe(&d_ioCtx.ring, head, cqe) {
        ++count;
        const auto conn_i = reinterpret_cast<conn_info*>(&cqe->user_data);

        if (cqe->res == -ENOBUFS) {
            // NOTIFY USER THAT WE ARE OUT OF SPACE
            fprintf(stdout, "bufs in automatic buffer selection empty, this should not happen...\n");
            fflush(stdout);
            exit(1);
        }
        
        if (conn_i->type == IO_READ) {
            if (cqe->res <= 0) {
                close(conn_i->fd);
            } else {
                auto reqId = conn_i->bgid;           // the packet's request ID
                auto buffIdx = cqe->flags >> 16;     // the packet's buffer index
                auto& req = d_activeRequests[reqId]; // get the associated request
                const auto resp = (sg_msg_t*) req.data(buffIdx);

                // If we are only processing packets for a given request
                if (processOnlyGivenReq && resp->hdr.req_id != req.id()) {
                    continue;
                }

                if (req.hasTimedOut()) {
                    req.updateStatus();
                    continue;
                }
                
                std::cout << "Got pk " << conn_i->fd << " for req " << req.id() << std::endl;
                req.addBufferPtr(conn_i->fd, buffIdx);
                req.updateStatus();

                // check for multi-packet message and add more reads if necessary
                if (req.d_expectedPacketsPerMessage != resp->hdr.num_pks && resp->hdr.num_pks > 1) {
                    req.d_expectedPacketsPerMessage = resp->hdr.num_pks;                       
                }

                int remaining = 0;
                for (const auto& [wfd, ptrs] : req.d_workerBufferPtrs) {
                    auto pksRemainingForThisWorker = abs(req.d_expectedPacketsPerMessage - ptrs.size());
                    if (pksRemainingForThisWorker > 0) {
                        remaining += pksRemainingForThisWorker;

                        // Add the remaining socket read operations to the SQ
                        for (auto i = 0; i < pksRemainingForThisWorker; i++)
                            add_socket_read(&d_ioCtx.ring, wfd, req.id(), IOUringContext::MaxBufferSize, IOSQE_BUFFER_SELECT);
                    }
                }
                submitPendingReads = (remaining > 0);
            }
        }
    }
    io_uring_cq_advance(&d_ioCtx.ring, count);

    if (submitPendingReads) {
        std::cout << "submitting pending reads from event loop (mistmatch in expected number of packets in resp)" << std::endl;
        io_uring_submit(&d_ioCtx.ring);
        submitPendingReads = false;
    }
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv) {

    // globally initialises the library and prepares eBPF environment
    // ScatterGather::init("scatter_gather.json");
    ScatterGatherContext ctx{argv[1], argv[2]};

    auto workers = Worker::fromFile("workers.cfg");
    ScatterGatherUDP sg{ctx, workers};

    // User can configure the ctrl socket as they wish, eg: set non blocking flag
    // int flags = fcntl(sg.ctrlSkFd(), F_GETFL, 0);
    // fcntl(sg.ctrlSkFd(), F_SETFL, flags | O_NONBLOCK);

    // EXAMPLE 1: Vector-based data (with in-kernel aggregation)
    auto req = sg.scatter("SCATTER");
    std::cout << "sent scatter request" << std::endl;

    // Wait on the ctrl socket to finish
    sg_msg_t buf;
    auto b = read(sg.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    assert(b == sizeof(sg_msg_t));
    // Important: it is up to the user to verify that this corresponds to the
    // request's ID, since the ctrl sk is global to all ongoing requests
    assert(buf.hdr.req_id == req->id());

    // Process the completed events in the io_uring queue
    // decouple threading model from library
    // To be called periodically or directly after an event on the ctrl sk

    sg.processEvents(); // or alternatively: sg.processRequestEvents(req->id());
    
    auto aggregatedData = (uint32_t*)(buf.body);
    std::cout << "control socket packet received\n";
    for (auto i = 0u; i < RESP_MAX_VECTOR_SIZE; i++) {
        if (i % 25 == 0)
            std::cout << "vec[" << i << "] = " << aggregatedData[i] << std::endl;
    }

    std::cout << "Got a total of " << req->bufferPointers().size() << std::endl;
    

    // ASSUMPTION: the number of packets in the response message must be specified
    // in advance if calling processEvents() AFTER the ctrl sk event. Otherwise,
    // a separate thread is needed to periodically call processEvents() to submit
    // any remaining read operations to the IO event queue (io_uring).

    // ASSUMPTION 2: for multi-packet aggregation, this must be done in userspace
    // and there is no notification to the ctrl socket. Therefore, the user must
    // periodically call processEvents() and wait until all packets have arrived.
    // One way to do this is to call processEvents() while waiting under req->isReady();


    // EXAMPLE TWO: multi-packet response, with userspace aggregation over individual packets
    // this is useful for multi-packet responses, so the user can perform the aggregation
    // themselves in user-space
    auto req2 = sg.scatter("SCATTER");

    while (!req2->isReady()) {
        // Because we have no notification on the ctrl socket in this case, we must
        // manually check whether we have received the packets by periodically calling
        // the process function
        sg.processRequestEvents(req2->id());
    }

    for (const auto& w : req2->workers()) {
        auto buffIdxs = req2->bufferPointers().at(w.socketFd());
        std::cout << "Num packets received: " << buffIdxs.size() << std::endl;
        
        for (auto buffIdx : buffIdxs) {
            auto pk = (sg_msg_t*) req2->data(buffIdx);
            std::cout << "Pk: " << buffIdx << " - " << ((uint32_t*)(pk->body)) << std::endl;
        }
    }
}
