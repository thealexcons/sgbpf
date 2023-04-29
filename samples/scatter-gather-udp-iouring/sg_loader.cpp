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



////////////////////////////
/////  ScatterProgram  ///// 
////////////////////////////

/*
struct ScatterProgram 
{
    bpf_tc_hook d_tcHook;
    bpf_tc_opts d_tcOpts;

    constexpr static const auto SCATTER_PROG_NAME = "scatter_prog";

    ScatterProgram() = default;
    ScatterProgram(const ebpf::Object& obj, uint32_t ifindex);

    ~ScatterProgram();
};

ScatterProgram::ScatterProgram(const ebpf::Object& obj, uint32_t ifindex) 
{
    auto prog = obj.findProgramByName(SCATTER_PROG_NAME);
    if (!prog)
		throw std::runtime_error{"Failed to find scatter program"};

    memset(&d_tcHook, 0, sizeof(bpf_tc_hook));
    d_tcHook.attach_point = BPF_TC_EGRESS;
    d_tcHook.ifindex = ifindex;
    d_tcHook.sz = sizeof(bpf_tc_hook);

    auto err = bpf_tc_hook_create(&d_tcHook);
	if (err && err != -EEXIST)
		throw std::runtime_error{"Failed to create TC hook"};

    memset(&d_tcOpts, 0, sizeof(bpf_tc_opts));
    d_tcOpts.prog_fd = prog.value().fd();
    d_tcOpts.sz = sizeof(bpf_tc_opts);

    if (bpf_tc_attach(&d_tcHook, &d_tcOpts) < 0)
		throw std::runtime_error{"Failed to attach program to TC egress hook"};

    std::cout << "Attached TC scatter program" << std::endl;
}

ScatterProgram::~ScatterProgram()
{
    bpf_tc_detach(&d_tcHook, &d_tcOpts);
    bpf_tc_hook_destroy(&d_tcHook);

    std::cout << "Dettached TC scatter program" << std::endl;
}
*/


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

    auto aggregationProgFd = d_aggregationProgObject.findProgramByName("aggregation_prog").value().fd();
    auto vecAggProgsMap = d_object.findMapByName("map_vector_aggregation_progs").value();
    auto progIdx = VECTOR_AGGREGATION_PROG_IDX;
    vecAggProgsMap.update(&progIdx, &aggregationProgFd);
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

// void ScatterGatherContext::setWorkers(const std::vector<Worker>& workers)
// {
//     d_workers = workers;

//     auto workerIpMap = d_object.findMapByName(WORKER_IPS_MAP_NAME).value();
//     auto workerPortMap = d_object.findMapByName(WORKER_PORTS_MAP_NAME).value();
//     for (auto i = 0u; i < workers.size(); ++i) {
//         auto ip = workers[i].ipAddressNet();
//         auto port = workers[i].portNet();
//         workerIpMap.update(&i, &ip);
//         workerPortMap.update(&i, &port);
//     }
// }

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
        if (io_uring_queue_init_params(numEntries, &ring, &params) < 0)
            throw std::runtime_error{"Failed to initialise io_uring queue"}; 

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
};

/////////////////////////////
///  ScatterGatherRequest  // 
/////////////////////////////

class ScatterGatherUDP;

class ScatterGatherRequest
{
    // Manages the state and execution of a scatter gather request. Each invocation
    // of the scatter gather primitive creates an instance of this class.

private:
    // DATA MEMBERS
    int d_requestID;                    // The unique request ID
    int d_expectedPacketsPerMessage;    // The number of expected packets per response message
    int d_remainingPackets;             // The number of remaining packets to be read 
    // int d_ctrlSkFd;
    std::vector<Worker> d_workers;
    // std::unordered_map<int, uint32_t>           d_workerPacketCount;    // The number of packets received for each worker
    // std::unordered_map<int, std::vector<char*>> d_workerPacketBuffers;  // The packet buffers received for each worker

    // num buffers should be the max number of packets for an entire request
    // = max num packets per response * max num workers
    char d_buffers[IOUringContext::NumBuffers][IOUringContext::MaxBufferSize] = {0};

    // todo make the key Worker type, instead of the fd
    std::unordered_map<int, int> d_workerBufferPtrs;

public:

    ScatterGatherRequest(int requestID, std::vector<Worker> workers)
        : d_requestID{requestID}
        , d_workers{workers}
    {}

    // map each worker with the buffer content
    const std::unordered_map<int, int>& bufferPointers() const { return d_workerBufferPtrs; };

    const std::vector<Worker>& workers() const { return d_workers; }

    const char* data(int packetIdx) const { return d_buffers[packetIdx]; }

    int id() const { return d_requestID; }

/* check if policy has met based on num of workers */
    bool hasFinished() { return d_workerBufferPtrs.size() == d_workers.size(); };

protected:

    friend ScatterGatherUDP;
    void setBufferPtr(int workerFd, int ptr) {
        d_workerBufferPtrs[workerFd] = ptr;
    }

    void* buffers() const {
        return (char*) d_buffers;
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
    ScatterGatherContext    d_ctx;
    std::vector<Worker>     d_workers;

    const uint16_t PORT = 9225;    // just generate and add to map

    static uint32_t s_nextRequestID;

    // IO uring
    IOUringContext d_ioCtx;

public:

    ScatterGatherUDP(ScatterGatherContext& ctx,
                     const std::vector<Worker>& workers);

    ~ScatterGatherUDP();

    template <typename TIMEOUT_UNITS = std::chrono::microseconds,
              GatherCompletionPolicy POLICY = GatherCompletionPolicy::WaitAll>
    ScatterGatherRequest scatter(const char* msg, size_t len);
    ScatterGatherRequest scatter(const std::string& msg);

    int ctrlSkFd() const { return d_ctrlSkFd; }

    // it might be better to set the completion policy in the invokation
    // since we only expose the sockets

    // template <typename RESULT, 
    //           typename TIMEOUT_UNITS = std::chrono::microseconds,
    //           GatherCompletionPolicy POLICY = GatherCompletionPolicy::WaitAll>
    // void gather(RESULT* result,
    //             TIMEOUT_UNITS timeout = {},
    //             GatherArgs gatherArgs = {});

    // Where to put the event loop? inside gather or a start() function?

private:

    // template <typename RESULT, typename TIMEOUT_UNITS>
    // void gatherWaitAll(RESULT* result, TIMEOUT_UNITS timeout);
    
    // template <typename RESULT, typename TIMEOUT_UNITS>
    // void gatherWaitAny(RESULT* result, TIMEOUT_UNITS timeout) { std::cout << "gatherWaitAny()\n"; }

    // template <typename RESULT, typename TIMEOUT_UNITS>
    // void gatherWaitN(RESULT* result, TIMEOUT_UNITS timeout, uint32_t n) { std::cout << "gatherWaitN()\n"; }


    // Helpers
    std::pair<int, uint16_t> openWorkerSocket();

    void addScatterSend(io_uring* ring, int skfd, sockaddr_in* servAddr, sg_msg_t* scatterMsg);
    void addSocketRead(io_uring* ring, int fd, unsigned groupID, size_t msgLen, unsigned flags);
};

uint32_t ScatterGatherUDP::s_nextRequestID = 0;

ScatterGatherUDP::ScatterGatherUDP(ScatterGatherContext& ctx, 
                                   const std::vector<Worker>& workers) 
    : d_ctx{ctx}
    , d_workers{workers}
    , d_ioCtx{2048}
{
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

    // d_ctx.setScatterPort(PORT); // Set the application's outgoing port for the scatter socket

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
    // close(d_scatterSkFd);
    // close(d_ctrlSkFd);
    // for (auto w : d_workers)
    //     close(w.socketFd());
}

enum {
    IO_READ,
    IO_WRITE,
};

typedef struct conn_info {
    __u32      fd;
    __u16 type;
    __u16 bid;
} conn_info;

void add_provide_buffers(struct io_uring* ring, void* buffers, int buffGroupID) {
    // Register packet buffers for buffer selection for the given request (buffGroupID)
    io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_provide_buffers(
        sqe, buffers, IOUringContext::MaxBufferSize, IOUringContext::NumBuffers, buffGroupID, 0
    );
    // io_uring_submit(ring);

    // move this error handling somewhere else?    
    // io_uring_cqe* cqe;
    // io_uring_wait_cqe(ring, &cqe);
    // if (cqe->res < 0)
    //     throw std::runtime_error{"Failed to provide buffers during io_uring setup"};
    // io_uring_cqe_seen(ring, cqe);
}

void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t message_size, unsigned flags) {
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv(sqe, fd, NULL, message_size, MSG_WAITALL); // wait for all fragments to arrive
    io_uring_sqe_set_flags(sqe, flags);
    sqe->buf_group = gid;

    conn_info conn_i = {
        .fd = fd,
        .type = IO_READ,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}


void add_scatter_send(struct io_uring* ring, int skfd, sockaddr_in* servAddr, const char* msg, size_t len) {
    // Send the message to itself
    // const auto SCATTER_STR = "SCATTER";
    sg_msg_t scatter_msg;
    memset(&scatter_msg, 0, sizeof(sg_msg_t));
    scatter_msg.hdr.req_id = 1;
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
	msgh.msg_namelen = sizeof(struct sockaddr_in);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_sendmsg(sqe, skfd, &msgh, 0); // TODO look into sendmsg_zc (zero-copy)
    io_uring_sqe_set_flags(sqe, 0);

    conn_info conn_i = {
        .fd = skfd,
        .type = IO_WRITE,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}


template <typename TIMEOUT_UNITS, GatherCompletionPolicy POLICY>
ScatterGatherRequest ScatterGatherUDP::scatter(const char* msg, size_t len)
{
    // set the POLICY settings in a map for the ebpf program to decide when its done
    // set a timer...
    int reqId = ++s_nextRequestID;
    ScatterGatherRequest req{reqId, d_workers};

    // Register response packet buffers for this SG request
    add_provide_buffers(&d_ioCtx.ring, req.buffers(), reqId);

    add_scatter_send(&d_ioCtx.ring, d_scatterSkFd, &d_scatterSkAddr, msg, len);

    // note that the buffers will be shared across multiple requests, so we need
    // a away to distinguish them maybe???
    // unless we provide a buffer group for each request, but would need to batch the syscall
    // because it requires a submit...
    // MAKE SURE TO UNDERSTAND THE BUFFER SELECTION CONTENT
    for (auto w : d_workers) {
        add_socket_read(&d_ioCtx.ring, w.socketFd(), reqId, IOUringContext::MaxBufferSize, IOSQE_BUFFER_SELECT);
    }

    // do not add the ctrl socket read to io_uring
    // add_socket_read(&d_ioCtx.ring, d_ctrlSkFd, IOUringContext::BufferGroupID, IOUringContext::MaxBufferSize, IOSQE_BUFFER_SELECT);

    io_uring_submit(&d_ioCtx.ring);

    // Save the pointer to the buffers in a background thread
    // probably should keep a background thread and queue requests into that
    // If we use a single BG thread, we need a pool of all open requests to filter
    // the incoming packets by ID
    std::thread bufferPtrThread([this](ScatterGatherRequest& reqHandle){
        while (1) {
            io_uring_cqe *cqe;
            unsigned count = 0;
            unsigned head;

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
                    int buff_id = cqe->flags >> 16;
                    if (cqe->res <= 0) {
                        close(conn_i->fd);
                    } else {
                        auto resp = (sg_msg_t*) reqHandle.data(buff_id);
                        if (resp->hdr.req_id == reqHandle.id())         
                            reqHandle.setBufferPtr(conn_i->fd, buff_id);
                    }
                }
            }
            io_uring_cq_advance(&d_ioCtx.ring, count);
            
            if (reqHandle.hasFinished()) {
                std::cout << "finished individual packet workers!!" << std::endl;
                break;
            }
        }
    }, std::ref(req));
    bufferPtrThread.detach();

    return req;
    ////////////////////////////////////////////

/*
    sg_msg_t scatter_msg;
    memset(&scatter_msg, 0, sizeof(sg_msg_t));

    scatter_msg.hdr.req_id = ++s_nextRequestID;
    scatter_msg.hdr.msg_type = SCATTER_MSG;
    scatter_msg.hdr.body_len = std::min(len, BODY_LEN);
    strncpy(scatter_msg.body, msg, scatter_msg.hdr.body_len);

    // Add the send operation to write the scatter request into the socket
    // addScatterSend(&ring, d_scatterSkFd, &d_scatterSkAddr, &scatter_msg);

    std::cout << io_uring_sq_ready(&ring) << std::endl;


    // Add all the socket read operations (workers and control socket)
    for (const auto& worker : d_workers) {
        addSocketRead(&ring, worker.socketFd(), IOUringContext::BufferGroupID, IOUringContext::MaxBufferSize, IOSQE_BUFFER_SELECT);
    }
    std::cout << io_uring_sq_ready(&ring) << std::endl;

    addSocketRead(&ring, d_ctrlSkFd, IOUringContext::BufferGroupID, IOUringContext::MaxBufferSize, IOSQE_BUFFER_SELECT);
    std::cout << io_uring_sq_ready(&ring) << std::endl;

    // Submit all IO requests to the queue and wait
    // NOTE: if we reuse the same ring for multiple requests, this number may be
    // inaccurate because it may mix operatioms from different requests

    std::cout << "here!!!" << std::endl;
    // TODO not sending????
    std::cout << d_workers.size() << std::endl;
    io_uring_submit_and_wait(&ring, d_workers.size() + 2);
    // io_uring_submit(&ring);
    // maybe here do not wait?
*/

/*
    std::vector<int> processedWorkerFds;

    std::unordered_map<int, std::vector<std::array<RESP_VECTOR_TYPE, RESP_MAX_VECTOR_SIZE>>> multiPacketMessages;
    std::unordered_map<int, uint32_t> multiPacketMessagesCount;

    unsigned expectedPacketsPerMsg = 1;
    for (auto w : d_workers)
        multiPacketMessages[w.socketFd()].resize(expectedPacketsPerMsg);  

    // COPY PASTE THE ENTIRE WHILE LOOP HERE    ,
     while (1) {
        std::cout << "entering event loop\n";       
        io_uring_cqe *cqe;
        unsigned count = 0;
        unsigned head;

        io_uring_for_each_cqe(&d_ioCtx.ring, head, cqe) {
            ++count;

            conn_info conn_i;
            memcpy(&conn_i, &cqe->user_data, sizeof(conn_i)); // TODO cast cqe->user_data to conn_i instead?

            if (cqe->res == -ENOBUFS) {
                fprintf(stdout, "bufs in automatic buffer selection empty, this should not happen...\n");
                fflush(stdout);
                exit(1);
            }
            
            if (conn_i.type == IO_READ) {
                // int bytes_read = cqe->res;
                int buff_id = cqe->flags >> 16;
                if (cqe->res <= 0) {
                    // read failed, re-add the buffer
                    // add_provide_buf(&ring, buff_id, group_id);
                    // connection closed or error
                    close(conn_i.fd);
                } else {
                    
                    // processedWorkerFds.push_back(conn_i.fd);
                    // auto resp = (sg_msg_t*) bufs[buff_id];

                    // Scalar aggregation:
                    // auto data = ntohl(*(uint32_t*) resp->body);
                    // userspace_aggregated_value += data;
                    // std::cout << "got response from worker socket: " << data << " with seq num = " << resp->hdr.seq_num << std::endl;

                    // Vectorised aggregation: check for control socket
                    // auto data = (uint32_t*) resp->body;

                    // ctrl socket notification (for single-packet vectorised aggregation)
                    if (conn_i.fd == d_ctrlSkFd) {
                        std::cout << "control socket packet received\n";
                        // for (auto i = 0u; i < RESP_MAX_VECTOR_SIZE; i++) {
                            // std::cout << "vec[" << i << "] = " << data[i] << std::endl;
                        // }
                    }
                    else    // read operation from a worker socket
                    {
                        std::cout << "worker socket packet received\n";
                    }
                }
            }
        }

        int remaining = 0;

        // // Check for completion
        // for (const auto& [wfd, pks] : multiPacketMessagesCount) {
        //     auto pksRemainingForThisWorker = abs(expectedPacketsPerMsg - pks);
        //     if (pksRemainingForThisWorker > 0) {
        //         remaining += pksRemainingForThisWorker;

        //         // Add the remaining socket read operations to the SQ
        //         // for (auto i = 0; i < pksRemainingForThisWorker; i++)
        //             // add_socket_read(&ring, wfd, GROUP_ID, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
        //     }
        // }

        // std::cout << "Remaining packets: " << remaining << std::endl;

        if (!remaining) {
            break;
        }

        io_uring_cq_advance(&d_ioCtx.ring, count);
        io_uring_submit_and_wait(&d_ioCtx.ring, remaining);
    }
*/
    // return ScatterGatherRequest{&d_ioCtx, scatter_msg.hdr.req_id};
    // return ScatterGatherRequest{(int)1, d_ctrlSkFd, d_workers};
}

ScatterGatherRequest ScatterGatherUDP::scatter(const std::string& msg)
{
    auto len = strnlen(msg.c_str(), msg.size() + 1);
    return scatter(msg.c_str(), len);
}

/*
template <typename RESULT, typename TIMEOUT_UNITS, GatherCompletionPolicy POLICY>
void ScatterGatherUDP::gather(RESULT* result,
                              TIMEOUT_UNITS timeout,
                              GatherArgs gatherArgs)
{
    if constexpr(POLICY == GatherCompletionPolicy::WaitAll)
        return gatherWaitAll(result, timeout);
    else if constexpr(POLICY == GatherCompletionPolicy::WaitAny)
        return gatherWaitAny(result, timeout);
    else
        return gatherWaitN(result, timeout, gatherArgs.nodesToWait);
}


template <typename RESULT, typename TIMEOUT_UNITS>
void ScatterGatherUDP::gatherWaitAll(RESULT* result, TIMEOUT_UNITS timeout)
{
    // TODO use epoll or other async IO

    constexpr auto readyMsgLen = 256;
    char readyMsg[readyMsgLen];

    // this blocks until we get the notification that we are ready to gather from all other
    int bytesRead = read(d_ctrlSkFd, readyMsg, readyMsgLen);
    if (bytesRead > 0 && strncmp(readyMsg, "GATHER_READY", 12)) {

        // Ready to read from worker sockets
        // for (auto i = 0u; i < d_workerSkFds.size(); ++i) {
        //     char resBuf[1024];
        //     int n = read(d_workerSkFds[i], resBuf, 1024);
        //     if (n < 0)
        //         std::cout << "Failed to read from worker " << i << "\n";
                
        //     resBuf[n] = '\0';
        //     std::cout << "Got response from worker " << i << ": '" << resBuf << "'\n";
        // }

    }

}
*/

void ScatterGatherUDP::addScatterSend(io_uring* ring, int skfd, sockaddr_in* servAddr, sg_msg_t* scatterMsg)
{
    struct iovec iov = {
		.iov_base = scatterMsg,
		.iov_len = sizeof(sg_msg_t),
	};

	struct msghdr msgh;
    memset(&msgh, 0, sizeof(msgh));
	msgh.msg_name = servAddr;
	msgh.msg_namelen = sizeof(sockaddr_in);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_sendmsg(sqe, skfd, &msgh, 0); // TODO look into sendmsg_zc (zero-copy)
    io_uring_sqe_set_flags(sqe, 0);

    conn_info conn_i = {
        .fd = skfd,
        .type = IO_WRITE,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_info));
}

void ScatterGatherUDP::addSocketRead(io_uring* ring, int fd, unsigned groupID, size_t msgLen, unsigned flags)
{
    io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv(sqe, fd, NULL, msgLen, MSG_WAITALL); // wait for all fragments to arrive
    io_uring_sqe_set_flags(sqe, flags);
    sqe->buf_group = groupID;

    conn_info conn_i = {
        .fd = fd,
        .type = IO_READ,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}


/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv) {

    // globally initialises the library and prepares eBPF subsystem
    // ScatterGather::init("scatter_gather.json");


    auto workers = Worker::fromFile("workers.cfg");

    ScatterGatherContext ctx{argv[1], argv[2]};
    // ctx.setWorkers(workers);

    ScatterGatherUDP sg{ctx, workers};

    std::cout << "Created context and operation\n";


    // char buf[256];
    // strncpy(buf, "SCATTER", 8);     
    // if (!scatterGather.scatter(buf, strlen(buf))) {
    //     std::cerr << "Failed to send scatter message\n";
    //     exit(EXIT_FAILURE);
    // }

    std::string scatterMsg = "SCATTER";
    auto req = sg.scatter(scatterMsg);

    std::cout << "sent scatter" << std::endl;

    // Read the ctrl socket with the aggregated value
    // can also poll on req.hasFinished() instead to read immediately
    char buf[sizeof(sg_msg_t)];
    read(sg.ctrlSkFd(), buf, sizeof(buf));

    auto aggregatedData = (uint32_t*)(((sg_msg_t*) buf)->body);
    std::cout << "control socket packet received\n";
    for (auto i = 0u; i < RESP_MAX_VECTOR_SIZE; i++) {
        if (i % 5 == 0)
            std::cout << "vec[" << i << "] = " << aggregatedData[i] << std::endl;
    }

    // Can also get the individual workers
    assert(req.hasFinished()); // always true if the read on the ctrl sk has completed
    for (const auto& w : req.workers()) {
        auto buffIdx = req.bufferPointers().at(w.socketFd());
        std::cout << "Worker " << w.port() << " (fd = " << w.socketFd() << ") with buffIdx " << buffIdx << std::endl;

        auto pk = (sg_msg_t*) req.data(buffIdx);
        std::cout << "Pk: " << ((uint32_t*)(pk->body))[33] << std::endl;
    }


}
