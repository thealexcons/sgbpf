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
#include <mutex>

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

    auto vecAggProgsMap = d_object.findMapByName("map_aggregation_progs").value();
    auto progIdx = CUSTOM_AGGREGATION_PROG;
    auto customAggregationProgFd = d_aggregationProgObject.findProgramByName("aggregation_prog").value().fd();
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
    int                 d_requestID;                    // The unique request ID
    std::vector<Worker> d_workers;
    int                 d_expectedPacketsPerMessage = 1;    // The number of expected packets per response message
    std::mutex*         d_mutex;
    // std::unordered_map<int, uint32_t>           d_workerPacketCount;    // The number of packets received for each worker
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
                         std::chrono::microseconds timeOut,
                         std::mutex* mut)
        : d_requestID{requestID}
        , d_workers{workers}
        , d_expectedPacketsPerMessage{numPksPerMsg}
        , d_timeOut{timeOut}
        , d_mutex{mut}
    {}

    int id() const { return d_requestID; }

    const std::vector<Worker>& workers() const { return d_workers; }

    const char* data(int packetIdx) const { return d_buffers[packetIdx]; }

    // TODO use Worker instance as key instead of FD
    const std::unordered_map<int, std::vector<int>>& bufferPointers() const { return d_workerBufferPtrs; };

    /* TODO check if policy has met based on num of workers */
    bool hasFinished() { 
        if (d_expectedPacketsPerMessage == 1)
            return d_workerBufferPtrs.size() == d_workers.size();

        std::scoped_lock lock{*d_mutex};
        int numPacketsReceived = 0;
        for (const auto& [_, ptrs] : d_workerBufferPtrs)
            numPacketsReceived += ptrs.size();
        
        return numPacketsReceived == d_workers.size() * d_expectedPacketsPerMessage;
    };

protected:

    friend ScatterGatherUDP;

    void addBufferPtr(int workerFd, int ptr) {
        d_workerBufferPtrs[workerFd].push_back(ptr);
    }

    void* buffers() const { return (char*) d_buffers; }

    void start() {
        d_startTime = std::chrono::steady_clock::now();
    }

    bool hasTimedOut() const {
        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - d_startTime);
        return duration >= d_timeOut; 
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

    std::mutex                                      d_requestsMutex;
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

    // it might be better to set the completion policy in the invokation
    // since we only expose the sockets

    // template <typename RESULT, 
    //           typename TIMEOUT_UNITS = std::chrono::microseconds,
    //           GatherCompletionPolicy POLICY = GatherCompletionPolicy::WaitAll>
    // void gather(RESULT* result,
    //             TIMEOUT_UNITS timeout = {},
    //             GatherArgs gatherArgs = {});
private:

    void eventLoop();

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

    // Start the background event loop thread
    std::thread bg{&ScatterGatherUDP::eventLoop, this};
    bg.detach();
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

template <typename TIMEOUT_UNITS, GatherCompletionPolicy POLICY>
ScatterGatherRequest* ScatterGatherUDP::scatter(const char* msg, size_t len, int numPksPerRespMsg)
{
    // set the POLICY settings in a map for the ebpf program to decide when its done
    // set a timer...
    auto timeout = std::chrono::microseconds{10 * 1000}; // 1 ms

    // the timeout here doesn't make sense... it should be in ebpf code to avoid
    // extra work 

    // if this is less than the actual num of pks, another syscall
    // is required to submit the remaining socket read operations
    // numPksPerRespMsg = 10;  

    int reqId = s_nextRequestID++;    
    ScatterGatherRequest* req = nullptr;
    {
        std::scoped_lock lock{d_requestsMutex};
        d_activeRequests[reqId] = ScatterGatherRequest{reqId, 
                                                       d_workers, 
                                                       numPksPerRespMsg, 
                                                       timeout,
                                                       &d_requestsMutex};
        req = &d_activeRequests[reqId];
        // TODO need a garbage collection mechanism to free the memory used
        // by cancelled and old requests
        // How to handle this?? buffers can be recycled by submitting another provide_buffers
        // or can be freed by submitting remove_buffers ... 
    }

    // Register response packet buffers for this SG request
    // Every ScatterGatherRequest instance allocates a set of buffers to store the
    // received packet contents. These buffers are registered with io_uring so that
    // the buffers are populated automatically using "automatic buffer selection".
    // Each request defines a group of buffers (hence the group buffer ID is equivalent
    // to the request ID) and the buffer ID is automatically set by io_uring and obtained
    // in the event loop thread, which saves this ID so it can be used by the developer
    // as a pointer into the buffer to read the packet contents.
    add_provide_buffers(&d_ioCtx.ring, req->buffers(), req->id());

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

void ScatterGatherUDP::eventLoop()
{
    // io_uring event loop in background thread
    // this thread will keep track of the pointers to the packet buffers which
    // are received for all requests
    while (1) {
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
                    auto reqId = conn_i->bgid; // the packet's request ID
                    auto buffIdx = cqe->flags >> 16; // the packet's buffer index

                    std::scoped_lock lock{d_requestsMutex};

                    auto& req = d_activeRequests[reqId]; // get the associated request
                    if (req.hasTimedOut()) {
                        std::cout << "REQUEST " << req.id() << " TIMED OUT!!!" << std::endl;
                        continue;
                    }

                    auto resp = (sg_msg_t*) req.data(buffIdx);
                    if (resp->hdr.req_id != req.id()) {
                        continue; // drop old or invalid packet
                    }
                    std::cout << "Got pk " << conn_i->fd << " for req " << req.id() << std::endl;
                    req.addBufferPtr(conn_i->fd, buffIdx);

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
            std::cout << "submit from event loop" << std::endl;
            io_uring_submit(&d_ioCtx.ring);
            submitPendingReads = false;
        }

        // keep spinning... 
    }
}

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////

int main(int argc, char** argv) {

    // globally initialises the library and prepares eBPF subsystem
    // ScatterGather::init("scatter_gather.json");
    auto workers = Worker::fromFile("workers.cfg");
    ScatterGatherContext ctx{argv[1], argv[2]};

    ScatterGatherUDP sg{ctx, workers};
    std::cout << "Created context and operation\n";

    // User can configure the ctrl socket as they wish, eg: set non blocking flag
    int flags = fcntl(sg.ctrlSkFd(), F_GETFL, 0);
    fcntl(sg.ctrlSkFd(), F_SETFL, flags | O_NONBLOCK);


    auto req = sg.scatter("SCATTER");
    std::cout << "sent scatter" << std::endl;

    // Read the ctrl socket with the aggregated value
    while (!req->hasFinished()) {}
    // wait until the request has finished, to avoid blocking on the read syscall

    sg_msg_t buf;
    auto b = read(sg.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    assert(b == sizeof(sg_msg_t));
    // Important: it is up to the user to verify that this corresponds to the
    // request's ID, since the ctrl sk is global to all ongoing requests
    assert(buf.hdr.req_id == req->id());

    auto aggregatedData = (uint32_t*)(buf.body);
    std::cout << "control socket packet received\n";
    for (auto i = 0u; i < RESP_MAX_VECTOR_SIZE; i++) {
        if (i % 25 == 0)
            std::cout << "vec[" << i << "] = " << aggregatedData[i] << std::endl;
    }


    // Can also get the individual workers
    // this is useful for multi-packet responses, so the user can perform the aggregation
    // themselves in user-space
    // for (const auto& w : req->workers()) {
    //     auto buffIdxs = req->bufferPointers().at(w.socketFd());
    //     std::cout << "Num packets received: " << buffIdxs.size() << std::endl;
        
    //     for (auto buffIdx : buffIdxs) {
    //         auto pk = (sg_msg_t*) req->data(buffIdx);
    //         std::cout << "Pk: " << buffIdx << " - " << ((uint32_t*)(pk->body)) << std::endl;
    //     }

    //     // std::cout << "[ReqID = " << req->id() << "] seq_num = " << pk->hdr.req_id << " - "
    //     //           << "Worker " << w.port() << " (fd = " << w.socketFd() 
    //     //           << ") with buffIdx[0] " << buffIdxs[0] << std::endl;

    // }

    // TODO logic in ebpf program does not support multiple requests, needs fixing

    auto req2 = sg.scatter("SCATTER");
    std::cout << "\nSENT SECOND REQUEST " << std::endl;

    while (!req2->hasFinished()) {}
    read(sg.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    std::cout << buf.hdr.req_id << std::endl;
    aggregatedData = (uint32_t*)(buf.body);
    std::cout << "Got req2 response, example: vec[33] = " << aggregatedData[33] << std::endl;
    


}
