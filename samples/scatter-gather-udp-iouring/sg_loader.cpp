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

#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <liburing.h>

#include "ebpfpp/Program.h"
#include "ebpfpp/Map.h"
#include "ebpfpp/Object.h"
#include "ebpfpp/Util.h"

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

public:

    // CONSTRUCTORS
    Worker(std::string ipAddress, uint16_t port);

    // GETTERS
    const uint32_t ipAddressNet() const { return d_ipAddressNet; }
    const uint16_t portNet() const { return d_portNet; }
    std::string ipAddress() const { return d_ipAddress; }
    uint16_t port() const { return d_port; }

    // STATIC METHODS
    static std::vector<Worker> fromFile(const std::string& filePath);
};

Worker::Worker(std::string ipAddress, uint16_t port)
    : d_ipAddress{std::move(ipAddress)}
    , d_port{port}
{
    if (!inet_pton(AF_INET, d_ipAddress.c_str(), &d_ipAddressNet))
        throw std::runtime_error{"Invalid IPv4 address"};
    
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

    /*
    std::cout << "Loaded TC prog with fd " << prog.value().fd() << " and name " << prog.value().name() << '\n';
    std::cout << "Prog type: " << bpf_program__type(prog.value().get()) << "\n";

    auto maps = obj.maps();
    for (const auto& m : maps) {
        std::cout << "Map " << m.name() << ", ";
    }
    std::cout << '\n';
    */

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


//////////////////////////////
///  ScatterGatherContext  /// 
//////////////////////////////

class ScatterGatherContext
{
private:
    // DATA
    ebpf::Object            d_object;
    uint32_t                d_ifindex;
    ScatterProgram          d_scatterProg;
    std::vector<Worker>     d_workers;    

    // Map names
    constexpr static const auto WORKER_IPS_MAP_NAME = "map_worker_ips";
    constexpr static const auto WORKER_PORTS_MAP_NAME = "map_worker_ports";
    constexpr static const auto APP_PORT_MAP_NAME = "map_application_port";

public:
    // TODO eventually read from file
    ScatterGatherContext(const char* objFile, const char* ifname);

    void setScatterPort(uint16_t port);

    void setWorkers(const std::vector<Worker>& workers);

    const std::vector<Worker>& workers() const { return d_workers; }
};


ScatterGatherContext::ScatterGatherContext(const char* objFile, const char* ifname)
    : d_object{objFile}
    , d_ifindex{::if_nametoindex(ifname)}
    , d_scatterProg{d_object, d_ifindex}
{
    if (!d_ifindex)
        throw std::invalid_argument{"Cannot resolve interface index"};
}

void ScatterGatherContext::setScatterPort(uint16_t port)
{
    // Register the application's outgoing port
    auto applicationPortMap = d_object.findMapByName(APP_PORT_MAP_NAME).value();
    const uint32_t idx = 0;
    const auto portNetBytes = htons(port);
    applicationPortMap.update(&idx, &portNetBytes);
}

void ScatterGatherContext::setWorkers(const std::vector<Worker>& workers)
{
    d_workers = workers;

    auto workerIpMap = d_object.findMapByName(WORKER_IPS_MAP_NAME).value();
    auto workerPortMap = d_object.findMapByName(WORKER_PORTS_MAP_NAME).value();
    for (auto i = 0u; i < workers.size(); ++i) {
        auto ip = workers[i].ipAddressNet();
        auto port = workers[i].portNet();
        workerIpMap.update(&i, &ip);
        workerPortMap.update(&i, &port);
    }
}

struct IOUringContext 
{
    constexpr static const auto NumBuffers    = 1024;
    constexpr static const auto MaxBufferSize = sizeof(sg_msg_t);
    constexpr static const auto BufferGroupID = 1337;   // why this? probably arbitrary

    io_uring ring;
    char buffers[NumBuffers][MaxBufferSize] = {0};

    IOUringContext(uint32_t numEntries) 
    {
        // Initialise io_uring
        io_uring_params params;
        memset(&params, 0, sizeof(params));
        if (io_uring_queue_init_params(numEntries, &ring, &params) < 0)
            throw std::runtime_error{"Failed to initialise io_uring queue"}; 

        // Register packet buffers for buffer selection 
        io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        io_uring_prep_provide_buffers(sqe, buffers, MaxBufferSize, NumBuffers, BufferGroupID, 0);
        io_uring_submit(&ring);
        
        io_uring_cqe* cqe;
        io_uring_wait_cqe(&ring, &cqe);
        if (cqe->res < 0)
            throw std::runtime_error{"Failed to provide buffers during io_uring setup"};
        io_uring_cqe_seen(&ring, cqe);
    }
};

/////////////////////////////
///  ScatterGatherRequest  // 
/////////////////////////////

class ScatterGatherRequest
{
    // Manages the state and execution of a scatter gather request. Each invocation
    // of the scatter gather primitive creates an instance of this class.

private:
    // DATA MEMBERS
    int d_requestID;                    // The unique request ID
    int d_expectedPacketsPerMessage;    // The number of expected packets per response message
    int d_remainingPackets;             // The number of remaining packets to be read 
    
    std::unordered_map<int, uint32_t>           d_workerPacketCount;    // The number of packets received for each worker
    std::unordered_map<int, std::vector<char*>> d_workerPacketBuffers;  // The packet buffers received for each worker

public:
    
    // Maybe pass in an io_uring context into the request?? might be more flexible
    // then creating one on every request

    ScatterGatherRequest(IOUringContext* io, int requestID) {};

    void start() {};

    bool hasFinished() { return false; };

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

struct GatherArgs {
    uint32_t nodesToWait;
};

class ScatterGatherUDP 
{
private:
    // DATA MEMBERS
    int                     d_scatterSkFd;  // Scatter socket
    sockaddr_in             d_scatterSkAddr;
    int                     d_ctrlSkFd;     // Gather control socket
    std::vector<int>        d_workerSkFds;  // Gather worker sockets
    ScatterGatherContext    d_ctx;

    const uint16_t PORT = 9223;    // just generate and add to map

    static uint32_t s_nextRequestID;

    // IO uring
    IOUringContext d_ioCtx;

    enum {
        IO_READ,
        IO_WRITE,
    };

    typedef struct conn_info {
        __u32 fd;
        __u16 type;
        __u16 bid;
    } conn_info;

public:

    explicit ScatterGatherUDP(ScatterGatherContext& ctx);

    ~ScatterGatherUDP();

    bool scatter(const char* msg, size_t len);
    bool scatter(const std::string& msg);

    template <typename RESULT, 
              typename TIMEOUT_UNITS = std::chrono::microseconds,
              GatherCompletionPolicy POLICY = GatherCompletionPolicy::WaitAll>
    void gather(RESULT* result,
                TIMEOUT_UNITS timeout = {},
                GatherArgs gatherArgs = {});

    // Where to put the event loop? inside gather or a start() function?

private:

    template <typename RESULT, typename TIMEOUT_UNITS>
    void gatherWaitAll(RESULT* result, TIMEOUT_UNITS timeout);
    
    template <typename RESULT, typename TIMEOUT_UNITS>
    void gatherWaitAny(RESULT* result, TIMEOUT_UNITS timeout) { std::cout << "gatherWaitAny()\n"; }

    template <typename RESULT, typename TIMEOUT_UNITS>
    void gatherWaitN(RESULT* result, TIMEOUT_UNITS timeout, uint32_t n) { std::cout << "gatherWaitN()\n"; }


    // IO Uring helpers
    void addScatterSend(io_uring* ring, int skfd, sockaddr_in* servAddr, sg_msg_t* scatterMsg);
    void addSocketRead(io_uring* ring, int fd, unsigned groupID, size_t msgLen, unsigned flags);
};

uint32_t ScatterGatherUDP::s_nextRequestID = 0;

ScatterGatherUDP::ScatterGatherUDP(ScatterGatherContext& ctx) 
    : d_ctx{ctx}
    , d_ioCtx{2048}
{

    // Configure the scatter socket for sending
    d_scatterSkFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  
    if (d_scatterSkFd < 0)
        throw std::runtime_error{"Failed socket() on scatter socket"};

    memset(&d_scatterSkAddr, 0, sizeof(d_scatterSkAddr));
    d_scatterSkAddr.sin_family = AF_INET;
    d_scatterSkAddr.sin_port = htons(PORT);       // TODO generate and add to map
    d_scatterSkAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(d_scatterSkFd, (const struct sockaddr *) &d_scatterSkAddr, sizeof(sockaddr_in)) < 0)
        throw std::runtime_error{"Failed bind() on scatter socket"};

    d_ctx.setScatterPort(PORT); // Set the application's outgoing port for the scatter socket


    // Configure the gather-control socket
    d_ctrlSkFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  
    if (d_ctrlSkFd < 0)
        throw std::runtime_error{"Failed socket() on gather-control socket"}; 

    // TODO any further setup


    // Configure the worker sockets
    for (const auto& _ : d_ctx.workers()) {
        auto wfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (wfd < 0)
            throw std::runtime_error{"Failed socket() on a worker socket"};

        d_workerSkFds.push_back(wfd); // TODO USE WORKERS OBJECTS

        // TODO any further setup
    }

    //////////// TODO review previous setup code //////////////////////
}

ScatterGatherUDP::~ScatterGatherUDP()
{
    // TODO rather than opening and closing a socket every time, we could keep
    // a global pool of reusable sockets to avoid this on every invokation of the primitive
    close(d_scatterSkFd);
    close(d_ctrlSkFd);
    for (auto fd : d_workerSkFds)
        close(fd);
}


bool ScatterGatherUDP::scatter(const char* msg, size_t len)
{
    sg_msg_t scatter_msg;
    memset(&scatter_msg, 0, sizeof(sg_msg_t));

    scatter_msg.hdr.req_id = ++s_nextRequestID;
    scatter_msg.hdr.msg_type = SCATTER_MSG;
    scatter_msg.hdr.body_len = std::min(len, BODY_LEN);
    strncpy(scatter_msg.body, msg, scatter_msg.hdr.body_len);

    // Add the send operation to write the scatter request into the socket
    addScatterSend(&d_ioCtx.ring, d_scatterSkFd, &d_scatterSkAddr, &scatter_msg);

    // Add all the socket read operations for each worker
    // ... TODO

    // Submit all IO requests to the queue and wait
    // NOTE: if we reuse the same ring for multiple requests, this number may be
    // inaccurate because it may mix operatioms from different requests
    io_uring_submit_and_wait(&d_ioCtx.ring, d_workerSkFds.size() + 1); // TODO USE WORKERS OBJECTS
}

bool ScatterGatherUDP::scatter(const std::string& msg)
{
    auto len = strnlen(msg.c_str(), msg.size() + 1);
    scatter(msg.c_str(), len);
}

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
        for (auto i = 0u; i < d_workerSkFds.size(); ++i) {
            char resBuf[1024];
            int n = read(d_workerSkFds[i], resBuf, 1024);
            if (n < 0)
                std::cout << "Failed to read from worker " << i << "\n";
                
            resBuf[n] = '\0';
            std::cout << "Got response from worker " << i << ": '" << resBuf << "'\n";
        }

    }

}

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
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
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

    ScatterGatherContext ctx{argv[1], argv[3]};
    ctx.setWorkers(workers);

    ScatterGatherUDP scatterGather{ctx};

    std::cout << "Created context and operation\n";


    // char buf[256];
    // strncpy(buf, "SCATTER", 8);     
    // if (!scatterGather.scatter(buf, strlen(buf))) {
    //     std::cerr << "Failed to send scatter message\n";
    //     exit(EXIT_FAILURE);
    // }

    std::string scatterMsg = "SCATTER";
    if (!scatterGather.scatter(scatterMsg)) {
        std::cerr << "Failed to send scatter message\n";
        exit(EXIT_FAILURE);
    }


    int res;
    scatterGather.gather(&res);

    // Different completion policies (need to specify result type in template):
    // scatterGather.gather<int, GatherCompletionPolicy::WaitAny>(&res);
    // GatherArgs args = { .nodesToWait = 5 };
    // scatterGather.gather<int, GatherCompletionPolicy::WaitN>(&res, args);

}
