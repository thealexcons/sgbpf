#include <vector>
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


#include "ebpfpp/Program.h"
#include "ebpfpp/Map.h"
#include "ebpfpp/Object.h"
#include "ebpfpp/Util.h"

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
    ScatterProgram(const ebpf::Object& obj, int ifindex);

    ~ScatterProgram();
};

ScatterProgram::ScatterProgram(const ebpf::Object& obj, int ifindex) 
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
    int                     d_ifindex;
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

public:

    explicit ScatterGatherUDP(ScatterGatherContext& ctx);

    ~ScatterGatherUDP();

    bool scatter(const char* msg, size_t len);

    template <typename RESULT, GatherCompletionPolicy POLICY = GatherCompletionPolicy::WaitAll>
    void gather(RESULT* result,
                GatherArgs gatherArgs = {});

private:

    template <typename RESULT>
    void gatherWaitAll(RESULT* result);
    
    template <typename RESULT>
    void gatherWaitAny(RESULT* result) { std::cout << "gatherWaitAny()\n"; }

    template <typename RESULT>
    void gatherWaitN(RESULT* result, uint32_t n) { std::cout << "gatherWaitN()\n"; }

};


ScatterGatherUDP::ScatterGatherUDP(ScatterGatherContext& ctx) 
    : d_ctx{ctx}
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

        d_workerSkFds.push_back(wfd);

        // TODO any further setup
    }
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
    // Send the dummy scatter message to itself
    std::cout << "Calling sendto()\n";
    return sendto(d_scatterSkFd, msg, len, 0, (const struct sockaddr *)&d_scatterSkAddr, sizeof(sockaddr_in)) != -1;
}



template <typename RESULT, GatherCompletionPolicy POLICY>
void ScatterGatherUDP::gather(RESULT* result,
                              GatherArgs gatherArgs)
{
    if constexpr(POLICY == GatherCompletionPolicy::WaitAll)
        return gatherWaitAll(result);
    else if constexpr(POLICY == GatherCompletionPolicy::WaitAny)
        return gatherWaitAny(result);
    else
        return gatherWaitN(result, gatherArgs.nodesToWait);
}


template <typename RESULT>
void ScatterGatherUDP::gatherWaitAll(RESULT* result)
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



int main(int argc, char** argv) {

    // globally initialises the library and prepares eBPF subsystem
    // ScatterGather::init("scatter_gather.json");


    auto workers = Worker::fromFile("workers.cfg");

    ScatterGatherContext ctx{argv[1], argv[3]};
    ctx.setWorkers(workers);

    ScatterGatherUDP scatterGather{ctx};

    std::cout << "Created context and operation\n";


    char buf[256];
    strncpy(buf, "SCATTER", 8); 
    if (!scatterGather.scatter(buf, strlen(buf))) {
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
