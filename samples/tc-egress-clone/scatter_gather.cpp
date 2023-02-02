#include <vector>
#include <stdexcept>
#include <iostream>
#include <fstream>
#include <sstream>
#include <cstring>

#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>




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
    const uint16_t portNet() { return d_portNet; }
    const std::string& ipAddress() const { return d_ipAddress; }
    uint16_t port() const { return d_port; }

    // STATIC METHODS
    static std::vector<Worker> fromFile(const std::string& filePath);
};

Worker::Worker(std::string ipAddress, uint16_t port)
    : d_ipAddress{std::move(ipAddress)}
    , d_port{port}
{
    if (!inet_pton(AF_INET, d_ipAddress.c_str(), &d_ipAddress))
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
                
            auto ipStr = ptr;

            ptr = strtok(NULL, ":");
            if (!ptr)
                throw std::runtime_error{"Invalid workers config file"};
            
            auto port = static_cast<uint16_t>(std::stoi(ptr));

            dests.emplace_back(ipStr, port);
        }
        file.close();
    }

    return dests;
}


////////////////////////////////////////////////////////////////////

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
    int                 d_scatterSkFd;  // Scatter socket
    sockaddr_in         d_scatterSkAddr;
    int                 d_ctrlSkFd;     // Gather control socket
    std::vector<int>    d_workerSkFds;  // Gather worker sockets
    std::vector<Worker> d_workers;

    const uint16_t      PORT = 9223;    // just generate and add to map

public:

    explicit ScatterGatherUDP(const std::vector<Worker>& workers);

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


ScatterGatherUDP::ScatterGatherUDP(const std::vector<Worker>& workers) 
    : d_workers{workers}
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


    // Configure the gather-control socket
    d_ctrlSkFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);  
    if (d_ctrlSkFd < 0)
        throw std::runtime_error{"Failed socket() on gather-control socket"}; 

    // TODO any further setup


    // Configure the worker sockets
    for (const auto& worker : d_workers) {
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
        for (auto i = 0; i < d_workerSkFds.size(); ++i) {
            char resBuf[1024];
            int n = read(d_workerSkFds[i], resBuf, 1024);
            if (n < 0)
                std::cout << "Failed to read from worker " << i << "\n";
                
            resBuf[n] = '\0';
            std::cout << "Got response from worker " << i << ": '" << resBuf << "'\n";
        }

    }

}



int main() {

    // globally initialises the library and prepares eBPF subsystem
    // ScatterGather::init("scatter_gather.json");

    auto workers = Worker::fromFile("workers.cfg");

    ScatterGatherUDP scatterGather{workers};

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