#ifndef _SGBPF_WORKER_H
#define _SGBPF_WORKER_H

#include "ebpf/Program.h"

#include <vector>
#include <sstream>
#include <fstream>
#include <exception>
#include <cstring>
#include <arpa/inet.h>

namespace sgbpf {

class Worker 
{
private:
    uint32_t    d_ipAddressNet;
    uint16_t    d_portNet;
    std::string d_ipAddress;
    uint16_t    d_port;
    int         d_skFd = -1;
    sockaddr_in d_destAddr;

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

    sockaddr_in* destAddr() { return &d_destAddr; }
 
    // STATIC METHODS
    static std::vector<Worker> fromFile(const std::string& filePath);
};

} // close namespace sgbpf

#endif // !_SGBPF_WORKER_H