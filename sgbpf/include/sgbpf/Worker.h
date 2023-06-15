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

/**
 * @brief A single worker endpoint participating in scatter-gather operations
 */
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
    /**
     * @brief Construct a new Worker object
     * 
     * @param ipAddress the IPv4 address as a string
     * @param port the port number
     */
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
    /**
     * @brief Load workers from a text file (one worker per line in the format: address:port)
     * 
     * @param filePath the path to the file
     * @return std::vector<Worker> a list of workers
     */
    static std::vector<Worker> fromFile(const std::string& filePath);
};

} // close namespace sgbpf

#endif // !_SGBPF_WORKER_H