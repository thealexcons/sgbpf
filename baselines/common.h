#ifndef COMMON_UTILS_H

#include <vector>
#include <sstream>
#include <fstream>
#include <exception>
#include <cstring>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>


#define MTU_SIZE 1500

typedef struct __attribute__((packed)) {
    // Header
    struct __attribute__((packed)) sg_msg_hdr {
        unsigned int    req_id;         // The request ID
        unsigned int    seq_num;        // The sequence number in a multi-packet msg
        unsigned int    num_pks;        // The number of packets in a multi-packet msg (used as waitN value in egress msg)
        unsigned int    body_len;       // The length of the body in bytes
        unsigned char   msg_type;       // The message type (SCATTER or GATHER)
        unsigned char   flags;          // Extra flags
    } hdr;

    // Body
    char body[MTU_SIZE - sizeof(struct iphdr) - sizeof(struct udphdr) - sizeof(struct sg_msg_hdr)];
} sg_msg_t;

#define BODY_LEN (sizeof(sg_msg_t) - __builtin_offsetof(sg_msg_t, body))


class Worker 
{
private:
    sockaddr_in d_destAddr;
    int         d_skFd;

public:

    // CONSTRUCTORS
    Worker(std::string ipAddress, uint16_t port) {
        uint32_t ipAddrNet;
        if (!inet_pton(AF_INET, ipAddress.c_str(), &ipAddrNet))
            throw std::runtime_error{"Invalid IPv4 address in worker config"};
    
        memset(&d_destAddr, 0, sizeof(sockaddr_in));
        d_destAddr.sin_family = AF_INET;
        d_destAddr.sin_port = htons(port);
        d_destAddr.sin_addr.s_addr = ipAddrNet;

        d_skFd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    // GETTERS
    int socketFd() const { return d_skFd; }
    sockaddr_in* destAddr() { return &d_destAddr; }

    // STATIC METHODS
    static std::vector<Worker> fromFile(const std::string& filePath) {
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
};


#endif // !COMMON_UTILS_H