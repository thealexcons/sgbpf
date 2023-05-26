#ifndef COMMON_UTILS_H

#include <vector>
#include <sstream>
#include <fstream>
#include <exception>
#include <cstring>
#include <arpa/inet.h>
#include <chrono>
#include <cmath>
#include <algorithm>
#include <sys/resource.h>

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
    Worker(std::string ipAddress, uint16_t port, bool openSocket) {
        uint32_t ipAddrNet;
        if (!inet_pton(AF_INET, ipAddress.c_str(), &ipAddrNet))
            throw std::runtime_error{"Invalid IPv4 address in worker config"};
    
        memset(&d_destAddr, 0, sizeof(sockaddr_in));
        d_destAddr.sin_family = AF_INET;
        d_destAddr.sin_port = htons(port);
        d_destAddr.sin_addr.s_addr = ipAddrNet;

        if (openSocket)
            d_skFd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    // GETTERS
    int socketFd() const { return d_skFd; }
    sockaddr_in* destAddr() { return &d_destAddr; }

    // STATIC METHODS
    static std::vector<Worker> fromFile(const std::string& filePath, bool openSocket) {
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

                dests.emplace_back(ipStr, port, openSocket);
            }
            file.close();
        }

        return dests;
    }
};


class BenchmarkTimer {
public:
    BenchmarkTimer(std::vector<uint64_t>& times)
        : start_time{std::chrono::high_resolution_clock::now()}
        , times_vec{times}
    {}
    
    ~BenchmarkTimer() {
        auto end_time = std::chrono::high_resolution_clock::now();
        auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);
        times_vec.push_back(elapsed_time.count());
    }

    static uint64_t maxTime(const std::vector<uint64_t>& times) {
        return *std::max_element(times.begin(), times.end());
    }

    static uint64_t minTime(const std::vector<uint64_t>& times) {
        return *std::min_element(times.begin(), times.end());

    }

    static double avgTime(const std::vector<uint64_t>& times) {
        int sum = 0;
        for (const auto& num : times) {
            sum += num;
        }
        return static_cast<double>(sum) / times.size();
    }

    static double stdDev(const std::vector<uint64_t>& times) {
        auto mean = avgTime(times);
        double stdDev = 0.0;
        for(auto i = 0u; i < times.size(); ++i) {
            stdDev += pow(times[i] - mean, 2);
        }
        return std::sqrt(stdDev / times.size());
    }

    static uint64_t medianTime(std::vector<uint64_t> times) {
        size_t n = times.size();
        std::sort(times.begin(), times.end());
        
        if (n % 2 == 0) {
            return (times[n/2 - 1] + times[n/2]) / 2.0;
        } else {
            return times[n/2];
        }
    }

private:
    std::chrono::high_resolution_clock::time_point  start_time;
    std::vector<uint64_t>&                          times_vec;
};


inline void increaseMaxNumFiles()
{
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        // std::cout << "Num FDs Soft limit: " << rlim.rlim_cur << std::endl;
        // std::cout << "Num FDs Hard limit: " << rlim.rlim_max << std::endl;
        rlim.rlim_cur = 32000;
        if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
            std::cout << "Unable to set file descriptor limits" << std::endl;
            exit(1);
        }
    } else {
        std::cout << "Unable to get file descriptor limits." << std::endl;
    }

    struct rlimit rlim1;
    if (getrlimit(RLIMIT_NOFILE, &rlim1) == 0) {
        std::cout << "Updated soft limit: " << rlim1.rlim_cur << std::endl;
    }
}


#endif // !COMMON_UTILS_H