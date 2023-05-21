#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <iostream>
#include <vector>
#include <cassert>

#include "common.h"

class ScatterGatherService {

    std::vector<Worker>&       d_workers;
    uint32_t                   d_nextRequest = 0;
    int                        d_skFd;

public:
    ScatterGatherService(std::vector<Worker>& workers)
        : d_workers{workers}
    {
        d_skFd = socket(AF_INET, SOCK_DGRAM, 0);
    }

    void scatter(const char* msg, size_t len) {
        // prepare a dummy sg_msg_t to send
        sg_msg_t scatter_msg;
        scatter_msg.hdr.req_id = d_nextRequest++;
        scatter_msg.hdr.seq_num = 0;
        scatter_msg.hdr.num_pks = 1; 
        scatter_msg.hdr.body_len = std::min(len, BODY_LEN);
        scatter_msg.hdr.msg_type = 0;
        scatter_msg.hdr.flags = 0;
        strncpy(scatter_msg.body, msg, scatter_msg.hdr.body_len);

        socklen_t addrSize = sizeof(sockaddr_in);
        for (auto& worker : d_workers) {
            // MAIN DIFFERENCE HERE: send via a single "global" socket to the worker
            sendto(d_skFd, &scatter_msg, sizeof(sg_msg_t), 0, (struct sockaddr *)worker.destAddr(), addrSize);              
        }
    }

    template <typename DATA_TYPE>
    void gather(DATA_TYPE* result) {
        for (auto& _ : d_workers) {
            (void)_;
            sockaddr_in client;
            socklen_t clientSize = sizeof(sockaddr_in);
            sg_msg_t resp;
            auto bytes = recvfrom(d_skFd, &resp, sizeof(sg_msg_t), 0, (struct sockaddr *) &client, &clientSize);
            assert(bytes == sizeof(sg_msg_t));
            // Note: we assume that only the workers are sending data to this process
            // and therefore we do not have to check that the client addr is a valid worker addr

            // Aggregation logic:
            auto numElems = resp.hdr.body_len / sizeof(DATA_TYPE);
            auto resp_data = (uint32_t*) resp.body;
            for (auto i = 0u; i < numElems; i++) {
                result[i] += resp_data[i];
            }
        }
    }

};


int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "Please provide the number of requests to send" << std::endl;
        return 1;
    }
    int numRequests = atoi(argv[1]);

    auto workers = Worker::fromFile("workers.cfg");
    ScatterGatherService service{workers};

    auto start = std::chrono::high_resolution_clock::now();

    // assume requests are sequential
    for (auto i = 0; i < numRequests; ++i) {
        service.scatter("SCATTER", 8);

        uint32_t data[1024]; // reserve enough memory
        memset(data, 0, sizeof(data));
        service.gather<uint32_t>(data);
    }

    auto end_time = std::chrono::high_resolution_clock::now();
    auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start);
    std::cout << "Total time = " << elapsed_time.count() << " us - " 
                << "Num requests = " << numRequests 
                << " , Num Workers = " << workers.size() 
                << std::endl;

}