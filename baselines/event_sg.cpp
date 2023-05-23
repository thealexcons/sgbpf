#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <iostream>
#include <vector>
#include <cassert>
#include <fcntl.h>
#include <sys/epoll.h>

#include "common.h"

class ScatterGatherService {

    std::vector<Worker>&       d_workers;
    uint32_t                   d_nextRequest = 0;
    int                        d_epollFd;
    epoll_event*               d_events;         

public:
    ScatterGatherService(std::vector<Worker>& workers)
        : d_workers{workers}
    {
        increaseMaxNumFiles();

        d_events = new epoll_event[d_workers.size()];

        // Register the worker sockets with epoll for read events
        d_epollFd = epoll_create1(0);
        assert(d_epollFd != -1);

        // make all worker sockets non-blocking
        for (auto& worker : d_workers) {
            int flags = fcntl(worker.socketFd(), F_GETFL, 0);
            assert(flags != -1);
            flags |= O_NONBLOCK;
            assert(fcntl(worker.socketFd(), F_SETFL, flags) != -1);

            epoll_event event;
            event.data.fd = worker.socketFd();
            event.events = EPOLLIN | EPOLLET;
            epoll_ctl(d_epollFd, EPOLL_CTL_ADD, worker.socketFd(), &event);
        }
    }

    ~ScatterGatherService() {
        delete[] d_events;
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
            sendto(worker.socketFd(), &scatter_msg, sizeof(sg_msg_t), 0, (struct sockaddr *)worker.destAddr(), addrSize);              
        }
    }

    template <typename DATA_TYPE>
    void gather(DATA_TYPE* result) {
        int remainingReads = d_workers.size();
        while (remainingReads > 0) {
            int n = epoll_wait(d_epollFd, d_events, d_workers.size(), -1);
            for (int i = 0; i < n; i++) {
                if (d_events[i].events & EPOLLIN && d_events[i].data.fd > 0) {
                    // Handle the message
                    sg_msg_t resp;
                    auto bytes = recv(d_events[i].data.fd, &resp, sizeof(sg_msg_t), 0);
                    assert(errno != EAGAIN && errno != EWOULDBLOCK);
                    assert(bytes == sizeof(sg_msg_t));

                    // Aggregation logic:
                    auto numElems = resp.hdr.body_len / sizeof(DATA_TYPE);
                    auto resp_data = (uint32_t*) resp.body;
                    for (auto i = 0u; i < numElems; i++) {
                        result[i] += resp_data[i];
                    }

                    remainingReads -= 1;
                }
            }
        }
    }

};

void throughput_benchmark(int numRequests) {
    std::cout << "Running throughput experiment" << std::endl;

    auto workers = Worker::fromFile("workers.cfg", true);
    ScatterGatherService service{workers};

    // ... 
    // confirm that async one is good

}

void unloaded_latency_benchmark(int numRequests) {
    std::cout << "Running unloaded latency experiment" << std::endl;

    auto workers = Worker::fromFile("workers.cfg", true);
    ScatterGatherService service{workers};

    uint32_t data[1024]; // reserve enough memory for the aggregated data
    std::vector<uint64_t> times;
    times.reserve(numRequests);
    for (auto i = 0; i < numRequests; ++i) {
        BenchmarkTimer timer{times};
        service.scatter("SCATTER", 8);

        memset(data, 0, sizeof(data));
        service.gather<uint32_t>(data);
    }

    std::cout << "Num workers: " << workers.size() << std::endl;
    std::cout << "Avg unloaded latency: " << BenchmarkTimer::avgTime(times) << " us\n";
    std::cout << "Median unloaded latency: " << BenchmarkTimer::medianTime(times) << " us\n";
    std::cout << "Std dev unloaded latency: " << BenchmarkTimer::stdDev(times) << " us\n";
}

int main(int argc, char* argv[]) {

    // Note: this implementation uses per-worker sockets to demonstrate the benefits
    // of an event notification system when handling multiple sockets. Otherwise,
    // it would have no advantage over using a single socket approach.

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <num reqs> <mode>" << std::endl;
        return 1;
    }
    int numRequests = atoi(argv[1]);
    std::string option = argv[2];

    if (option == "throughput") {
        throughput_benchmark(numRequests);
    }
    else {
        unloaded_latency_benchmark(numRequests);
    }

}