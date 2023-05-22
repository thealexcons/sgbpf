#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <iostream>
#include <vector>
#include <cassert>
#include <fcntl.h>
#include <liburing.h>

#include "common.h"

class ScatterGatherService {

    std::vector<Worker>&       d_workers;
    uint32_t                   d_nextRequest = 0;
    io_uring                   d_ring;
    msghdr*                    d_msgHdrs;
    uint16_t                   d_bgid = 42;
    char*                      d_buffers;

    constexpr static uint64_t READ_OP = 0xdeadbeef;

public:
    ScatterGatherService(std::vector<Worker>& workers)
        : d_workers{workers}
    {
        increaseMaxNumFiles();

        std::cout << "num workers: " << d_workers.size() << std::endl;
        d_msgHdrs = new msghdr[d_workers.size()];
        d_buffers = new char[sizeof(sg_msg_t) * d_workers.size()];

        // Setup io uring
        io_uring_params params;
        memset(&params, 0, sizeof(params));

        if (io_uring_queue_init_params(d_workers.size() * 3, &d_ring, &params) < 0)
            throw std::runtime_error{"Failed to initialise io_uring queue"};

        // Preallocate and register buffers to receive the packets in
        io_uring_sqe* sqe = io_uring_get_sqe(&d_ring);
        io_uring_prep_provide_buffers(sqe, d_buffers, sizeof(sg_msg_t), d_workers.size(), d_bgid, 0);
        io_uring_submit(&d_ring);
        io_uring_cqe* cqe;
        io_uring_wait_cqe(&d_ring, &cqe);
        if (cqe->res < 0)
            throw std::runtime_error{"Failed to provide io_uring buffers to the kernel"};
        io_uring_cqe_seen(&d_ring, cqe);
    }

    ~ScatterGatherService() {
        delete[] d_msgHdrs;
        delete[] d_buffers;
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

        struct iovec iov = {
            .iov_base = &scatter_msg,
            .iov_len = sizeof(sg_msg_t),
        };

        for (auto i = 0u; i < d_workers.size(); ++i) {
            auto& worker = d_workers[i];
            memset(&d_msgHdrs[i], 0, sizeof(msghdr));
            d_msgHdrs[i].msg_name = worker.destAddr();
            d_msgHdrs[i].msg_namelen = sizeof(sockaddr_in);
            d_msgHdrs[i].msg_iov = &iov;
            d_msgHdrs[i].msg_iovlen = 1;

            // Add write
            io_uring_sqe *sqe = io_uring_get_sqe(&d_ring);
            io_uring_prep_sendmsg(sqe, worker.socketFd(), &d_msgHdrs[i], 0);
            io_uring_sqe_set_flags(sqe, 0);

            // Add read
            sqe = io_uring_get_sqe(&d_ring);
            io_uring_prep_recv(sqe, worker.socketFd(), NULL, sizeof(sg_msg_t), 0);
            io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
            sqe->buf_group = d_bgid;
            sqe->user_data = READ_OP;
        }

        // Submit send syscalls as batch and wait for a response from each worker
        #ifdef BUSY_WAITING_MODE
        io_uring_submit(&d_ring);
        #else
        io_uring_submit_and_wait(&d_ring, d_workers.size());
        #endif
    }

    template <typename DATA_TYPE>
    void gather(DATA_TYPE* result) {
        int remainingReads = d_workers.size();

        while (remainingReads > 0) {
            io_uring_cqe *cqe;
            unsigned count = 0;
            unsigned head;
            io_uring_for_each_cqe(&d_ring, head, cqe) {
                ++count;
                if (cqe->user_data == READ_OP) {
                    auto bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                    auto resp = (sg_msg_t*) (d_buffers + bid * sizeof(sg_msg_t));

                    // Aggregation logic:
                    auto numElems = resp->hdr.body_len / sizeof(DATA_TYPE);
                    auto resp_data = (uint32_t*) resp->body;
                    for (auto i = 0u; i < numElems; i++) {
                        result[i] += resp_data[i];
                    }
                    remainingReads -= 1;
                }
            }
            io_uring_cq_advance(&d_ring, count);
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


    /*
    start time
    n scatters
    gather_count = 0
    while(1)
    {
        wait for gather
        gather_count++
        send out a new scatter

        if (gather_count % n == 0)
            time = now() - start_time
            throughput = gather_count / time
            print(throughput) 
            gather_count = 0
            start_time = now()
    }

    auto throughputCalculationRate = 64;
    auto outstandingReqs = 64;
    for (auto i = 0; i < outstandingReqs; i++) {
        service.scatter("SCATTER", 8);
    }
    auto gatherCount = 0;
    auto start = std::chrono::high_resolution_clock::now();
    while (1) {
        // wait for gather to complete
        uint32_t data[1024];
        memset(data, 0, sizeof(data));
        service.gather<uint32_t>(data);
        for (int i = 0; i < 25; i++) {
            std::cout << data[i] << std::endl;
            // assert(data[i] == workers.size()*i);
        }
        gatherCount++;

        // send out another gather
        service.scatter("SCATTER", 8);

        if (gatherCount == throughputCalculationRate) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto elapsed_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start);
            auto tput = gatherCount / static_cast<double>(elapsed_time.count());
            std::cout << "Throughput: " << tput << " req/s\n";
            gatherCount = 0;
            start = std::chrono::high_resolution_clock::now();
        }
    }
    */

    uint32_t data[1024]; // reserve enough memory for the aggregated data
    std::vector<uint64_t> times;
    times.reserve(numRequests);
    for (auto i = 0; i < numRequests; ++i) {
        BenchmarkTimer timer{times};
        service.scatter("SCATTER", 8);

        memset(data, 0, sizeof(data));
        service.gather<uint32_t>(data);
    }

    std::cout << "Avg unloaded latency: " << BenchmarkTimer::avgTime(times) << " us\n";
    std::cout << "Median unloaded latency: " << BenchmarkTimer::medianTime(times) << " us\n";
    std::cout << "Std dev unloaded latency: " << BenchmarkTimer::stdDev(times) << " us\n";


    // for (auto i = 0; i < numRequests; ++i) {

    //     // start time
    //     service.scatter("SCATTER", 8);

    //     uint32_t data[1024]; // reserve enough memory
    //     memset(data, 0, sizeof(data));
    //     service.gather<uint32_t>(data);
    //     // end time

        // for (int i = 0; i < 100; i++) {
        //     assert(data[i] == workers.size()*i);
        // }
    // }

    // auto end_time = std::chrono::high_resolution_clock::now();
    // auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start);
    // std::cout << "Total time = " << elapsed_time.count() << " us - " 
    //             << "Num requests = " << numRequests 
    //             << " , Num Workers = " << workers.size() 
    //             << std::endl;
}