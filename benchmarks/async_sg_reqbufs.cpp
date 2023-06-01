#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <iostream>
#include <vector>
#include <cassert>
#include <thread>
#include <fcntl.h>
#include <liburing.h>

#include "common.h"

inline uint32_t getRequestMapIdx(uint32_t reqID) {
    return reqID & (8192 - 1);
}


struct Request {
    char* d_buffers; 
    uint32_t d_reqId;   
    bool d_active = false;

    Request(uint32_t reqId, uint32_t pks) {
        d_buffers = new char[pks * sizeof(sg_msg_t)];
        d_reqId = reqId;
        d_active = true;
    }

    Request() = default;

    ~Request() {
        delete[] d_buffers;
    }
};


class ScatterGatherService {

    typedef struct __attribute__((packed)) conn_info  {
        int      reqID;
        uint16_t type;
        uint16_t idx;
    } conn_info_t;

    std::vector<Worker>&       d_workers;
    uint32_t                   d_nextRequest = 0;
    io_uring                   d_ring;
    msghdr*                    d_msgHdrs;
    uint16_t                   d_bgid = 42;
    // char*                      d_buffers;
    int                        d_skFd;
    Request*                   d_requests;
    // size_t                     d_numSkReads;
    // std::vector<char*>         d_packetBufferPool;
    constexpr static const int NUM_BUFFERS = std::numeric_limits<uint16_t>::max(); // for fair comparison with sgbpf

    constexpr static uint16_t READ_OP = 0x12;

public:
    ScatterGatherService(std::vector<Worker>& workers)
        : d_workers{workers}
    {
        std::cout << "Workers loaded: " << workers.size() << std::endl;
        increaseMaxNumFiles();

        d_requests = new Request[8192];

        d_skFd = socket(AF_INET, SOCK_DGRAM, 0);

        d_msgHdrs = new msghdr[d_workers.size()];

        // Setup io uring
        io_uring_params params;
        memset(&params, 0, sizeof(params));

        if (io_uring_queue_init_params(d_workers.size() * 3, &d_ring, &params) < 0)
            throw std::runtime_error{"Failed to initialise io_uring queue"};

        // Preallocate and register buffers to receive the packets in
        // provideBuffers(true);
    }

    ~ScatterGatherService() {
        delete[] d_msgHdrs;
    }

    void scatter(const char* msg, size_t len) {
        // prepare a dummy sg_msg_t to send
        int reqID = d_nextRequest++;
        sg_msg_t scatter_msg;
        scatter_msg.hdr.req_id = reqID;
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

        auto idx = getRequestMapIdx(scatter_msg.hdr.req_id);
        if (d_requests[idx].d_active) {
            d_requests[idx].~Request(); // explicitly free resources
        }
        Request* req = new (d_requests + idx) Request{reqID, d_workers.size()};


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
            io_uring_prep_recv(sqe, worker.socketFd(), req->d_buffers + i * sizeof(sg_msg_t), sizeof(sg_msg_t), 0);
            // io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
            // sqe->buf_group = bgid;
            conn_info_t conn_i = {
                .reqID = reqID,
                .type = READ_OP,
                .idx = i,
            };
            memcpy(&sqe->user_data, &conn_i, sizeof(conn_info_t));
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
                const auto conn_i = reinterpret_cast<conn_info_t*>(&cqe->user_data);
                if (conn_i->type == READ_OP) {
                    auto idx = conn_i->idx;
                    auto reqID = conn_i->reqID;
                    if (!d_requests[getRequestMapIdx(reqID)].d_active)
                        continue;
                    // auto bgid = conn_i->bgid;
                    // auto bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                    auto resp = (sg_msg_t*) (d_requests[getRequestMapIdx(reqID)].d_buffers + idx * sizeof(sg_msg_t));

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

void throughput_benchmark(int numRequests) {
    std::cout << "Running throughput experiment" << std::endl;

    auto workers = Worker::fromFile("workers.cfg", true);
    ScatterGatherService service{workers};

    auto totalGathers = 0;
    auto throughputCalculationRate = 200;   // print xput every n ops
    
    if (numRequests < throughputCalculationRate) {
        std::cout << "Please specify a larger number of requests (at least 200)\n";
        return;
    }
    
    std::vector<uint64_t> throughputValues;

    auto outstandingReqs = 128;
    for (auto i = 0; i < outstandingReqs; i++) {
        service.scatter("SCATTER", 8);
    }
    auto gatherCount = 0;
    auto start = std::chrono::high_resolution_clock::now();
    while (totalGathers < numRequests) {
        // wait for gather to complete
        uint32_t data[1024];
        memset(data, 0, sizeof(data));
        service.gather<uint32_t>(data);

        gatherCount++;
        totalGathers++;

        // send out another scatter
        service.scatter("SCATTER", 8);

        if (gatherCount == throughputCalculationRate) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start);
            auto tput = gatherCount / static_cast<double>(elapsed_time.count()) * 1000000;
            throughputValues.push_back(tput);
            // std::cout << "Throughput: " << tput << " req/s (" << totalGathers << " ops completed)\n" ;
            std::cout << tput << "\n" ;
            gatherCount = 0;
            start = std::chrono::high_resolution_clock::now();
        }
    }
    std::cout << "!!!!!!! Average throughput = " << BenchmarkTimer::avgTime(throughputValues) << " req/s" << std::endl;

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

    std::cout << "Avg unloaded latency: " << BenchmarkTimer::avgTime(times) << " us\n";
    std::cout << "Median unloaded latency: " << BenchmarkTimer::medianTime(times) << " us\n";
    std::cout << "Std dev unloaded latency: " << BenchmarkTimer::stdDev(times) << " us\n";
} 


int main(int argc, char* argv[]) {

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <num reqs> <mode>" << std::endl;
        return 1;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(std::thread::hardware_concurrency() - 1, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);


    int numRequests = atoi(argv[1]);
    std::string option = argv[2];

    if (option == "throughput") {
        throughput_benchmark(numRequests);
    }
    else {
        unloaded_latency_benchmark(numRequests);
    }
    
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
    */
}
