#include <iostream>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cmath>

#include <net/if.h>
#include <unistd.h>
#include <sys/epoll.h> 

#include <sgbpf/Worker.h>
#include <sgbpf/Context.h>
#include <sgbpf/Request.h>
#include <sgbpf/Service.h>
#include <sgbpf/Common.h>

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

    static double stdDev(const std::vector<uint64_t>& times) {
        auto mean = avgTime(times);
        double stdDev = 0.0;
        for(auto i = 0u; i < times.size(); ++i) {
            stdDev += std::pow(times[i] - mean, 2);
        }
        return std::sqrt(stdDev / times.size());
    }

    static double avgTime(const std::vector<uint64_t>& times) {
        int sum = 0;
        for (const auto& num : times) {
            sum += num;
        }
        return static_cast<double>(sum) / times.size();
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


#ifdef IO_URING_CTRL_SK

void throughput_benchmark(int numRequests, sgbpf::Context& ctx) {
    std::cout << "Running throughput experiment (io_uring mode)" << std::endl;

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    std::cout << "Workers loaded: " << workers.size() << std::endl;
    sgbpf::Service service{ctx, workers, sgbpf::PacketAction::Discard};

    auto outstandingReqs = 32;

    io_uring ring;
    io_uring_params ringParams;
    memset(&ringParams, 0, sizeof(ringParams));

    if (io_uring_queue_init_params(1024, &ring, &ringParams) < 0)
        throw std::runtime_error{"Failed to initialise io_uring queue"};

    // Preallocate and register buffers to receive the packets in
    char* buffer = new char[(numRequests + outstandingReqs) * sizeof(sg_msg_t)];

    io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    io_uring_prep_provide_buffers(sqe, buffer, sizeof(sg_msg_t), numRequests + outstandingReqs, 0, 0);
    io_uring_submit(&ring);
    io_uring_cqe* cqe;
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0)
        throw std::runtime_error{"Failed to provide io_uring buffers to the kernel"};
    io_uring_cqe_seen(&ring, cqe);

    auto totalGathers = 0;
    auto throughputCalculationRate = 200;   // print xput every n ops
    
    for (auto i = 0; i < outstandingReqs; i++) {
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_recv(sqe, service.ctrlSkFd(), NULL, sizeof(sg_msg_t), 0);
        io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
        sqe->buf_group = 0;
        sqe->user_data = 123;

        service.scatter("SCATTER", 8);
        io_uring_submit(&ring);
    }
    auto gatherCount = 0;
    auto start = std::chrono::high_resolution_clock::now();
    while (totalGathers < numRequests) {
        // wait for gather to complete
        unsigned count = 0;
        unsigned head;
        // io_uring_wait_cqe(&ring, &cqe);
        // this is wrong...
        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;
            if (cqe->user_data == 123) {
                auto bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                auto resp = (sg_msg_t*) (buffer + bid * sizeof(sg_msg_t));
                gatherCount++;
                totalGathers++;
            }
        }
        io_uring_cq_advance(&ring, count);

        service.processEvents();    // DISCARD_PK enabled, so this should be negligible

        // send out another scatter
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_recv(sqe, service.ctrlSkFd(), NULL, sizeof(sg_msg_t), 0);
        io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
        sqe->buf_group = 0;
        sqe->user_data = 123;

        service.scatter("SCATTER", 8);
        io_uring_submit(&ring);

        if (gatherCount == throughputCalculationRate) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start);
            auto tput = gatherCount / static_cast<double>(elapsed_time.count()) * 1000000;
            std::cout << "Throughput: " << tput << " req/s (" << totalGathers << " ops completed)\n" ;
            gatherCount = 0;
            start = std::chrono::high_resolution_clock::now();
        }
    }

}


void unloaded_latency_benchmark(int numRequests, sgbpf::Context& ctx) {
    std::cout << "Running unloaded latency experimen (io_uring mode)" << std::endl;

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    std::cout << "Workers loaded: " << workers.size() << std::endl;
    sgbpf::Service service{ctx, workers, sgbpf::PacketAction::Discard};

    io_uring ring;
    io_uring_params ringParams;
    memset(&ringParams, 0, sizeof(ringParams));

    if (io_uring_queue_init_params(1024, &ring, &ringParams) < 0)
        throw std::runtime_error{"Failed to initialise io_uring queue"};

    // Preallocate and register buffers to receive the packets in
    char* buffer = new char[numRequests * sizeof(sg_msg_t)];

    io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    io_uring_prep_provide_buffers(sqe, buffer, sizeof(sg_msg_t), numRequests, 0, 0);
    io_uring_submit(&ring);
    io_uring_cqe* cqe;
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0)
        throw std::runtime_error{"Failed to provide io_uring buffers to the kernel"};
    io_uring_cqe_seen(&ring, cqe);

    auto numCompletedGathers = 0;
    std::vector<uint64_t> times;
    times.reserve(numRequests);
    for (auto i = 0; i < numRequests; ++i) {
        BenchmarkTimer timer{times};
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_recv(sqe, service.ctrlSkFd(), NULL, sizeof(sg_msg_t), 0);
        io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
        sqe->buf_group = 0;
        sqe->user_data = 123;
        auto req = service.scatter("SCATTER", 8);
        io_uring_submit_and_wait(&ring, 1);

        unsigned count = 0;
        unsigned head;
        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;
            if (cqe->user_data == 123) {
                auto bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                auto resp = (sg_msg_t*) (buffer + bid * sizeof(sg_msg_t));
                numCompletedGathers++;
            }
        }
        io_uring_cq_advance(&ring, count);

        service.processEvents(req->id());
    }

    std::cout << "Num workers: " << workers.size() << std::endl;
    std::cout << "Avg unloaded latency: " << BenchmarkTimer::avgTime(times) << " us\n";
    std::cout << "Median unloaded latency: " << BenchmarkTimer::medianTime(times) << " us\n";
    std::cout << "Std dev unloaded latency: " << BenchmarkTimer::stdDev(times) << " us\n";
}

#else

void throughput_benchmark(int numRequests, sgbpf::Context& ctx) {
    std::cout << "Running throughput experiment" << std::endl;

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    std::cout << "Workers loaded: " << workers.size() << std::endl;
    sgbpf::Service service{ctx, workers, sgbpf::PacketAction::Discard};

    auto totalGathers = 0;
    auto throughputCalculationRate = 200;   // print xput every n ops
    
    auto outstandingReqs = 32;
    for (auto i = 0; i < outstandingReqs; i++) {
        service.scatter("SCATTER", 8);
    }
    sg_msg_t buf;
    auto gatherCount = 0;
    auto start = std::chrono::high_resolution_clock::now();
    while (totalGathers < numRequests) {
        // wait for gather to complete
        std::cout << totalGathers << std::endl;
        auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
        assert(b == sizeof(sg_msg_t));
        service.processEvents();    // DISCARD_PK enabled, so this should be negligible

        gatherCount++;
        totalGathers++;

        // send out another scatter
        service.scatter("SCATTER", 8);

        if (gatherCount == throughputCalculationRate) {
            auto end_time = std::chrono::high_resolution_clock::now();
            auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start);
            auto tput = gatherCount / static_cast<double>(elapsed_time.count()) * 1000000;
            std::cout << "Throughput: " << tput << " req/s (" << totalGathers << " ops completed)\n" ;
            gatherCount = 0;
            start = std::chrono::high_resolution_clock::now();
        }
    }

}

void unloaded_latency_benchmark(int numRequests, sgbpf::Context& ctx) {
    std::cout << "Running unloaded latency experiment" << std::endl;

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    std::cout << "Workers loaded: " << workers.size() << std::endl;
    sgbpf::Service service{ctx, workers, sgbpf::PacketAction::Discard};

    sg_msg_t buf;
    std::vector<uint64_t> times;
    times.reserve(numRequests);
    for (auto i = 0; i < numRequests; ++i) {
        BenchmarkTimer timer{times};
        auto req = service.scatter("SCATTER", 8);
 
        auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
        assert(b == sizeof(sg_msg_t));
        service.processEvents(req->id());
    }

    std::cout << "Num workers: " << workers.size() << std::endl;
    std::cout << "Avg unloaded latency: " << BenchmarkTimer::avgTime(times) << " us\n";
    std::cout << "Median unloaded latency: " << BenchmarkTimer::medianTime(times) << " us\n";
    std::cout << "Std dev unloaded latency: " << BenchmarkTimer::stdDev(times) << " us\n";
}

#endif

int main(int argc, char** argv) {

    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <path/to/bpfobjs> <ifname> <numReqs> <benchmark>" << std::endl;
        return 1;
    }
    sgbpf::Context ctx{argv[1], argv[2]};
    int reqs = atoi(argv[3]);
    std::string option = argv[4];

    if (option == "throughput") {
        throughput_benchmark(reqs, ctx);
    }
    else {
        unloaded_latency_benchmark(reqs, ctx);
    }
}
