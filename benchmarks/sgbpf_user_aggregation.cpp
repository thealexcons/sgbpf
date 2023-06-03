#include <iostream>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <deque>
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



void throughput_benchmark(int numRequests, sgbpf::Context& ctx) {
    std::cout << "Running throughput experiment" << std::endl;

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    std::cout << "Workers loaded: " << workers.size() << std::endl;
    sgbpf::Service service{
        ctx, 
        workers, 
        sgbpf::PacketAction::Allow,
        sgbpf::CtrlSockMode::DefaultUnix
    };
    auto outstandingReqs = 32;
    auto totalGathers = 0;
    auto throughputCalculationRate = 200;   // print xput every n ops
    
    if (numRequests < throughputCalculationRate) {
        std::cout << "Please specify a larger number of requests (at least 200)\n";
        return;
    }

    std::deque<sgbpf::Request*> reqs;
    // reqs.reserve(numRequests + outstandingReqs);
    for (auto i = 0; i < outstandingReqs; i++) {
        auto r = service.scatter("SCATTER", 8); // this will block
        reqs.push_back(r);
    }

    uint32_t data[RESP_MAX_VECTOR_SIZE];
    auto gatherCount = 0;
    auto start = std::chrono::high_resolution_clock::now();
    while (totalGathers < numRequests) {
        // wait for one gather to complete
        service.processEvents();
        for (auto it=reqs.begin(); it!=reqs.end(); ++it) {
            auto req = *it;
            if (req->isReady()) {
                for (auto [wfd, ptrs] : req->bufferPointers()) {
                    assert(ptrs.size() == 1);
                    auto ptr = ptrs[0];

                    for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
                        auto buf = (sg_msg_t*) req->data(ptr);
                        data[j] += ((uint32_t*) buf->body)[j]; 
                    }
                }
                memset(data, 0, sizeof(uint32_t) * RESP_MAX_VECTOR_SIZE);
                gatherCount++;
                totalGathers++;
                reqs.erase(it);
                break;
            }
        }

        auto r = service.scatter("SCATTER", 8);
        reqs.push_back(r);

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
    sgbpf::Service service{
        ctx, 
        workers, 
        sgbpf::PacketAction::Allow,
        sgbpf::CtrlSockMode::DefaultUnix
    };

    sgbpf::ReqParams params;
    params.completionPolicy = sgbpf::GatherCompletionPolicy::WaitAll;
    params.timeout = std::chrono::microseconds{50000 * 100};

    sg_msg_t buf;
    uint32_t data[RESP_MAX_VECTOR_SIZE];
    std::vector<uint64_t> times;
    times.reserve(numRequests);
    for (auto i = 0; i < numRequests; ++i) {
        memset(data, 0, sizeof(uint32_t) * RESP_MAX_VECTOR_SIZE);
        
        BenchmarkTimer timer{times};
        auto req = service.scatter("SCATTER", 8, params);
        auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
        assert(b == sizeof(sg_msg_t));

        // should be ready, but check just in case ctrl sk data "beats" worker sk data in kernel stack
        while (!req->isReady()) {
            service.processEvents(req->id());
        }
        for (auto [wfd, ptrs] : req->bufferPointers()) {
            assert(ptrs.size() == 1);
            auto ptr = ptrs[0];

            for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
                auto buf = (sg_msg_t*) req->data(ptr);
                data[j] += ((uint32_t*) buf->body)[j];
            }
        }
    }

    std::cout << "Avg unloaded latency: " << BenchmarkTimer::avgTime(times) << " us\n";
    std::cout << "Median unloaded latency: " << BenchmarkTimer::medianTime(times) << " us\n";
    std::cout << "Std dev unloaded latency: " << BenchmarkTimer::stdDev(times) << " us\n";
}


int main(int argc, char** argv) {

    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " <path/to/bpfobjs> <ifname> <numReqs> <benchmark>" << std::endl;
        return 1;
    }

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(std::thread::hardware_concurrency() - 1, &cpuset);
    sched_setaffinity(0, sizeof(cpu_set_t), &cpuset);

    std::cout << "REMINDER: make sure the aggregation function is compiled with ALLOW_PK specified\n";

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
