#include <iostream>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>

#include <net/if.h>
#include <unistd.h>

#include "sgbpf/Worker.h"
#include "sgbpf/Context.h"
#include "sgbpf/Request.h"
#include "sgbpf/Service.h"
#include "sgbpf/Common.h"

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

int main(int argc, char** argv) {

    if (argc < 3) {
        std::cerr << "Invalid usage. Correct usage: " << argv[0] << " <path/to/bpfobjs> <ifname>" << std::endl;
        return 1;
    }
    // sudo ./sg_program bpfobjs lo
    // export OUTPUT_BPF_OBJ_DIR=$(pwd)/bpfobjs

    // Standard method (BPF program)
    // export CUSTOM_AGGREGATION_BPF_PROG=$(pwd)/custom_aggregation.bpf.c
    // Using make --directory=../sgbpf bpf
    // sgbpf::ContextParams ctxParams;
    // ctxParams.bpfObjsPath = argv[1];
    // ctxParams.customAggregationMode = sgbpf::AggregationMode::Program;
    // ctxParams.ifname = argv[2];
    // sgbpf::Context ctx{ctxParams};

    // Using the alternative method (regular C function for custom aggregation)
    // export CUSTOM_AGGREGATION_FUNCTION=$(pwd)/custom_agg_func.bpf.h
    // Using make --directory=../sgbpf bpf_func
    sgbpf::ContextParams ctxParams;
    ctxParams.bpfObjsPath = argv[1];
    ctxParams.customAggregationMode = sgbpf::AggregationMode::Function;
    ctxParams.ifname = argv[2];
    sgbpf::Context ctx{ctxParams};

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    sgbpf::Service service{ctx, workers};
    
    // EXAMPLE 1: Vector-based data (with in-kernel aggregation)
    sgbpf::ReqParams params; // set params here....
    params.completionPolicy = sgbpf::GatherCompletionPolicy::WaitN;
    params.numWorkersToWait = 10;
    params.timeout = std::chrono::microseconds{100*1000}; // 10 ms
    
    std::vector<uint64_t> times;
    times.reserve(100);
    for (auto i = 0u; i < 100; i++) {
        BenchmarkTimer t{times};
        auto req = service.scatter("SCATTER", 8, params);
        sg_msg_t buf;
        auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
        assert(b == sizeof(sg_msg_t));
        assert(buf.hdr.req_id == req->id());
        service.processEvents();
        // std::this_thread::sleep_for(std::chrono::microseconds{100});
    }

    std::cout << "Max E2E latency (us) = " << BenchmarkTimer::maxTime(times) << std::endl;
    std::cout << "Min E2E latency (us) = " << BenchmarkTimer::minTime(times) << std::endl;
    std::cout << "Avg E2E latency (us) = " << BenchmarkTimer::avgTime(times) << std::endl;
    std::cout << "Median E2E latency (us) = " << BenchmarkTimer::medianTime(times) << std::endl;

    // std::cout << "sent scatter request" << std::endl;

    // Wait on the ctrl socket to finish
    // sg_msg_t buf;
    // auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    // assert(b == sizeof(sg_msg_t));
    // assert(buf.hdr.req_id == req->id());

    // service.processEvents();
    
    // auto aggregatedData = (uint32_t*)(buf.body);
    // std::cout << "control socket packet received\n";
    // for (auto i = 0u; i < RESP_MAX_VECTOR_SIZE; i++) {
    //     if (i % 25 == 0)
    //         std::cout << "vec[" << i << "] = " << aggregatedData[i] << std::endl;
    // }

    // std::cout << "Got a total of " << req->bufferPointers().size() << std::endl;

    // service.freeRequest(req, true);
}
