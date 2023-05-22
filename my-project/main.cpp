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
        for(auto i = 0; i < times.size(); ++i) {
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

int main(int argc, char** argv) {

    if (argc < 3) {
        std::cerr << "Invalid usage. Correct usage: " << argv[0] << " <path/to/bpfobjs> <ifname>" << std::endl;
        return 1;
    }

    int reqs = atoi(argv[3]);

    // sudo ./sg_program bpfobjs lo
    // export OUTPUT_BPF_OBJ_DIR=$(pwd)/bpfobjs

    // Standard method (BPF program)
    // export CUSTOM_AGGREGATION_BPF_PROG=$(pwd)/custom_aggregation.bpf.c
    // Using make --directory=../sgbpf bpf
    sgbpf::Context ctx{argv[1], argv[2]};

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    sgbpf::Service service{ctx, workers, sgbpf::PacketAction::Discard};
    
    // int flags = fcntl(sg.ctrlSkFd(), F_GETFL, 0);
    // fcntl(service.ctrlSkFd(), F_SETFL, flags | O_NONBLOCK);

    // EXAMPLE 1: Vector-based data (with in-kernel aggregation)
    sgbpf::ReqParams params; // set params here....
    params.completionPolicy = sgbpf::GatherCompletionPolicy::WaitAll;
    params.numWorkersToWait = 20;
    params.timeout = std::chrono::microseconds{100*1000}; // 10 ms

    
    // io_uring ring;
    // io_uring_params ringParams;
    // memset(&ringParams, 0, sizeof(ringParams));

    // if (io_uring_queue_init_params(1024, &ring, &ringParams) < 0)
    //     throw std::runtime_error{"Failed to initialise io_uring queue"};

    // // Preallocate and register buffers to receive the packets in
    // char* buffer = new char[reqs * sizeof(sg_msg_t)];

    // io_uring_sqe* sqe = io_uring_get_sqe(&ring);
    // io_uring_prep_provide_buffers(sqe, buffer, sizeof(sg_msg_t), reqs, 0, 0);
    // io_uring_submit(&ring);
    // io_uring_cqe* cqe;
    // io_uring_wait_cqe(&ring, &cqe);
    // if (cqe->res < 0)
    //     throw std::runtime_error{"Failed to provide io_uring buffers to the kernel"};
    // io_uring_cqe_seen(&ring, cqe);
    
    sg_msg_t buf;
    std::vector<uint64_t> times;
    times.reserve(reqs);
    // auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < reqs; i++) {
        BenchmarkTimer t{times};
        // sqe = io_uring_get_sqe(&ring);
        // io_uring_prep_recv(sqe, service.ctrlSkFd(), NULL, sizeof(sg_msg_t), 0);
        // io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
        // sqe->buf_group = 0;
        // sqe->user_data = 123;

        auto req = service.scatter("SCATTER", 8);
        // io_uring_submit(&ring);

        // unsigned count = 0;
        // unsigned head;
        // io_uring_for_each_cqe(&ring, head, cqe) {
        //     ++count;
        //     if (cqe->user_data == 123) {
        //         auto bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        //         auto resp = (sg_msg_t*) (buffer + bid * sizeof(sg_msg_t));
        //         assert(resp->hdr.req_id == req->id()); // not guaranteed to be in order
        //         // assert(((uint32_t*)resp->body)[10] == workers.size() * 10);
        //         reqIDs.push_back(resp->hdr.req_id);
        //     }
        // }
        // io_uring_cq_advance(&ring, count);

        auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
        assert(b == sizeof(sg_msg_t));

        service.processEvents(req->id());
    }

    std::cout << "Avg unloaded latency: " << BenchmarkTimer::avgTime(times) << " us\n";
    std::cout << "Median unloaded latency: " << BenchmarkTimer::medianTime(times) << " us\n";
    std::cout << "Std dev unloaded latency: " << BenchmarkTimer::stdDev(times) << " us\n";

    // auto end_time = std::chrono::high_resolution_clock::now();
    // auto elapsed_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start);
    // std::cout << "Total time = " << elapsed_time.count() << " us - " 
    //             << "Num requests = " << reqs 
    //             << " , Num Workers = " << workers.size() 
    //             << std::endl;

    // // this is not guaranteed... need to wait for all to arrive
    // uint32_t sum = 0;
    // uint32_t expected = reqs * (reqs + 1) / 2;
    // for (auto id : reqIDs)
    //     sum += id;

    // std::cout << sum << " " << expected << std::endl;
    // assert(sum == expected);

    // buf size (8192) = 187886 us
    // buf size (1024) = 57917 us

    // std::cout << "Avg throughput (req/s) = " << reqs / (std::chrono::duration_cast<std::chrono::seconds>(elapsed_time).count()) << std::endl;

    // while (1) {
    //     std::this_thread::yield();
    // }

    // std::cout << "Max E2E latency (us) = " << BenchmarkTimer::maxTime(times) << std::endl;
    // std::cout << "Min E2E latency (us) = " << BenchmarkTimer::minTime(times) << std::endl;
    // std::cout << "Avg E2E latency (us) = " << BenchmarkTimer::avgTime(times) << std::endl;
    // std::cout << "Median E2E latency (us) = " << BenchmarkTimer::medianTime(times) << std::endl;

    // WAIT ALL WORKS PERFECTLY FINE
    // MUST BE RELATED TO THE DROPPED PACKETS IN WAIT_N ??
    // also not UDP reliability issues because setting WAIT N = all - 1 still fails
    // IF WE DON'T DROP REDUNDANT PACKETS (LINE 368 IN EBPF), WE CAN JUST IGNORE THEM IN USERSPACE
    // still seems to be a bug...
    // idek, goes on streaks where it works, sometimes randomly gives num pk mismatch??
    // can we just assume reliability isn't perfect??

    // WHEN SENDING MANY REQUESTS, AT SOME POINT IT LOOKS LIKE THEY GET STUCK
    // AROUND REQ 427.
    // looks like workers ARE NOT sending data back? maybe they crashed?

    // todo send requests, do not expect reply

    // std::cout << "sent scatter request" << std::endl;
    // for (auto i = 0u; i < 3; i++) {
    //     auto req = service.scatter("SCATTER", 8, params);

    //     sg_msg_t buf;
    //     auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    //     assert(b == sizeof(sg_msg_t));
    //     assert(buf.hdr.req_id == req->id());

    //     // while (req->bufferPointers().size() != params.numWorkersToWait)
    //     service.processEvents();
        
    //     auto aggregatedData = (uint32_t*)(buf.body);
    //     // std::cout << "control socket packet received\n";
    //     for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
    //         bool c = aggregatedData[j] == j * params.numWorkersToWait;
    //         if(!c) {
    //             std::cout << "DATA MISMATCH on REQ " << i << " - Got " << aggregatedData[j] << " at idx " << j << " instead of " << j * params.numWorkersToWait << std::endl;
    //             throw;
    //         }
    //         std::cout << "vec[" << j << "] = " << aggregatedData[j] << std::endl;
    //     }
    //     bool c = req->bufferPointers().size() == params.numWorkersToWait;
    //     if(!c) {
    //         std::cout << "NUM PKS MISMATCH on REQ " << i << " - Got " << req->bufferPointers().size() << " instead of " << params.numWorkersToWait << std::endl;
    //         throw;
    //     }
    //     // service.freeRequest(req);
    // }
    
}
