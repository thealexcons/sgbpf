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

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	/* Ignore debug-level libbpf logs */
	if (level > LIBBPF_WARN)
		return 0;
	return vfprintf(stderr, format, args);
}

int main(int argc, char** argv) {

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <path/to/bpfobjs> <ifname>" << std::endl;
        return 1;
    }

    // start with ctrl sk io_uring support
    // test and benchmark compared with read()

    // IS EPOLL ON CTRL SK WORTH IT?? maybe if we get multiple notifs then yes...
    // then move onto epoll via ringbuf
    // test and benchmark compared with read()


    // sudo ./sg_program bpfobjs lo
    // export OUTPUT_BPF_OBJ_DIR=$(pwd)/bpfobjs

    // Standard method (BPF program)
    // export CUSTOM_AGGREGATION_BPF_PROG=$(pwd)/custom_aggregation.bpf.c
    // Using make --directory=../sgbpf bpf
    sgbpf::Context ctx{argv[1], argv[2]};

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    sgbpf::Service service{
        ctx, 
        workers, 
        sgbpf::PacketAction::Discard,   // We only care about the aggregated data
        sgbpf::CtrlSockMode::Block    // Causes scatter() to block on the ctrl sk
    };

    // int flags = fcntl(sg.ctrlSkFd(), F_GETFL, 0);
    // fcntl(service.ctrlSkFd(), F_SETFL, flags | O_NONBLOCK);

    // EXAMPLE 1: Vector-based data (with in-kernel aggregation)
    sgbpf::ReqParams params; // set params here....
    params.completionPolicy = sgbpf::GatherCompletionPolicy::WaitAll;
    params.numWorkersToWait = workers.size();
    params.timeout = std::chrono::microseconds{50000 * 100};

    // sg_msg_t buf;
    // auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    // assert(b == sizeof(sg_msg_t));

    auto req = service.scatter("SCATTER", 8, params);

    service.processEvents(req->id());
    assert(req->isReady());
    auto buf = req->ctrlSockData();
    
    for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
        std::cout << "vec[" << j << "] = " << ((uint32_t*) buf->body)[j] << std::endl;
        assert(((uint32_t*) buf->body)[j] == workers.size() * j);
    }
    
    // std::cout << "\n\n";
    // for (auto [wfd, ptrs] : req->bufferPointers()) {
    //     std::cout << "Worker " << wfd  << std::endl;
    //     for (auto ptr : ptrs) {
    //         auto r = (sg_msg_t*) req->data(ptr);
    //         std::cout << "  " << ((uint32_t*)r->body)[10] << std::endl;
    //     }
    // }

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
