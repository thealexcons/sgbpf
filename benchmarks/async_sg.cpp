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
#include <sys/mman.h>
#include "common.h"
#include <stack>
#include <memory>
#include <list>

template <size_t BlockSize, size_t ReservedBlocks = 0>
class Pool {
private:
    size_t size_;
    std::stack<void *> addrs_;
    std::stack<std::unique_ptr<uint8_t[]>> blocks_;

public:
    explicit Pool(size_t size) : size_(size) {
        for (size_t i = 0; i < ReservedBlocks; i++) {
            add_more_addresses();
        }
    }

    void* allocate() {
        if (addrs_.empty()) {
            add_more_addresses();
        }

        auto ptr = addrs_.top();
        addrs_.pop();
        return ptr;
    }

    void deallocate(void *ptr) {
        addrs_.push(ptr);
    }

    /* Rebind should only be called by STL containers when they need to create
       an allocator for an internal node-like structure from the value_type allocator.
       This means that the original allocator must not have been used yet, so we
       are free to reassign the size_ field safely. */
    void rebind(size_t size) {
        if (!(addrs_.empty() && blocks_.empty())) {
            std::cerr << "Cannot call Pool::rebind() after an allocation\n";
            abort();
        }

        size_ = size;
    }

private:
    // Refill the address stack by allocating another block of memory
    void add_more_addresses() {
        auto block = std::make_unique<uint8_t[]>(BlockSize);
        auto total_size = BlockSize % size_ == 0 ? BlockSize : BlockSize - size_;

        // Divide the allocated block into chunks of size_ bytes, and add their address
        for (size_t i = 0; i < total_size; i += size_) {
            addrs_.push(&block.get()[i]);
        }

        // Keep the memory of the block alive by adding it to our stack
        blocks_.push(std::move(block));
    }
};

template <typename T, size_t BlockSize = 4096, size_t ReservedBlocks = 0>
class PoolAllocator {
private:
    using PoolType = Pool<BlockSize, ReservedBlocks>;
    std::shared_ptr<PoolType> pool_;

public:
    using value_type = T;
    using is_always_equal = std::false_type;

    PoolAllocator() : pool_(std::make_shared<PoolType>(sizeof(T))) {}

    // Rebind copy constructor
    template <typename U>
    PoolAllocator(const PoolAllocator<U>& other) : pool_{other.pool_} {
        pool_->rebind(sizeof(T));
    }

    template <typename U>
    struct rebind {
        using other = PoolAllocator<U, BlockSize, ReservedBlocks>;
    };

    PoolAllocator(const PoolAllocator& other) = default;
    PoolAllocator(PoolAllocator&& other) = default;
    PoolAllocator& operator=(const PoolAllocator& other) = default;
    PoolAllocator& operator=(PoolAllocator&& other) = default;

    T* allocate(size_t n) {
        if (n > 1) {
            // For n > 1, resort to using malloc
            return static_cast<T*>(malloc(sizeof(T) * n));
        }

        return static_cast<T*>(pool_->allocate());
    }

    void deallocate(T* ptr, size_t n) {
        if (n > 1) {
            free(ptr);
            return;
        }

        pool_->deallocate(ptr);
    }
};





class ScatterGatherService {

    typedef struct __attribute__((packed)) conn_info  {
        int      fd;
        uint16_t type;
        uint16_t bgid;
    } conn_info_t;

    std::vector<Worker>&       d_workers;
    uint32_t                   d_nextRequest = 0;
    io_uring                   d_ring;
    msghdr*                    d_msgHdrs;
    uint16_t                   d_bgid = 42;
    // char*                      d_buffers;
    int                        d_skFd;
    size_t                     d_numSkReads;
    std::vector<char*>         d_packetBufferPool;
    constexpr static const int NUM_BUFFERS = std::numeric_limits<uint16_t>::max(); // for fair comparison with sgbpf
    PoolAllocator<char, NUM_BUFFERS*sizeof(sg_msg_t)> d_poolAllocator;

    constexpr static uint16_t READ_OP = 0x12;

public:
    ScatterGatherService(std::vector<Worker>& workers)
        : d_workers{workers}
        , d_numSkReads{0}
    {
        std::cout << "Workers loaded: " << workers.size() << std::endl;
        increaseMaxNumFiles();

        d_skFd = socket(AF_INET, SOCK_DGRAM, 0);

        d_msgHdrs = new msghdr[d_workers.size()];

        // Setup io uring
        io_uring_params params;
        memset(&params, 0, sizeof(params));

        if (io_uring_queue_init_params(d_workers.size() * 3, &d_ring, &params) < 0)
            throw std::runtime_error{"Failed to initialise io_uring queue"};

        // Preallocate and register buffers to receive the packets in
        provideBuffers(true);
    }

    uint16_t provideBuffers(bool immediate = false) {
        // Register packet buffers for buffer selection
        #ifdef HUGE_PAGE_ALLOCATOR
            void* buffer = nullptr;
            auto alloc_size = NUM_BUFFERS * sizeof(sg_msg_t);
            if (posix_memalign(&buffer, 1 << 21, alloc_size) != 0) {
                throw std::bad_alloc();
            }
            
            madvise(buffer, alloc_size, MADV_HUGEPAGE);
            if (buffer == nullptr) {
                throw std::bad_alloc();
            }
        #else
            char* buffer  = new char[NUM_BUFFERS * sizeof(sg_msg_t)];
        #endif
        d_packetBufferPool.push_back(static_cast<char*>(buffer));

        // std::cout << "[DEBUG] Providing buffers to the kernel (new bgid = "
        //         << d_packetBufferPool.size() - 1 << ") num reads = " << d_numSkReads << std::endl;

        auto bgid = d_packetBufferPool.size() - 1;  // the idx of the buffer in the pool
        io_uring_sqe* sqe = io_uring_get_sqe(&d_ring);
        io_uring_prep_provide_buffers(sqe, buffer, sizeof(sg_msg_t), NUM_BUFFERS, bgid, 0);

        if (immediate) {
            io_uring_submit(&d_ring);
            io_uring_cqe* cqe;
            io_uring_wait_cqe(&d_ring, &cqe);
            if (cqe->res < 0)
                throw std::runtime_error{"Failed to provide io_uring buffers to the kernel"};
            io_uring_cqe_seen(&d_ring, cqe);
        }
        return bgid;
    }

    ~ScatterGatherService() {
        delete[] d_msgHdrs;
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

        uint16_t bgid = d_packetBufferPool.size() - 1; // use the most recent bgid
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
            if (d_numSkReads == NUM_BUFFERS) {
                bgid = provideBuffers();
                d_numSkReads = 0;
            }
            d_numSkReads++;
            sqe = io_uring_get_sqe(&d_ring);
            io_uring_prep_recv(sqe, worker.socketFd(), NULL, sizeof(sg_msg_t), 0);
            io_uring_sqe_set_flags(sqe, IOSQE_BUFFER_SELECT);
            sqe->buf_group = bgid;
            conn_info_t conn_i = {
                .fd = worker.socketFd(),
                .type = READ_OP,
                .bgid = bgid,
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
                    auto bgid = conn_i->bgid;
                    auto bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
                    auto resp = (sg_msg_t*) (d_packetBufferPool[bgid] + bid * sizeof(sg_msg_t));

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
