#include "bpf_h/helpers.bpf.h"


SEC("xdp")
int aggregation_prog(struct xdp_md* xdp_ctx) {
    struct aggregation_prog_ctx ctx;
    AGGREGATION_PROG_INTRO(ctx, xdp_ctx);

    AGGREGATION_PROG_ACQUIRE_LOCK(ctx); 

    // perform aggregation logic here...
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        ctx.current_value[i] += ((RESP_VECTOR_TYPE*)ctx.pk_msg->body)[i];
    }
    AGGREGATION_PROG_RELEASE_LOCK(ctx); 

    AGGREGATION_PROG_OUTRO(ctx, DISCARD_PK);
}

    // ITEM LIST (IN ORDER OF PRIORITY):

    // LOOK INTO PER SOCKET STORAGE FOR THE FUTURE WORK SECTION

    //  5. start thinking about evaluation (see below)

    // Research socket layer programs and their capabilities
    // redirection, per-socket storage, etc. to see if this system could be
    // replicated in TCP. Preliminary work under "future work" section in report 

    // key metrics: 
    //      1- throughput (number of requests per second) 
    //      2- latency (average time to complete a request)
    // macro benchmark: end-to-end application
    //      find an example use case and build a naive baseline, and one using the SG library
    //      measure key metrics
    // micro benchmark: 
    //      num syscalls (via strace) 
    //      kernel-user crossings (num ctx switches proxy?) 
    //          https://stackoverflow.com/questions/21777430/what-does-high-involuntary-context-switches-mean
    //      num copies (to investigate) 
    //      cpu usage
    //      individual components of the system 
    //          (measure per-request latency of each BPF program, profile and find hotspots)
    //  look at FPGA paper for evaluation metrics

    // ================== THIS WEEK ======================
    // [1] profile and figure out the latency bottleneck with the num buffers for io_uring
    //  two options:
    //      - allow users to specify num buffers themselves
    //      - use a global pre-allocated buffer like in previous design
    //
    //  https://elixir.bootlin.com/linux/latest/source/io_uring/kbuf.c#L422
    //  io_uring internally iterates over the number of buffers: io_add_buffers
    //
    //  not only that, but for a large number of packets, this is restricted by the stack size
    //  therefore, this constrains the performance of the scatter() invocation to O(n)
    //  Hence, the best option is to allocate a large pool of memory dedicated to packet buffers
    //  ahead of time and use ptrs/offsets to divide this block into per-request regions
    //  this is another implementation detail that should be mentioned in the report, as it
    //  depends the automatic buffer selection mechanism. mention both designs, and why this one 
    //  is preferred for performance

    // [2] measure unloaded (single-request) latency and throughput for different setups (locally)
    //     this is all done locally, just to explain the difference in performance
    //        early dropping vs userspace aggregation for example
    //        fan-out impact

    // [3] implement different dummy baselines using IO mechanisms
    //      naive blocking read/write
    //      epoll
    //      io_uring syscall batching
    //
    //      here the point is not only to measure latency/throughput, but also
    //      to focus on the mechanical differences in terms of syscalls, copies,
    //      ctx switches, etc.



char LICENSE[] SEC("license") = "GPL";
