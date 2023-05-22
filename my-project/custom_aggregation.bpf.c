#include "bpf_h/helpers.bpf.h"


SEC("xdp")
int aggregation_prog(struct xdp_md* xdp_ctx) {
    struct aggregation_prog_ctx ctx;
    AGGREGATION_PROG_INTRO(ctx, xdp_ctx);

    // Note any logic added here takes place under a spinlock
    // hence you must follow the eBPF rules (eg: no function calls)
    
    // if this is a bottleneck (restricts parallelism), may need to consider
    // per-cpu maps and do the final aggregation at the end
    // but this may complicate the design because it requires invoking the aggregation
    // logic twice...

    // perform aggregation logic here...
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        ctx.current_value[i] += ((RESP_VECTOR_TYPE*)ctx.pk_msg->body)[i];
    }

    AGGREGATION_PROG_OUTRO(ctx, DISCARD_PK);
}

    // ITEM LIST (IN ORDER OF PRIORITY):

    // LOOK INTO PER SOCKET STORAGE FOR THE FUTURE WORK SECTION

    // TODO: Unify aggregation types for VECTOR and SCALAR data (in common.h)
    // fsanitize issue

    // important design choice (in the evaluation):
    //   scattering in TC
    //   scattering in user space (with io_uring)
    //  Num syscalls is same in both, but what about number of memcpys?
    //  Evaluate throughput (req/s)

    // have option to early drop individual packets after aggregation

    //  5. start thinking about evaluation (see below)

    // Research socket layer programs and their capabilities
    // redirection, per-socket storage, etc. to see if this system could be
    // replicated in TCP. Preliminary work under "future work" section in report 

    // week after:
    // multi-packet vector aggregation could be done using sequence numbers


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
