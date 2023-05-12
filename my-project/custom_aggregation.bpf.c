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

    AGGREGATION_PROG_OUTRO(ctx);
}

    // ITEM LIST (IN ORDER OF PRIORITY):

    // FIX MISSING PACKETS FOR N < WORKERS.SIZE()
    // IO_URING DOES NOT SEEM TO BE GETTING ALL THE PACKETS FROM EBPF???

    // LOOK INTO PER SOCKET STORAGE FOR THE FUTURE WORK SECTION

    // bpf prog: (note these have ASan on, can't get rid of it)
    // Max E2E latency (us) = 2591
    // Min E2E latency (us) = 1357
    // Avg E2E latency (us) = 1732.93
    // Median E2E latency (us) = 1681
    // regular func:
    // Max E2E latency (us) = 2911
    // Min E2E latency (us) = 1358
    // Avg E2E latency (us) = 1693.11
    // Median E2E latency (us) = 1629
    // very similar measurements. is this because of ASan?

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


char LICENSE[] SEC("license") = "GPL";
