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

    // TODO: Unify aggregation types for VECTOR and SCALAR data (in common.h)
    //  4. consider ebpf prog vs regular func call for custom aggregation logic
    //      in terms of performance, ease of use, etc.

    //  TIME OUT MECHANISM: measure in userspace, if timed out, make syscall to
    //      cleanup state in the ebpf program (unoptimised path)
    //  this is essentially done, except the time out cleanup

    // FIX RACE CONDITION FOR COUNT ATOMICS

    // two options:
    //   things to cleanup: reset aggregated value, count, 
    //  eager cleanup: cleanup required map state once the request finishes
    //      // probably faster, as it avoids duplicate map lookups
    //      // but requires user invocation to cleanup timed out requess
    //      // Preferred? since we can assume timed out requests are not part
    //         of the optimised path.
    //  lazy cleanup: cleanup required map state of previous entry on scatter send
    //      // probably slower on scatter send
    //      // but cleanup is essentially automatic

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
