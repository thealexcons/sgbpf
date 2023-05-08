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

char LICENSE[] SEC("license") = "GPL";
