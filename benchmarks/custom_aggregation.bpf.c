#include "bpf_h/helpers.bpf.h"


SEC("xdp")
int aggregation_prog(struct xdp_md* xdp_ctx) {
    struct aggregation_prog_ctx ctx;
    AGGREGATION_PROG_INTRO(ctx, xdp_ctx);
    
    AGGREGATION_PROG_ACQUIRE_LOCK(ctx);
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        ctx.current_value[i] += ((RESP_VECTOR_TYPE*) ctx.pk_msg->body)[i];
    }
    AGGREGATION_PROG_RELEASE_LOCK(ctx); 

    AGGREGATION_PROG_OUTRO(ctx, DISCARD_PK);
}

char LICENSE[] SEC("license") = "GPL";
