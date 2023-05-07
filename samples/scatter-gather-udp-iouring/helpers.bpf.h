#ifndef HELPERS_BPF_H
#define HELPERS_BPF_H

#pragma clang diagnostic ignored "-Wcompare-distinct-pointer-types"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "maps.bpf.h"

#define MOD_POW2(x, y) (x & (y - 1))
#define GET_REQ_MAP_SLOT(req_id) MOD_POW2(req_id, MAX_ACTIVE_REQUESTS_ALLOWED)
#define ATOMIC_LOAD_S64(ptr, dest) asm volatile("lock *(i64 *)(%0+0) += %1" : "=r"(dest) : "r"(ZERO_IDX), "0"(ptr));

static inline enum xdp_action parse_msg_xdp(struct xdp_md* ctx, sg_msg_t** msg) {
    void* data = (void *)(long)ctx->data;
    void* data_end = (void *)(long)ctx->data_end;
    struct ethhdr* ethh;
    struct iphdr* iph;
    struct udphdr* udph;
    
    ethh = (struct ethhdr*)data;
    if ((void *)(ethh + 1) > data_end)
        return XDP_DROP;
    if (ethh->h_proto != bpf_htons(ETH_P_IP))
        return XDP_DROP;
    
    iph = (struct iphdr *)(ethh + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_DROP;
    if (iph->protocol != IPPROTO_UDP)
        return XDP_DROP;
    
    udph = (struct udphdr*)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return XDP_DROP;
    
    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    if (payload_size != sizeof(sg_msg_t))
        return XDP_DROP;
    
    char* payload = (char*) udph + sizeof(struct udphdr);
    if ((void*) payload + payload_size > data_end)
        return XDP_DROP;

    *msg = (sg_msg_t*) payload;
    return XDP_PASS;
}

static inline enum xdp_action post_aggregation_process(struct xdp_md* ctx, sg_msg_t* resp_msg) {
    // Set the flag in the payload for the upper layer programs
    resp_msg->hdr.flags = SG_MSG_F_PROCESSED;

    // Increment received packet count for the request
    __u32 slot = GET_REQ_MAP_SLOT(resp_msg->hdr.req_id);

    #ifdef BPF_DEBUG_PRINT
    bpf_printk("Slot for request: %d", slot);
    #endif

    __s64* count = bpf_map_lookup_elem(&map_workers_resp_count, &slot);
    if (!count)
        return XDP_ABORTED;

    __s64 pk_count = __atomic_add_fetch(count, 1, __ATOMIC_ACQ_REL);

    // Device drivers not supporting data_meta will fail here
    if (bpf_xdp_adjust_meta(ctx, -(int) sizeof(__u32)) < 0)
        return XDP_ABORTED;

    void* data = (void*)(unsigned long) ctx->data;
    __u32* pk_count_meta;
    pk_count_meta = (void*)(unsigned long) ctx->data_meta;
    if (pk_count_meta + 1 > data)
        return XDP_ABORTED;

    *pk_count_meta = (__u32) pk_count;
    
    return XDP_PASS;
}

// A helper context structure for user-defined aggregation programs
struct aggregation_prog_ctx {
    sg_msg_t* pk_msg;                   // The incoming packet
    RESP_VECTOR_TYPE* current_value;    // The current aggregated value
    struct bpf_spin_lock* lock;         // Spinlock for synchronisation
    struct xdp_md* xdp_ctx;             // The XDP metadata context object
};

#define AGGREGATION_PROG_INTRO(ctx, xdp_ctx) { \
    ctx.xdp_ctx = xdp_ctx; \
    int act; \
    if ((act = parse_msg_xdp(xdp_ctx, &ctx.pk_msg)) != XDP_PASS) \
        return act; \
    __u32 slot = GET_REQ_MAP_SLOT(ctx.pk_msg->hdr.req_id); \
    /* static __u32 ZERO_IDX = 0;*/ \
    struct aggregation_entry* agg_entry = bpf_map_lookup_elem(&map_aggregated_response, &slot); \
    if (!agg_entry) \
        return XDP_ABORTED; \
    ctx.current_value = agg_entry->data; \
    ctx.lock = &agg_entry->lock; \
    bpf_spin_lock(ctx.lock); \
}

#define AGGREGATION_PROG_OUTRO(ctx) { \
    bpf_spin_unlock(ctx.lock); \
    int act; \
    if ((act = post_aggregation_process(ctx.xdp_ctx, ctx.pk_msg)) != XDP_PASS) \
        return act; \
    return XDP_PASS; \
}




#endif // HELPERS_BPF_H
