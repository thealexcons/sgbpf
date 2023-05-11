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

#include "Common.h"
#include "maps.bpf.h"

#define MOD_POW2(x, y) (x & (y - 1))
#define GET_REQ_MAP_SLOT(req_id) MOD_POW2(req_id, MAX_ACTIVE_REQUESTS_ALLOWED)
// #define ATOMIC_LOAD_S64(ptr, dest) asm volatile("lock *(i64 *)(%0+0) += %1" : "=r"(dest) : "r"(ZERO_IDX), "0"(ptr));

#define UNLIKELY(cond) __builtin_expect ((cond), 0)
#define LIKELY(cond) __builtin_expect ((cond), 1)

#define CHECK_MAP_LOOKUP(ptr, ret) \
    if (UNLIKELY(!ptr)) \
        return ret;

static inline enum xdp_action parse_msg_xdp(struct xdp_md* ctx, sg_msg_t** msg) {
    void* data = (void *)(long)ctx->data;
    void* data_end = (void *)(long)ctx->data_end;
    struct ethhdr* ethh;
    struct iphdr* iph;
    struct udphdr* udph;
    
    ethh = (struct ethhdr*)data;
    if (UNLIKELY( (void *)(ethh + 1) > data_end || ethh->h_proto != bpf_htons(ETH_P_IP) ))
        return XDP_DROP;
    
    iph = (struct iphdr *)(ethh + 1);
    if (UNLIKELY( (void *)(iph + 1) > data_end || iph->protocol != IPPROTO_UDP ))
        return XDP_DROP;
    
    udph = (struct udphdr*)(iph + 1);
    if (UNLIKELY( (void *)(udph + 1) > data_end ))
        return XDP_DROP;
    
    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    char* payload = (char*) udph + sizeof(struct udphdr);
    if (UNLIKELY( payload_size != sizeof(sg_msg_t) || (void*) payload + payload_size > data_end ))
        return XDP_DROP;

    *msg = (sg_msg_t*) payload;
    return XDP_PASS;
}

static __always_inline enum xdp_action post_aggregation_process(struct xdp_md* ctx, sg_msg_t* resp_msg) {
    // Set the flag in the payload for the upper layer programs
    resp_msg->hdr.flags = SG_MSG_F_PROCESSED;
    __u32* pk_count = (void*)(unsigned long) ctx->data_meta;
    if (pk_count + 1 > (void*)(unsigned long) ctx->data) {
        return XDP_ABORTED; \
    }
    bpf_printk("done aggregation with pk %d", *pk_count);
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
    CHECK_MAP_LOOKUP(agg_entry, XDP_ABORTED); \
    ctx.current_value = agg_entry->data; \
    ctx.lock = &agg_entry->lock; \
    __u32* pk_count = (void*)(unsigned long) xdp_ctx->data_meta; \
    if (pk_count + 1 > (void*)(unsigned long) xdp_ctx->data) { \
        return XDP_ABORTED; \
    } \
    bpf_printk("starting aggregation with pk %d", *pk_count); \
    bpf_spin_lock(ctx.lock); \
}

#define AGGREGATION_PROG_OUTRO(ctx) { \
    bpf_spin_unlock(ctx.lock); \
    int act; \
    if ((act = post_aggregation_process(ctx.xdp_ctx, ctx.pk_msg)) != XDP_PASS) \
        return act; \
    return XDP_PASS; \
}


struct timer {
    const char* name;
    __u64       start_ns;
};
#define START_TIMER(prog_name) \
    struct timer __START_TIMER_timer; \
    __START_TIMER_timer.name = prog_name; \
    __START_TIMER_timer.start_ns = bpf_ktime_get_ns();

#define END_TIMER() { \
    __u64 time_ns = bpf_ktime_get_ns() - __START_TIMER_timer.start_ns; \
    bpf_printk("Elapsed time for '%s': %d ns (%d us)", __START_TIMER_timer.name, time_ns, time_ns / 1000); \
}

#endif // HELPERS_BPF_H
