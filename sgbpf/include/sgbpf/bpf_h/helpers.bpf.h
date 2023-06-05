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
#define UNLIKELY(cond) __builtin_expect ((cond), 0)
#define LIKELY(cond) __builtin_expect ((cond), 1)

#define CHECK_MAP_LOOKUP(ptr, ret) \
    if (UNLIKELY(!ptr)) \
        return ret;

#define ALLOW_PK 0      // Allow the individual packet through to user-space
#define DISCARD_PK 1    // Discard the individual packet after aggregation

static __always_inline void clear_vector(RESP_VECTOR_TYPE* agg_vector) {
    // ebpf sets a maximum size for memset, so we need to "hack" around it
    #define MAX_CONTIGUOUS_MEMSET_SIZE 256

    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        if (UNLIKELY( MOD_POW2(i, MAX_CONTIGUOUS_MEMSET_SIZE) == 0 )) {
            asm volatile("" ::: "memory"); // dummy instruction needed to break the memset, need something cheap
        }
        agg_vector[i] = 0;
    }
}

static __always_inline __s32 write_data_to_ringbuf(__u32 req_id, RESP_VECTOR_TYPE* current_value) {
    sg_msg_t* rb_data = bpf_ringbuf_reserve(&map_ctrl_sk_ringbuf, sizeof(sg_msg_t), 0);
    if (!rb_data)
        return -1;
    
    // copy the request ID and the aggregated data into the ring buffer
    rb_data->hdr.req_id = req_id;
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        ((RESP_VECTOR_TYPE*) rb_data->body)[i] = current_value[i];
    }

    bpf_ringbuf_submit(rb_data, 0);
    return 0;
}

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

static __always_inline enum xdp_action post_aggregation_process(struct xdp_md* ctx, sg_msg_t* resp_msg, RESP_VECTOR_TYPE* current_value, __u8 action) {
    // Set the flag in the payload for the upper layer programs
    resp_msg->hdr.flags = SG_MSG_F_PROCESSED;
    
    __u32 slot = GET_REQ_MAP_SLOT(resp_msg->hdr.req_id);
    
    struct req_state* rs = bpf_map_lookup_elem(&map_req_state, &slot);
    CHECK_MAP_LOOKUP(rs, XDP_ABORTED);
    __sync_add_and_fetch(&rs->post_agg_count, 1);

    #ifdef DEBUG_PRINT
    bpf_printk("Finished aggregation, SET pk count to %d", *pk_count);
    #endif

    // If ALLOW_PK, all packets should be passed through to userspace
    if (action == ALLOW_PK)
        return XDP_PASS;

    // If DISCARD_PK, all packets except the last one should be dropped
    if (__sync_val_compare_and_swap(&rs->post_agg_count, rs->num_workers, -1) == rs->num_workers) {
        // This is the final packet. If the ringbuf is enabled and all-gather is disabled, we can
        // deliver the aggregated value from here and avoid going to the TC layer (bypass skb alloc)
        const __u32 zero = 0;
        struct ctrl_sk_info* ctrl_sk = bpf_map_lookup_elem(&map_gather_ctrl_port, &zero);
        CHECK_MAP_LOOKUP(ctrl_sk, XDP_DROP);

        if (ctrl_sk->use_ring_buf && !ctrl_sk->all_gather) {
            if (write_data_to_ringbuf(resp_msg->hdr.req_id, current_value) == -1)
                return XDP_PASS; // If failed, retry in TC layer
            clear_vector(current_value);
            return XDP_DROP;
        }
        // Proceed to notify_prog with the final packet
        return XDP_PASS;
    }
    return XDP_DROP;
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
    struct aggregation_entry* agg_entry = bpf_map_lookup_elem(&map_aggregated_response, &slot); \
    CHECK_MAP_LOOKUP(agg_entry, XDP_ABORTED); \
    ctx.current_value = agg_entry->data; \
    ctx.lock = &agg_entry->lock; \
    bpf_spin_lock(ctx.lock); \
}

#define AGGREGATION_PROG_OUTRO(ctx, pk_action) { \
    bpf_spin_unlock(ctx.lock); \
    return post_aggregation_process(ctx.xdp_ctx, ctx.pk_msg, ctx.current_value, pk_action); \
}


// bpf_ktime_get_ns() roughly takes 30-40 ns
struct timer {
    const char* name;
    __u64       start_ns;
};
#define START_TIMER(prog_name) \
    struct timer __START_TIMER_timer; \
    __START_TIMER_timer.name = prog_name; \
    __START_TIMER_timer.start_ns = bpf_ktime_get_ns();

#define MEASURE_ELAPSED_TIME(checkpoint_name) { \
    __u64 time_ns = bpf_ktime_get_ns() - __START_TIMER_timer.start_ns; \
    bpf_printk("Elapsed time for '_%s': %d ns (%d us)", checkpoint_name, time_ns, time_ns / 1000); \
}

#endif // HELPERS_BPF_H
