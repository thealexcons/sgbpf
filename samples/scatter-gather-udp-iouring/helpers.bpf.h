#ifndef HELPERS_BPF_H
#define HELPERS_BPF_H

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

static inline enum xdp_action post_aggregation_process(sg_msg_t* resp_msg) {
    // Increment received packet count for the request
    __u32 slot = MOD_POW2(resp_msg->hdr.req_id, MAX_ACTIVE_REQUESTS_ALLOWED);
    bpf_printk("Slot for request: %d", slot);

    // TODO something about this not working when called from custom aggregation program
    // maybe related to tail call issue...
    struct resp_count* rc = bpf_map_lookup_elem(&map_workers_resp_count, &slot);
    if (!rc)
        return XDP_ABORTED;

    bpf_spin_lock(&rc->lock);
    rc->count++;
    bpf_spin_unlock(&rc->lock);

    // Flag that this worker is completed
    // worker_resp_status_t updated_status = RECEIVED_RESPONSE; // cannot recycle pointers returned by map lookups!
    // bpf_map_update_elem(&map_workers_resp_status, &worker, &updated_status, 0);

    // Set the flag in the payload for the upper layer programs
    resp_msg->hdr.flags = SG_MSG_F_PROCESSED;
    bpf_printk("post aggregation function done");

    return XDP_PASS;
}

#define AGGREGATION_PROG_INTRO(resp_msg, agg_resp) { \
    int act; \
    if ((act = parse_msg_xdp(ctx, &resp_msg)) != XDP_PASS) \
        return act; \
    static __u32 ZERO_IDX = 0; \
    agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX); \
    if (!agg_resp) \
        return XDP_ABORTED; \
}

#define AGGREGATION_PROG_OUTRO(resp_msg) { \
    int act; \
    if ((act = post_aggregation_process(resp_msg)) != XDP_PASS) \
        return act; \
    return XDP_PASS; \
}

#endif // HELPERS_BPF_H
