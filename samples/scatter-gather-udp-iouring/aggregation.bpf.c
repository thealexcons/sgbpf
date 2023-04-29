#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <netinet/in.h>

#include "common.h"
#include "maps.bpf.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

inline enum xdp_action INTRO(struct xdp_md* ctx, sg_msg_t* msg) {
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

    msg = (sg_msg_t*) payload;
    return XDP_PASS;
}


SEC("xdp")
int aggregation_prog(struct xdp_md* ctx) {

    // it seems like the contents get messed up when parsing it again.
    sg_msg_t* msg;
    int act;
    if ((act = INTRO(ctx, msg)) != XDP_PASS)
        return act;

    // 1. fix new version of code: individual worker sockets should be buffer selected
    //     ctrl socket should be outwards exposed
    // 3. intro and outro parsing macro to hide the parsing boilerplate code
    // 2. scatter gather array in the ctrl socket


    // macro benchmark: end-to-end application
    // micro benchmark: num syscalls, kernel-user crossings, num copies, cpu usage, individual components of the system
    // key metrics: throughput and latency

    static const __u32 ZERO_IDX = 0;

    // this is always zero....
    // char* body_data = bpf_map_lookup_elem(&map_body_data, &ZERO_IDX);
    // if (!body_data)
    //     return XDP_ABORTED;

    // bpf_printk("msg->hdr.req_id = %d", msg->hdr.req_id);
    // bpf_printk("body_Data[33] = %d", ((RESP_VECTOR_TYPE *)msg->body)[33]);

    RESP_VECTOR_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
    if (!agg_resp)
        return XDP_ABORTED;

    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        agg_resp[i] += ((RESP_VECTOR_TYPE*)msg->body)[i];
        // bpf_printk("body_data[%d] = %d", i, ((RESP_VECTOR_TYPE*)body_data)[i]);
    }

    bpf_printk("custom aggregation function done");

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";