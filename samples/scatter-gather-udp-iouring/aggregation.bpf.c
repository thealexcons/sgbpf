#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <netinet/in.h>

#include "common.h"
#include "maps.bpf.h"

SEC("xdp")
int aggregation_prog(struct xdp_md* ctx) {
    static const __u32 ZERO_IDX = 0;

    // this is always zero....
    char* body_data = bpf_map_lookup_elem(&map_body_data, &ZERO_IDX);
    if (!body_data)
        return XDP_ABORTED;

    bpf_printk("body_Data[33] = %d", ((RESP_VECTOR_TYPE *)body_data)[33]);

    RESP_VECTOR_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
    if (!agg_resp)
        return XDP_ABORTED;

    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        agg_resp[i] += ((RESP_VECTOR_TYPE*)body_data)[i];
        // bpf_printk("body_data[%d] = %d", i, ((RESP_VECTOR_TYPE*)body_data)[i]);
    }

    bpf_printk("custom aggregation function done");

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";