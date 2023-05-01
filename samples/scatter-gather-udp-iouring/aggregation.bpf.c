#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <netinet/in.h>

#include "helpers.bpf.h"
#include "maps.bpf.h"

#include <linux/if_ether.h>
#include <linux/ip.h>


// if this program is placed in scatter_gather.bpf.c , it works
// correctly. might be due to being two different objects and the maps
// are instantiated separately??? may need to pin.
// alternative is to see discussion about making this a regular
// function call.

SEC("xdp")
int aggregation_prog(struct xdp_md* ctx) {
    return XDP_PASS;
    // sg_msg_t* resp_msg;
    // RESP_VECTOR_TYPE* current_aggregated_value;
    // AGGREGATION_PROG_INTRO(resp_msg, current_aggregated_value);

    // // perform aggregation logic here...
    // for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
    //     current_aggregated_value[i] += ((RESP_VECTOR_TYPE*)resp_msg->body)[i];
    // }

    // AGGREGATION_PROG_OUTRO(resp_msg);
}

    // ITEM LIST (IN ORDER OF PRIORITY):
    //  2. fix the worker count being updated from the custom aggregation func
    //  3. thread-safety in maps and per-request separation of state
    //  5. start thinking about evaluation (see below)

    // if time:
    //  6. timeout mechanism? or completion policy!!  IN EBPF CODE, not userspace

    // macro benchmark: end-to-end application
    // micro benchmark: num syscalls, kernel-user crossings, num copies, cpu usage, individual components of the system
    // key metrics: throughput and latency

char LICENSE[] SEC("license") = "GPL";