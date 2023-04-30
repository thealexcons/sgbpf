#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <netinet/in.h>

#include "helpers.bpf.h"
#include "maps.bpf.h"

#include <linux/if_ether.h>
#include <linux/ip.h>


SEC("xdp")
int aggregation_prog(struct xdp_md* ctx) {
    sg_msg_t* resp_msg;
    RESP_VECTOR_TYPE* current_aggregated_value;
    AGGREGATION_PROG_INTRO(resp_msg, current_aggregated_value);

    // perform aggregation logic here...
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        current_aggregated_value[i] += ((RESP_VECTOR_TYPE*)resp_msg->body)[i];
    }

    // bpf_printk("custom aggregation function done");
    AGGREGATION_PROG_OUTRO(resp_msg);
}

    // ITEM LIST (IN ORDER OF PRIORITY):
    //  3. support multiple requests in ebpf code
    //  5. start thinking about evaluation

    // if time:
    //  6. double free bug
    //  6. timeout mechanism? or completion policy!!  IN EBPF CODE, not userspace

    // macro benchmark: end-to-end application
    // micro benchmark: num syscalls, kernel-user crossings, num copies, cpu usage, individual components of the system
    // key metrics: throughput and latency

char LICENSE[] SEC("license") = "GPL";