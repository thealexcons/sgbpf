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
    sg_msg_t* resp_msg;
    RESP_VECTOR_TYPE* current_aggregated_value;
    AGGREGATION_PROG_INTRO(resp_msg, current_aggregated_value);

    // perform aggregation logic here...
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        current_aggregated_value[i] += ((RESP_VECTOR_TYPE*)resp_msg->body)[i];
    }

    AGGREGATION_PROG_OUTRO(resp_msg);
}

    // ITEM LIST (IN ORDER OF PRIORITY):

    // need to discuss event loop in separate thread... if we are using multiple threads
    // it might even be worth looking into the io_uring kernel thread to make zero syscalls

    //  2. fix the worker count being updated from the custom aggregation func
    //      No idea what the problem is... very weird
    //  3. thread-safety in maps and per-request separation of state
    //      Need to get ARRAY_OF_MAPS to work for this
    //  4. Atomics for worker count instead of spin lock
    //      LLVM fails when compiling the compare_and_swap operation
    //  https://www.ibm.com/docs/en/xl-c-aix/13.1.0?topic=functions-sync-bool-compare-swap
    //  6. timeout mechanism? or completion policy!!  IN EBPF CODE, not userspace
    //      see comment in isExpired() in ScatterGatherRequest class
    //  5. start thinking about evaluation (see below)

    // key metrics: 
    //      1- throughput (number of requests per second) 
    //      2- latency (average time to complete a request)
    // macro benchmark: end-to-end application
    //      find an example use case and build a naive baseline, and one using the SG library
    //      measure key metrics
    // micro benchmark: 
    //      num syscalls (via strace) 
    //      kernel-user crossings (num ctx switches proxy?) 
    //      num copies (to investigate) 
    //      cpu usage
    //      individual components of the system 
    //          (measure per-request latency of each BPF program, profile and find hotspots)

char LICENSE[] SEC("license") = "GPL";