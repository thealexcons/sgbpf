#ifndef MAPS_BPF_H
#define MAPS_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "Common.h"

// ---------------------- //
//       eBPF Maps        //
// ---------------------- //

// Stores the different parts of the aggregation logic for vector data
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, NUM_AGGREGATION_PROGS);
} map_aggregation_progs SEC(".maps");


// Stores the application outgoing port (for scattering)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, 1);
} map_application_port SEC(".maps");


// Stores the application control port (for gathering)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, 1);
} map_gather_ctrl_port SEC(".maps");


// Array of workers (used for egress scattering)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, worker_info_t);
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_workers SEC(".maps");


// Hash set of workers (used for ingress gathering)

// TODO can we avoid using HASH? ARRAY proven to be much faster? use req ID somehow?
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, worker_info_t);
    __type(value, worker_resp_status_t); // this should also be per request ID
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_workers_resp_status SEC(".maps");

// Stores the timing information about requests for handling time outs
// struct req_timing {
//     __u64 start_ns;
//     __u64 timeout_ns;
// };
// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __type(key, __u32);
//     __type(value, struct req_timing);
//     __uint(max_entries, MAX_ACTIVE_REQUESTS_ALLOWED);
// } map_req_timing SEC(".maps");


struct req_state {
    __s64                count;         // Num responses received
    struct bpf_spin_lock count_lock;    // Lock to R/W to count variable
    __u32                num_workers;   // Num workers to wait for completion
    sg_msg_flags_t       policy;        // Completion policy (NOT NEEDED)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct req_state);
    __uint(max_entries, MAX_ACTIVE_REQUESTS_ALLOWED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_req_state SEC(".maps");

// Stores the number of packets received for each request ID

// struct {
//     __uint(type, BPF_MAP_TYPE_ARRAY);
//     __type(key, __u32);
//     __type(value, __s64);
//     __uint(max_entries, MAX_ACTIVE_REQUESTS_ALLOWED);
//     __uint(pinning, LIBBPF_PIN_BY_NAME);
// } map_workers_resp_count SEC(".maps");

// The total current value of the aggregated responses
struct aggregation_entry {
    RESP_VECTOR_TYPE data[RESP_MAX_VECTOR_SIZE];
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct aggregation_entry);
    __uint(max_entries, MAX_ACTIVE_REQUESTS_ALLOWED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} map_aggregated_response SEC(".maps");

// FOr multi-packet vector aggregation, extra layer of indirection is needed
// to store MAX_PACKETS * DATA_ARRAY per request

// To unpin a map with the pinning field set, do:
// sudo rm /sys/fs/bpf/<map_name>

#endif // MAPS_BPF_H
