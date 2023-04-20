#ifndef MAPS_BPF_H
#define MAPS_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "common.h"

// ---------------------- //
//       eBPF Maps        //
// ---------------------- //

// Stores the different parts of the aggregation logic for vector data
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} map_vector_aggregation_progs SEC(".maps");


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
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, worker_info_t);
    __type(value, worker_resp_status_t); // this should also be per request ID
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_workers_resp_status SEC(".maps");

// Stores the number of packets received for each request ID
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // per cpu?
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_ACTIVE_REQUESTS_ALLOWED);
} map_workers_resp_count SEC(".maps");

// The total current value of the aggregated responses
// TODO eventually, use an array/hash map which maps request IDs -> values
// to support multiple concurrent operations

// TODO this should also be thread-safe!!!!
//  - use spin lock to update
//  - use per cpu maps and perform a final aggregation at the end? probably faster
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, RESP_VECTOR_TYPE[RESP_MAX_VECTOR_SIZE]);
    __uint(max_entries, RESP_VECTOR_MAP_ENTRIES);   // can be reverted to 1, unless we do multi-packet vector aggregation
} map_aggregated_response SEC(".maps");

// look into making RESP_AGGREGATION_TYPE an array of fixed size?
// vectorised aggregation inside ebpf (single packet)
// make configurable whether to return final response or all responses

// course-grained fault tolerance (recovery): use timer at application level
// to check if the operation has complete

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, char[BODY_LEN]);
    __uint(max_entries, 1);
} map_body_data SEC(".maps");


#endif // MAPS_BPF_H
