#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_SOCKETS_ALLOWED 1024
#define MAX_DATA_LENGTH 1024

struct result {
    char    data[MAX_DATA_LENGTH];
    __u32   len;
};


enum reduce_operation_t {
    REDUCE_OPERATION_UNDEFINED = 0,
    REDUCE_OPERATION_SUM,
    REDUCE_OPERATION_MULTIPLY,
    // REDUCE_OPERATION_FILTER // TODO future, allow composable operations
};

struct bpf_map_def SEC("maps") map_local_ports = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u16),            // Local port number (in htons)
    .value_size     = sizeof(__u8),             // Is present?
    .max_entries    = MAX_SOCKETS_ALLOWED
};

struct bpf_map_def SEC("maps") map_gather_results = {
    .type           = BPF_MAP_TYPE_HASH,
    .key_size       = sizeof(__u16),            // Local port number (in htons)
    .value_size     = sizeof(struct result),    // Result          
    .max_entries    = MAX_SOCKETS_ALLOWED
};

// Stores the ordered list of reduction operations
struct bpf_map_def SEC("maps") map_reduce_operation = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .key_size       = sizeof(__u32),      
    .value_size     = sizeof(enum reduce_operation_t),          
    .max_entries    = 1
};

// Stores the current total aggregate value from all previous reductions
struct bpf_map_def SEC("maps") map_current_reduced_value = {
    .type           = BPF_MAP_TYPE_ARRAY,
    .key_size       = sizeof(__u32),
    .value_size     = sizeof(void*),    // TODO Maybe this should just be bytes
    .max_entries    = 1
};


// Program map for tail calls

enum {
    PROG_XDP_RX_FILTER = 0,
    PROG_XDP_RX_READ_PAYLOAD,

    XDP_PROG_COUNT
};

struct bpf_map_def SEC("maps") map_xdp_progs = {
	.type           = BPF_MAP_TYPE_PROG_ARRAY,
	.key_size       = sizeof(__u32),
	.value_size     = sizeof(__u32),
	.max_entries    = XDP_PROG_COUNT,
};

// Checks if PTR + OFFSET > END
#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END) (((void*) PTR) + OFFSET > ((void*) END))

SEC("xdp/rx_filter")
int rx_filter_func(struct xdp_md* ctx) {
    void* data_end = (void*) (long) ctx->data_end;
    void* data = (void*) (long) ctx->data;

    if (CHECK_OUT_OF_BOUNDS(data, sizeof(struct ethhdr), data_end))
        return XDP_DROP;

    struct iphdr* ip = data + sizeof(struct ethhdr);
    if (CHECK_OUT_OF_BOUNDS(ip, sizeof(struct iphdr), data_end))
        return XDP_DROP;

    void* payload;
    __u16 local_port;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr* udp = ((void*) ip) + sizeof(struct iphdr);
        if (CHECK_OUT_OF_BOUNDS(udp, sizeof(struct udphdr), data_end))
            return XDP_DROP;

        local_port = udp->dest;
        payload = ((void*) udp) + sizeof(struct udphdr);
    }
    else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = ((void*) ip) + sizeof(struct iphdr);
        if (CHECK_OUT_OF_BOUNDS(tcp, sizeof(struct tcphdr), data_end))
            return XDP_DROP;

        local_port = tcp->dest;
        payload = ((void*) tcp) + sizeof(struct tcphdr);   
    }
    else {
        return XDP_PASS;
    }

    // Check if the packet is destined for one of the application's opened ports
    __u8* is_open = bpf_map_lookup_elem(&map_local_ports, &local_port);
    if (!is_open)
        return XDP_PASS;

    // REMEMBER that the map stores the port in htons, no need to convert

    // TODO Store the payload in a parsing context object
    // bpf_tail_call(ctx, &map_xdp_progs, PROG_XDP_RX_READ_PAYLOAD);

    // JUST FOR TESTING, DROP ANY PACKETS FOR THE PORTS
    return XDP_DROP;
}


char LICENSE[] SEC("license") = "GPL";