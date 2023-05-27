#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_SOCKETS_ALLOWED 1024
#define MAX_DATA_LENGTH 1024

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_local_ports SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} map_ringbuf SEC(".maps");


// Checks if PTR + OFFSET > END
#define CHECK_OUT_OF_BOUNDS(PTR, OFFSET, END) (((void*) PTR) + OFFSET > ((void*) END))

SEC("xdp")
int ringbuf_prog(struct xdp_md* ctx) {
    void* data_end = (void*) (long) ctx->data_end;
    void* data = (void*) (long) ctx->data;

    if (CHECK_OUT_OF_BOUNDS(data, sizeof(struct ethhdr), data_end))
        return XDP_DROP;

    struct iphdr* ip = data + sizeof(struct ethhdr);
    if (CHECK_OUT_OF_BOUNDS(ip, sizeof(struct iphdr), data_end))
        return XDP_DROP;

    void* payload;
    int payload_len = 0;
    __u16 local_port;

    if (ip->protocol == IPPROTO_UDP) {
        struct udphdr* udp = ((void*) ip) + sizeof(struct iphdr);
        if (CHECK_OUT_OF_BOUNDS(udp, sizeof(struct udphdr), data_end))
            return XDP_DROP;

        local_port = udp->dest;
        payload_len = ntohs(ip->tot_len) - (ip->ihl + sizeof(struct udphdr));
        payload = ((void*) udp) + sizeof(struct udphdr);
    }
    else if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp = ((void*) ip) + sizeof(struct iphdr);
        if (CHECK_OUT_OF_BOUNDS(tcp, sizeof(struct tcphdr), data_end))
            return XDP_DROP;

        local_port = tcp->dest;
        payload_len = ntohs(ip->tot_len) - (ip->ihl + tcp->doff) * 4;
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

    // DO something with application layer data (payload and payload_len)

    // TODO Store the payload in a parsing context object
    // bpf_tail_call(ctx, &map_xdp_progs, PROG_XDP_RX_READ_PAYLOAD);

    static int c = 0;

    bpf_printk("got packet for port %d", local_port);

	__u32* entry = bpf_ringbuf_reserve(&map_ringbuf, sizeof(__u32), 0);
    if (!entry)
        return XDP_DROP;

    *entry = ++c;
	bpf_ringbuf_submit(entry, BPF_RB_FORCE_WAKEUP); // either this or 0 for the flag

    // bpf_ringbuf_output(&map_ringbuf, &d, sizeof(__u32), 0);

    // JUST FOR TESTING, DROP ANY PACKETS FOR THE PORTS
    return XDP_DROP;
}


char LICENSE[] SEC("license") = "GPL";
