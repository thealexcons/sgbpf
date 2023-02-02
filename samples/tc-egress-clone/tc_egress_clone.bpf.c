#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MAX_SOCKETS_ALLOWED 1024

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} map_application_port SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // TODO consider per-cpu map
    __type(key, __u32);
    __type(value, __u16);
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_worker_ports SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // TODO consider per-cpu map
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_worker_ips SEC(".maps");


static inline __u8 strncmp(const char* str1, const char* str2, __u32 n) {
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < n; ++i)
        if (str1[i] != str2[i])
            return 0;
    return 1;
}


#define IP_DEST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define IP_CSUM_OFF (ETH_HLEN + offsetof(struct iphdr, check))

#define UDP_DEST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, check))

#define IS_PSEUDO 0x10


unsigned long long load_half(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.half");

unsigned long long load_word(void *skb,
			     unsigned long long off) asm("llvm.bpf.load.word");

static void modify_packet_udp(struct __sk_buff* skb, struct iphdr* iph, struct udphdr* udph, __u32 worker_ip, __u16 worker_port) {
    (void) iph;
    (void) udph;

    // worker_port is in host byte order, just like old_port below

    __u16 old_port = load_half(skb, UDP_DEST_OFF); // this seems to be in host byte order
    // but udph->dest is in network byte order??

    // SAME as bpf_htons(udph->dest);
    // bpf_printk("udph->dest : %d", udph->dest);
    // bpf_printk("bpf_htons(udph->dest) : %d", bpf_htons(udph->dest));
    // bpf_printk("old_port = %d", old_port);
    // bpf_printk("worker port = %d", worker_port);

    __u32 old_ip_addr = bpf_htonl(load_word(skb, IP_DEST_OFF));    // SAME as iph->daddr
    // bpf_printk("iph->daddr : %d", iph->daddr);
    // bpf_printk("old_ip_addr = %d", old_ip_addr);
    // bpf_printk("worker ip = %d", worker_ip);

    // Modify header with the new destination IP address
    bpf_l4_csum_replace(skb, UDP_CSUM_OFF, old_ip_addr, worker_ip, IS_PSEUDO | sizeof(worker_ip));
    bpf_l3_csum_replace(skb, IP_CSUM_OFF, old_ip_addr, worker_ip, sizeof(worker_ip));
    bpf_skb_store_bytes(skb, IP_DEST_OFF, &worker_ip, sizeof(worker_ip), BPF_F_RECOMPUTE_CSUM);

    // Modify header the new destination port
    bpf_l4_csum_replace(skb, UDP_CSUM_OFF, old_port, worker_port, sizeof(worker_port));
    bpf_skb_store_bytes(skb, UDP_DEST_OFF, &worker_port, sizeof(worker_port), BPF_F_RECOMPUTE_CSUM);

    // 3. Once we get to the scatter, we should probably set the udph->source to
    // port of the worker UDP sockets to correctly reply to the coordinator
    
    bpf_clone_redirect(skb, skb->ifindex, 0);

}


static void clone_send_packet(struct __sk_buff* skb, 
                              struct iphdr* iph, 
                              struct udphdr* udph,
                              uint32_t worker_ip,   // Network byte order
                              uint16_t worker_port) // Network byte order
{
    char str[16] = "";
    __u32 ip_addr_h = bpf_ntohl(worker_ip);
	BPF_SNPRINTF(str, sizeof(str), "%d.%d.%d.%d",
		(ip_addr_h >> 24) & 0xff, (ip_addr_h >> 16) & 0xff,
		(ip_addr_h >> 8) & 0xff, ip_addr_h & 0xff);

    bpf_printk("Sending packet to %s:%d", str, bpf_ntohs(worker_port));

    // 1. Update the packet header for the new destination
    modify_packet_udp(skb, iph, udph, worker_ip, bpf_ntohs(worker_port));    

    // 2. Clone the skb

}


struct send_worker_ctx {
    struct __sk_buff* skb;
    struct iphdr* ip_header;
    struct udphdr* udp_header;
};

static __u64 send_worker(void* ip_map, __u32* idx, __u32* worker_ip, struct send_worker_ctx* data) {    
    // Non-populated map entries are zero, so stop iterating if we encounter 0
    // return 1 means the iteration should stop
    if (!worker_ip || *worker_ip == 0)
        return 1;

    uint16_t* worker_port = bpf_map_lookup_elem(&map_worker_ports, idx);
    if (!worker_port || *worker_port == 0)
        return 1;

    clone_send_packet(data->skb, data->ip_header, data->udp_header, *worker_ip, *worker_port);

    return 0;   // Continue to next worker destination (return 0)
}

static const char* SCATTER_MSG = "SCATTER";
static const __u32 SCATTER_MSG_LEN = 7;


SEC("tc")
int tc_egress_clone_prog(struct __sk_buff* skb) {
	void* data = (void *)(long)skb->data;
	void* data_end = (void *)(long)skb->data_end;
	struct ethhdr* ethh;
	struct iphdr* iph;
    struct udphdr* udph;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	ethh = data;
	if ((void *)(ethh + 1) > data_end)
		return TC_ACT_OK;

	iph = (struct iphdr *)(ethh + 1);
	if ((void *)(iph + 1) > data_end)
		return TC_ACT_OK;


    // Intercept any outgoing scatter messages from the application
    // TODO Maybe there's a better way to intercept traffic from a particular socket
    uint16_t* local_application_port; // in network byte order already
    const uint32_t zero = 0;
    local_application_port = bpf_map_lookup_elem(&map_application_port, &zero);
    if (!local_application_port)
        return TC_ACT_OK;

    if (iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;


    udph = (struct udphdr*)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    // view logs: sudo cat /sys/kernel/debug/tracing/trace_pipe
    // sometimes they take long to appear
    
    // the scatter request is sent to "self", so have this check here
    if (udph->dest == udph->source && udph->source == *local_application_port) {
        
        __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);

        // Note: this equality is needed so that the comparison size is known
        // at compile-time for the loop unrolling.
        if (payload_size != SCATTER_MSG_LEN)
            return TC_ACT_OK;

        char* payload = (char*) udph + sizeof(struct udphdr);
        if ((void*) payload + payload_size > data_end)
            return TC_ACT_OK;

        if (!strncmp(payload, SCATTER_MSG, payload_size))
            return TC_ACT_OK;
    

        bpf_printk("Got SCATTER request");
        bpf_printk("App port = %d", *local_application_port);

        // Clone the outgoing packet to all the registered workers
        struct send_worker_ctx data = {
            .skb = skb,
            .ip_header = iph,
            .udp_header = udph,
        };
        bpf_for_each_map_elem(&map_worker_ips, send_worker, &data, 0);

        bpf_printk("Finished SCATTER request");
        
        return TC_ACT_OK;
    }
    

    // look at consensus paper on how to do this

    return TC_ACT_OK;
}




char LICENSE[] SEC("license") = "GPL";