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
#define MAX_DATA_LENGTH 1024

struct result {
    char    data[MAX_DATA_LENGTH];
    __u32   len;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, __u8);
    __uint(max_entries, MAX_SOCKETS_ALLOWED);
} map_local_ports SEC(".maps");


SEC("tc")
int tc_ingress_filter_prog(struct __sk_buff* skb) {
	void* data = (void *)(long)skb->data;
	void* data_end = (void *)(long)skb->data_end;
	struct ethhdr* l2;
	struct iphdr* l3;
    struct tcphdr* tcp;

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

    if (l3->protocol == 6)  { //tcp
        tcp = (struct tcphdr*)(l3 + 1);

        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;

        if (tcp->dest == bpf_htons(9921)) { // DROP packets to port 9921
            return TC_ACT_SHOT;
        }
    }
	// bpf_printk("Got IP packet: tot_len: %d, ttl: %d", bpf_ntohs(l3->tot_len), l3->ttl);
	return TC_ACT_OK;
}


SEC("tc")
int tc_egress_filter_prog(struct __sk_buff* skb) {

    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "GPL";