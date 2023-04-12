#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "maps.bpf.h"

static const __u32 ZERO_IDX = 0;

static inline __u8 strncmp(const char* str1, const char* str2, __u32 n) {
    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < n; ++i)
        if (str1[i] != str2[i])
            return 0;
    return 1;
}

#define SG_MSG_F_PROCESSED 1

#define IP_DEST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define UDP_DEST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_SRC_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))

static void __always_inline clone_and_send_packet(struct __sk_buff* skb, 
                                                  struct iphdr* iph, 
                                                  struct udphdr* udph,
                                                  uint32_t worker_ip,   // Network byte order
                                                  uint16_t worker_port, // Network byte order
                                                  uint16_t app_port)    // Network byte order
{
    (void) iph;
    (void) udph;

    char str[16] = "";
    __u32 ip_addr_h = bpf_ntohl(worker_ip);
	BPF_SNPRINTF(str, sizeof(str), "%d.%d.%d.%d",
		(ip_addr_h >> 24) & 0xff, (ip_addr_h >> 16) & 0xff,
		(ip_addr_h >> 8) & 0xff, ip_addr_h & 0xff);

    bpf_printk("Sending packet to %s:%d", str, bpf_ntohs(worker_port));

    // 1. Update the packet header for the new destination
    bpf_skb_store_bytes(skb, IP_DEST_OFF, &worker_ip, sizeof(worker_ip), BPF_F_RECOMPUTE_CSUM);
    bpf_skb_store_bytes(skb, UDP_DEST_OFF, &worker_port, sizeof(worker_port), BPF_F_RECOMPUTE_CSUM);
    bpf_skb_store_bytes(skb, UDP_SRC_OFF, &app_port, sizeof(app_port), BPF_F_RECOMPUTE_CSUM);

    // 2. Clone and redirect the packet to the worker
    bpf_clone_redirect(skb, skb->ifindex, 0);

    // Cloning within the kernel means we avoid multiple user-kernel interactions
    // and multiple traversals through the TCP/IP stack. See Electrode paper (consensus)

    // Example of modifying the payload
    // char c = '_';
    // int off = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    // bpf_skb_store_bytes(skb, off, &c, sizeof(c), BPF_F_RECOMPUTE_CSUM);  
}


struct send_worker_ctx {
    struct __sk_buff* skb;
    struct iphdr* ip_header;
    struct udphdr* udp_header;
};

static __u64 send_worker(void* map, __u32* idx, worker_info_t* worker, struct send_worker_ctx* data) {    
    // Non-populated map entries are zero, so stop iterating if we encounter 0
    // return 1 means the iteration should stop
    if (!worker || (worker->worker_ip == 0 || worker->worker_port == 0))
        return 1;

    clone_and_send_packet(data->skb, data->ip_header, data->udp_header, worker->worker_ip, worker->worker_port, worker->app_port);
    return 0;   // Continue to next worker destination (return 0)
}

// static const char* SCATTER_MSG = "SCATTER";
// static const __u32 SCATTER_MSG_LEN = 7;


SEC("tc")
int scatter_prog(struct __sk_buff* skb) {
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

    if (iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    udph = (struct udphdr*)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    // view logs: sudo cat /sys/kernel/debug/tracing/trace_pipe
    // sometimes they take long to appear

    // TO measure runtime of an ebpf program, set:
    // sudo sysctl -w kernel.bpf_stats_enabled=1   (remember to turn off)
    // Then, do:
    // sudo cat /proc/<LOADER_PID>/fdinfo/<BPF_PROG_FD>
    // The loader pid is typically 2nd after running: ps aux | grep "loader"

    // Intercept any outgoing scatter messages from the application
    // TODO Maybe there's a better way to intercept traffic from a particular socket
    // look into BPF_MAP_TYPE_SK_STORAGE
    // see example code Marios sent in email (email subject: Modifying SKB header fields to clone packet)
    uint16_t* local_application_port; // in network byte order already
    local_application_port = bpf_map_lookup_elem(&map_application_port, &ZERO_IDX);
    if (!local_application_port)
        return TC_ACT_OK;

    // the scatter request is sent to "self", so have this check here
    if (udph->dest == udph->source && udph->source == *local_application_port) {
        
        __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);

        // Note: this equality is needed so that the comparison size is known
        // at compile-time for the loop unrolling.
        if (payload_size != sizeof(sg_msg_t))
            return TC_ACT_OK;

        char* payload = (char*) udph + sizeof(struct udphdr);
        if ((void*) payload + payload_size > data_end)
            return TC_ACT_OK;


        sg_msg_t* sgh = (sg_msg_t*) payload; 
        if (sgh->msg_type != SCATTER_MSG)
            return TC_ACT_OK;

        const char* s = "SCATTER";
        if (!strncmp(sgh->body, s, 8))
            return TC_ACT_OK;
    

        bpf_printk("Got SCATTER request");

        // Clone the outgoing packet to all the registered workers
        struct send_worker_ctx data = {
            .skb = skb,
            .ip_header = iph,
            .udp_header = udph,
        };
        bpf_for_each_map_elem(&map_workers, send_worker, &data, 0);

        bpf_printk("Finished SCATTER request");
        
        //  todo: no need to clone the last one
        return TC_ACT_SHOT; // To avoid double-sending to the last worker
    }
    
    return TC_ACT_OK;
}


// static __always_inline enum worker_response_status* get_worker_status(__u32 source_ip, __u16 source_port) {
//     struct ubpf_worker w;
//     // without this, the verifier thinks we are accessing uninitialised memory
//     __builtin_memset(&w, 0, sizeof(struct ubpf_worker));
//     w.ip_addr = source_ip;
//     w.port = source_port;
//     return bpf_map_lookup_elem(&map_workers_resp_status, &w);
// }


static __u64 check_worker_status(void* map, worker_info_t* worker, worker_resp_status_t* status, __u8* waiting) {
    if (!status)
        return 1;

    *waiting = (*status == WAITING_FOR_RESPONSE);
    return *waiting ? 1 : 0;
}


static __u64 reset_worker_status(void* map, worker_info_t* worker, worker_resp_status_t* status, __u8* waiting) {
    if (!status)
        return 1;

    worker_resp_status_t updated_status = WAITING_FOR_RESPONSE;
    bpf_map_update_elem(map, worker, &updated_status, 0);
    return 0;
}



static __always_inline unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;

    while (bufsz > 1) {
        sum += *buf;
        buf++;
        bufsz -= 2;
    }

    if (bufsz == 1)
        sum += *(unsigned char *)buf;

    sum = (sum & 0xffff0000) + (sum & 0xffff);
    sum = (sum & 0xffff0000) + (sum & 0xffff);

    return ~sum;
}



SEC("xdp")
int gather_prog(struct xdp_md* ctx) {
    void* data = (void *)(long)ctx->data;
	void* data_end = (void *)(long)ctx->data_end;
	struct ethhdr* ethh;
	struct iphdr* iph;
    struct udphdr* udph;

	ethh = data;
	if ((void *)(ethh + 1) > data_end)
		return XDP_PASS;

	if (ethh->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	iph = (struct iphdr *)(ethh + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP)
        return XDP_PASS;

    udph = (struct udphdr*)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return XDP_PASS;


    // TODO Potentially move this to the socket/TC layer and use the SOCKET STORAGE Map?
    // each socket has some storage associated, such as the worker IP and worker source
    worker_info_t worker;
    __builtin_memset(&worker, 0, sizeof(worker_info_t));    // needed
    worker.worker_ip = iph->saddr;
    worker.worker_port = udph->source;
    worker.app_port = udph->dest;
    worker_resp_status_t* status = bpf_map_lookup_elem(&map_workers_resp_status, &worker);
    if (!status || *status == RECEIVED_RESPONSE)
        return XDP_PASS;


    bpf_printk("Is from a NEW worker!");

    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    bpf_printk("Payload size: %d", payload_size);

    // Note: this equality is needed so that the comparison size is known
    // at compile-time for the loop unrolling.
    if (payload_size != sizeof(sg_msg_t))
        return TC_ACT_OK;

    char* payload = (char*) udph + sizeof(struct udphdr);
    if ((void*) payload + payload_size > data_end)
        return TC_ACT_OK;


    sg_msg_t* resp_msg = (sg_msg_t*) payload;
    if (resp_msg->msg_type != GATHER_MSG)
        return TC_ACT_OK;

    // Get the int the worker responded with
    __u32 resp = bpf_ntohl(*((__u32 *) resp_msg->body));
    bpf_printk("Got packet from worker %d with payload = %d for req ID = %d", bpf_ntohs(udph->source), resp, resp_msg->req_id);

    // Aggregate the value
    RESP_AGGREGATION_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
    if (!agg_resp)
        return XDP_ABORTED;


    const __u32 updated_resp = *agg_resp + resp;
    bpf_map_update_elem(&map_aggregated_response, &ZERO_IDX, &updated_resp, 0);

    // Flag that this worker is completed
    worker_resp_status_t updated_status = RECEIVED_RESPONSE; // cannot recycle pointers returned by map lookups!
    bpf_map_update_elem(&map_workers_resp_status, &worker, &updated_status, 0);

    // Set the flag in the payload for the upper layer programs
    resp_msg->flags = SG_MSG_F_PROCESSED;

    // // if this was the last packet, notify the control socket
    // __u8 still_waiting = 0;
    // bpf_for_each_map_elem(&map_workers_resp_status, check_worker_status, &still_waiting, 0);

    // if (!still_waiting) {
    //     bpf_printk("Got last packet!");

    //     // how to do this?
    //     __u16* port = bpf_map_lookup_elem(&map_gather_ctrl_port, &ZERO_IDX);
    //     if (!port)
    //         return XDP_DROP;
        
    //     udph->dest = *port;
    //     udph->check = 0;
    //     udph->check = checksum((unsigned short *)udph, sizeof(struct udphdr));

    //     // Mark the packet as done

    //     // MAYBE just do this specific redirection in TC layer
    // }



    return XDP_PASS;
}


SEC("tc")
int notify_gather_ctrl_prog(struct __sk_buff* skb) {
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

    if (iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    udph = (struct udphdr*)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;


    // CHECK THE FORMAT OF THE PAYLOAD TO MAKE SURE IT IS A GATHER MESSAGE
    // AND FLAGS IS SET TO 1

    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    if (payload_size != sizeof(sg_msg_t))
        return TC_ACT_OK;

    char* payload = (char*) udph + sizeof(struct udphdr);
    if ((void*) payload + payload_size > data_end)
        return TC_ACT_OK;

    sg_msg_t* resp_msg = (sg_msg_t*) payload;
    if (resp_msg->flags != SG_MSG_F_PROCESSED && resp_msg->msg_type != GATHER_MSG)
        return TC_ACT_OK;

    // if this was the last packet, notify the control socket
    __u8 still_waiting = 0;
    bpf_for_each_map_elem(&map_workers_resp_status, check_worker_status, &still_waiting, 0);

    if (!still_waiting) {        
        const __u16 worker_port = udph->dest;

        __u16* port = bpf_map_lookup_elem(&map_gather_ctrl_port, &ZERO_IDX);
        if (!port)
            return TC_ACT_SHOT;
        
        // Notify the gather control socket
        bpf_skb_store_bytes(skb, UDP_DEST_OFF, port, sizeof(*port), BPF_F_RECOMPUTE_CSUM);
        bpf_clone_redirect(skb, skb->ifindex, 0);

        bpf_skb_store_bytes(skb, UDP_DEST_OFF, &worker_port, sizeof(worker_port), BPF_F_RECOMPUTE_CSUM);
        
        // RESET
        bpf_for_each_map_elem(&map_workers_resp_status, reset_worker_status, &still_waiting, 0);
    }


    return TC_ACT_OK;

}


char LICENSE[] SEC("license") = "GPL";