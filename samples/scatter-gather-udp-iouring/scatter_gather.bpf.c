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

// static inline __u8 strncmp(const char* str1, const char* str2, __u32 n) {
//     #pragma clang loop unroll(full)
//     for (__u32 i = 0; i < n; ++i)
//         if (str1[i] != str2[i])
//             return 0;
//     return 1;
// }

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
        bpf_printk("payload size: %d   sizeof(sg_msg_t) = %d", payload_size, sizeof(sg_msg_t));

        // Note: this equality is needed so that the comparison size is known
        // at compile-time for the loop unrolling.
        if (payload_size != sizeof(sg_msg_t))
            return TC_ACT_OK;

        char* payload = (char*) udph + sizeof(struct udphdr);
        if ((void*) payload + payload_size > data_end) {
            // data_end - data = MTU size + ETH_HDR (14 bytes)
            bpf_printk("Invalid packet size: payload might be larger than MTU");
            return TC_ACT_OK;
        }

        sg_msg_t* sgh = (sg_msg_t*) payload; 
        if (sgh->hdr.msg_type != SCATTER_MSG)
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


// static __u64 check_worker_status(void* map, worker_info_t* worker, worker_resp_status_t* status, __u8* waiting) {
//     if (!status)
//         return 1;

//     *waiting = (*status == WAITING_FOR_RESPONSE);
//     return *waiting ? 1 : 0;
// }


// static __u64 reset_worker_status(void* map, worker_info_t* worker, worker_resp_status_t* status, __u8* waiting) {
//     if (!status)
//         return 1;

//     worker_resp_status_t updated_status = WAITING_FOR_RESPONSE;
//     bpf_map_update_elem(map, worker, &updated_status, 0);
//     return 0;
// }



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

    // we only check that the worker is valid, we don't check for duplicates now
    worker_resp_status_t* status = bpf_map_lookup_elem(&map_workers_resp_status, &worker);
    if (!status) {
        return XDP_PASS;
    }

    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);

    // Note: this equality is needed so that the comparison size is known
    // at compile-time for the loop unrolling.
    if (payload_size != sizeof(sg_msg_t))
        return XDP_DROP;

    char* payload = (char*) udph + sizeof(struct udphdr);
    if ((void*) payload + payload_size > data_end)
        return XDP_DROP;


    sg_msg_t* resp_msg = (sg_msg_t*) payload;
    if (resp_msg->hdr.msg_type != GATHER_MSG)
        return XDP_DROP;

    // If this is a multi-packet message, forward the packet without aggregation
    if (resp_msg->hdr.num_pks > 1 && resp_msg->hdr.seq_num <= resp_msg->hdr.num_pks) {
        bpf_printk("[MP] [Worker %d] Got packet with req ID = %d and seq num = %d", bpf_ntohs(worker.worker_port), resp_msg->hdr.req_id, resp_msg->hdr.seq_num);
        return XDP_PASS;
    }

    // Single-packet response aggregation:

#ifdef VECTOR_RESPONSE
    bpf_map_update_elem(&map_vector_aggregation_chunk_idx, &ZERO_IDX, &ZERO_IDX, 0);
    // Save the pointer to the packet body
    bpf_map_update_elem(&map_packet_body_context, &ZERO_IDX, &resp_msg->body, BPF_F_CURRENT_CPU);

    // Perform the vector aggregation logic in a new stack frame
    bpf_tail_call(ctx, &map_vector_aggregation_progs, VECTOR_AGGREGATION_PROG_IDX);

#else
    // Get the int the worker responded with
    __u32 resp = bpf_ntohl(*((__u32 *) resp_msg->body));
    bpf_printk("Got packet with payload = %d for req ID = %d and seq num = %d", resp, resp_msg->hdr.req_id, resp_msg->hdr.seq_num);

    // Aggregate the value
    RESP_AGGREGATION_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
    if (!agg_resp)
        return XDP_ABORTED;

    const __u32 updated_resp = *agg_resp + resp;
    bpf_map_update_elem(&map_aggregated_response, &ZERO_IDX, &updated_resp, 0);

#endif

    // Flag that this worker is completed
    // worker_resp_status_t updated_status = RECEIVED_RESPONSE; // cannot recycle pointers returned by map lookups!
    // bpf_map_update_elem(&map_workers_resp_status, &worker, &updated_status, 0);

    // Set the flag in the payload for the upper layer programs
    // resp_msg->flags = SG_MSG_F_PROCESSED;

    return XDP_PASS;
}

#define MIN(a,b) ((a) < (b) ? (a) : (b))

SEC("xdp")
int vector_aggregation_prog(struct xdp_md* ctx) {
#ifdef VECTOR_RESPONSE
    __u32* chunk_idx_ptr = bpf_map_lookup_elem(&map_vector_aggregation_chunk_idx, &ZERO_IDX);
    if (!chunk_idx_ptr)
        return XDP_ABORTED;

    __u32 chunk_idx = *chunk_idx_ptr;   // TODO can we remove this
    bpf_printk("Processing chunk %d", chunk_idx);
    
    RESP_VECTOR_TYPE* resp = bpf_map_lookup_elem(&map_packet_body_context, &ZERO_IDX);
    if (!resp)
        return XDP_ABORTED;

    RESP_VECTOR_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &chunk_idx);
    if (!agg_resp)
        return XDP_ABORTED;

    RESP_VECTOR_TYPE updated_resp[VECTOR_AGGREGATION_CHUNK] = {0};
    __u32 chunk_size = MIN(RESP_MAX_VECTOR_SIZE - (chunk_idx * VECTOR_AGGREGATION_CHUNK), VECTOR_AGGREGATION_CHUNK);
    for (__u32 i = 0; i < chunk_size; ++i) {

        // updated_resp[i] = resp[i] + 1;// resp[i];   // THE PROBLEM Is the access into resp
        updated_resp[i] = agg_resp[i] + 1;// this works
    }
    bpf_map_update_elem(&map_aggregated_response, &chunk_idx, &updated_resp, 0);
    bpf_printk("%d", resp[0]);

    // Check if done
    chunk_idx++;
    if (chunk_idx * VECTOR_AGGREGATION_CHUNK >= RESP_MAX_VECTOR_SIZE) {
        bpf_printk("finished vector aggregation");
        bpf_tail_call(ctx, &map_vector_aggregation_progs, 1);
        return XDP_PASS;
    }
    if (chunk_idx >= RESP_VECTOR_MAP_ENTRIES)
        return XDP_ABORTED;

    bpf_map_update_elem(&map_vector_aggregation_chunk_idx, &ZERO_IDX, &chunk_idx, 0);

    chunk_idx--;

    // Move the body pointer forward
    char* updated_body = (char*) (resp + chunk_size);
    bpf_map_update_elem(&map_packet_body_context, &ZERO_IDX, &updated_body, 0);

    // Repeat with remaining elements
    bpf_tail_call(ctx, &map_vector_aggregation_progs, VECTOR_AGGREGATION_PROG_IDX);

#endif
    return XDP_PASS;
}


SEC("xdp")
int post_vector_aggregation_prog(struct xdp_md* ctx) {
    // __u32 idx = 0;
    // bpf_printk("------- Chunk %d -------", idx);
    // RESP_VECTOR_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &idx);
    // if (!agg_resp)
    //     return XDP_ABORTED;

    // for (__u32 i = 0; i < VECTOR_AGGREGATION_CHUNK; ++i) {
    //     bpf_printk("updated_resp[%d] = %d", i, agg_resp[i]);
    // }        

    // idx++;
    // bpf_printk("------- Chunk %d -------", idx);
    // RESP_VECTOR_TYPE* agg_resp2 = bpf_map_lookup_elem(&map_aggregated_response, &idx);
    // if (!agg_resp2)
    //     return XDP_ABORTED;

    // // bpf_printk("------- Chunk %d -------", c);
    // for (__u32 i = VECTOR_AGGREGATION_CHUNK; i < VECTOR_AGGREGATION_CHUNK * 2; ++i) {
    //     bpf_printk("updated_resp[%d] = %d", i, agg_resp2[i]);
    // }        


    return XDP_PASS;
}

/*
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


    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    if (payload_size != sizeof(sg_msg_t))
        return TC_ACT_OK;

    char* payload = (char*) udph + sizeof(struct udphdr);
    if ((void*) payload + payload_size > data_end)
        return TC_ACT_OK;

    sg_msg_t* resp_msg = (sg_msg_t*) payload;
    if (resp_msg->hdr.flags != SG_MSG_F_PROCESSED && resp_msg->hdr.msg_type != GATHER_MSG)
        return TC_ACT_OK;

    // if this was the last packet, notify the control socket
    __u8 still_waiting = 0;
    bpf_for_each_map_elem(&map_workers_resp_status, check_worker_status, &still_waiting, 0);

    if (!still_waiting) { 
        bpf_printk("!!!!!!!!!!!! NOTIFYING CTRL SOCKET !!!!!!!!!!!!!!!11");       
        __u16* ctrl_sk_port = bpf_map_lookup_elem(&map_gather_ctrl_port, &ZERO_IDX);
        if (!ctrl_sk_port)
            return TC_ACT_SHOT;
        
        // Send the incoming packet to the final worker
        bpf_clone_redirect(skb, skb->ifindex, 0);

        // Notify the control socket with the final aggregated value
        RESP_AGGREGATION_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
        if (!agg_resp)
            return TC_ACT_SHOT;

        RESP_AGGREGATION_TYPE agg_resp_val = bpf_htonl(*agg_resp);  // conversion not strictly needed, as long as app reads in correct form
        unsigned offset = ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + offsetof(sg_msg_t, body);
        bpf_skb_store_bytes(skb, offset, &agg_resp_val, sizeof(agg_resp_val), BPF_F_RECOMPUTE_CSUM);
        bpf_skb_store_bytes(skb, UDP_DEST_OFF, ctrl_sk_port, sizeof(*ctrl_sk_port), BPF_F_RECOMPUTE_CSUM);
        
        // RESET
        bpf_for_each_map_elem(&map_workers_resp_status, reset_worker_status, &still_waiting, 0);
    }

    return TC_ACT_OK;
}

*/


char LICENSE[] SEC("license") = "GPL";