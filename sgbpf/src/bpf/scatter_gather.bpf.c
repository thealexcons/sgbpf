#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/in.h>

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "Common.h"
#include "bpf_h/helpers.bpf.h"
#include "bpf_h/maps.bpf.h"


// Offsets for specific fields in the packets
#define IP_DEST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define UDP_DEST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_SRC_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define SG_MSG_FLAGS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + offsetof(sg_msg_t, hdr) + offsetof(struct sg_msg_hdr, flags))
#define SG_MSG_MSGTYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + offsetof(sg_msg_t, hdr) + offsetof(struct sg_msg_hdr, msg_type))
#define SG_MSG_BODY_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + offsetof(sg_msg_t, body))

/**************************** HELPER FUNCTIONS ********************************/

static void __always_inline clone_and_send_packet(struct __sk_buff* skb, 
                                                  uint32_t worker_ip,   // Network byte order
                                                  uint16_t worker_port, // Network byte order
                                                  uint16_t app_port)    // Network byte order
{
    #ifdef BPF_DEBUG_PRINT
    char str[16] = "";
    __u32 ip_addr_h = bpf_ntohl(worker_ip);
	BPF_SNPRINTF(str, sizeof(str), "%d.%d.%d.%d",
		(ip_addr_h >> 24) & 0xff, (ip_addr_h >> 16) & 0xff,
		(ip_addr_h >> 8) & 0xff, ip_addr_h & 0xff);

    bpf_printk("Sending packet to %s:%d", str, bpf_ntohs(worker_port));
    #endif

    // 1. Update the packet header for the new destination
    bpf_skb_store_bytes(skb, IP_DEST_OFF, &worker_ip, sizeof(worker_ip), 0);
    bpf_skb_store_bytes(skb, UDP_DEST_OFF, &worker_port, sizeof(worker_port), 0);
    bpf_skb_store_bytes(skb, UDP_SRC_OFF, &app_port, sizeof(app_port), BPF_F_RECOMPUTE_CSUM);

    // 2. Clone and redirect the packet to the worker
    bpf_clone_redirect(skb, skb->ifindex, 0);
}


struct send_worker_ctx {
    struct __sk_buff* skb;
};

static __u64 send_worker(void* map, __u32* idx, worker_info_t* worker, struct send_worker_ctx* ctx) {    
    // Non-populated map entries are zero, so stop iterating if we encounter 0
    // return 1 means the iteration should stop
    if (!worker || (worker->worker_ip == 0 || worker->worker_port == 0))
        return 1;

    clone_and_send_packet(ctx->skb, worker->worker_ip, worker->worker_port, worker->app_port);
    return 0;   // Continue to next worker destination (return 0)
}


static inline int handle_clean_req_msg(char* payload, __u32 payload_size, void* data_end) {

    sg_clean_req_msg_t* clean_msg = (sg_clean_req_msg_t*) payload;
    if (UNLIKELY( clean_msg->magic != SG_CLEAN_REQ_MSG_MAGIC ))
        return TC_ACT_OK;

    #ifdef DEBUG_PRINT
    bpf_printk("Got cleanup msg for req id %d", clean_msg->req_id);
    #endif
    
    __u32 slot = GET_REQ_MAP_SLOT(clean_msg->req_id);

    // reset the stale count
    struct req_state* rs = bpf_map_lookup_elem(&map_req_state, &slot);
    CHECK_MAP_LOOKUP(rs, XDP_ABORTED);

    bpf_spin_lock(&rs->count_lock); // probably not needed, as it won't be under contention
    rs->count = 0;
    rs->post_agg_count = 0;
    bpf_spin_unlock(&rs->count_lock);

    // reset the stale aggregated data
    struct aggregation_entry* agg_entry = bpf_map_lookup_elem(&map_aggregated_response, &slot);
    CHECK_MAP_LOOKUP(agg_entry, TC_ACT_SHOT);
    
    bpf_spin_lock(&agg_entry->lock);
    clear_vector(agg_entry->data);
    bpf_spin_unlock(&agg_entry->lock);

    return TC_ACT_SHOT;
}

/******************************************************************************/


SEC("tc")
int scatter_prog(struct __sk_buff* skb) {
    // START_TIMER("scatter_prog"); // hot path takes around 10 to 20 us

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
    // The loader pid is typically 2nd (w/o sudo) after running: ps aux | grep "loader"
    // however this seems to be mismatched with manually timing it.

    // TODO Maybe there's a better way to intercept traffic from a particular socket
    const __u32 zero = 0;
    uint16_t* local_application_port = bpf_map_lookup_elem(&map_application_port, &zero); // in network byte order
    CHECK_MAP_LOOKUP(local_application_port, TC_ACT_OK);

    // the scatter request is sent to "self", so have this check here
    if (udph->dest == udph->source && udph->source == *local_application_port) {
        
        __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
        char* payload = (char*) udph + sizeof(struct udphdr);

        // Note: this equality is needed so that the comparison size is known
        // at compile-time for the loop unrolling.
        if (payload_size != sizeof(sg_msg_t)) {
            if (payload_size == sizeof(sg_clean_req_msg_t) && !((void*) payload + payload_size > data_end)) {
                return handle_clean_req_msg(payload, payload_size, data_end);
            }
            return TC_ACT_OK;
        }

        if (UNLIKELY( (void*) payload + payload_size > data_end )) {
            // data_end - data = MTU size + ETH_HDR (14 bytes)
            bpf_printk("Invalid packet size: payload might be larger than MTU?");
            return TC_ACT_OK;
        }

        sg_msg_t* sgh = (sg_msg_t*) payload; 
        if (UNLIKELY( sgh->hdr.msg_type != SCATTER_MSG ))
            return TC_ACT_OK;

        __u32 slot = GET_REQ_MAP_SLOT(sgh->hdr.req_id);

        // Configure request settings from the provided flags (completion policy)
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("====================== GOT NEW REQ %d==============================", sgh->hdr.req_id);
        #endif

        // Reset count (NOTE: this must go here, NOT in the notification prog)
        struct req_state* rs = bpf_map_lookup_elem(&map_req_state, &slot);
        CHECK_MAP_LOOKUP(rs, TC_ACT_SHOT);

        bpf_spin_lock(&rs->count_lock);
        rs->count = 0;
        rs->post_agg_count = 0;
        bpf_spin_unlock(&rs->count_lock);

        rs->num_workers = sgh->hdr.num_pks;

        #ifdef BPF_DEBUG_PRINT
        bpf_printk("Got num workers to WAIT = %d", rs->num_workers);
        #endif

        // Clone the outgoing packet to all the registered workers
        struct send_worker_ctx data = {
            .skb = skb,
        };
        bpf_for_each_map_elem(&map_workers, send_worker, &data, 0);

#ifdef BPF_DEBUG_PRINT
        bpf_printk("Finished SCATTER request");
#endif
        return TC_ACT_SHOT; // To avoid double-sending to the last worker
    }
    
    return TC_ACT_OK;
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


    worker_info_t worker;
    __builtin_memset(&worker, 0, sizeof(worker_info_t));    // needed
    worker.worker_ip = iph->saddr;
    worker.worker_port = udph->source;
    worker.app_port = udph->dest;

    // we only check that the worker is valid, we don't check for duplicates now
    worker_resp_status_t* status = bpf_map_lookup_elem(&map_workers_resp_status, &worker);
    CHECK_MAP_LOOKUP(status, XDP_PASS);

    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    char* payload = (char*) udph + sizeof(struct udphdr);
    if (UNLIKELY( payload_size != sizeof(sg_msg_t) || (void*) payload + payload_size > data_end ))
        return XDP_DROP;

    sg_msg_t* resp_msg = (sg_msg_t*) payload;
    if (UNLIKELY( resp_msg->hdr.msg_type != GATHER_MSG ))
        return XDP_DROP;

    #ifdef BPF_DEBUG_PRINT
    // bpf_printk("got to gather XDP Prog with resp from worker %d", bpf_ntohs(worker.worker_port));
    #endif

    // If this is a multi-packet message, forward the packet without aggregation
    if (resp_msg->hdr.num_pks > 1 && resp_msg->hdr.seq_num <= resp_msg->hdr.num_pks) {
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("[MP] [Worker %d] Got packet with req ID = %d and seq num = %d", bpf_ntohs(worker.worker_port), resp_msg->hdr.req_id, resp_msg->hdr.seq_num);
        #endif
        return XDP_PASS;
    }

    // Single-packet response aggregation:
    
    if (resp_msg->hdr.flags == SG_MSG_F_LAST_CLONED) {
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("dropping cloned (final) packet from worker %d", bpf_ntohs(worker.worker_port));
        #endif
        return XDP_PASS;
    } else {
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("processing msg from worker %d", bpf_ntohs(worker.worker_port));
        #endif
    }

    __u32 slot = GET_REQ_MAP_SLOT(resp_msg->hdr.req_id);
    
    struct req_state* rs = bpf_map_lookup_elem(&map_req_state, &slot);
    CHECK_MAP_LOOKUP(rs, XDP_ABORTED);

    // THE ISSUE IS THAT ONCE TWO PACKETS ARE PAST THIS CHECK,
    // BOTH PACKETS WILL PERFORM AGGREGATION BUT ONLY ONE WILL BE SUCCESSFUL
    // IN THE COMPLETION CHECK.
    // HENCE THE COMPLETION CHECK MUST TAKE PLACE HERE (IE: BEFORE AGGREGATION)
    bpf_spin_lock(&rs->count_lock);
    if (rs->count < 0) {
        bpf_spin_unlock(&rs->count_lock);
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("dropping packet, completion flag set");
        #endif
        return XDP_PASS;
    }

    // Check for completion and increment count
    __s64 pk_count = ++rs->count;
    rs->count = (rs->num_workers == pk_count) ? -1 : pk_count;
    bpf_spin_unlock(&rs->count_lock);

    // Jump to user-supplied aggregation program
    bpf_tail_call(ctx, &map_aggregation_progs, CUSTOM_AGGREGATION_PROG_IDX);
    return XDP_ABORTED;

/*  SCALAR AGGREGATION EXAMPLE:

    // Get the int the worker responded with
    __u32 resp = bpf_ntohl(*((__u32 *) resp_msg->body));
    bpf_printk("Got packet with payload = %d for req ID = %d and seq num = %d", resp, resp_msg->hdr.req_id, resp_msg->hdr.seq_num);

    // Aggregate the value
    RESP_AGGREGATION_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &slot);
    if (!agg_resp)
        return XDP_ABORTED;

    const __u32 updated_resp = *agg_resp + resp;
    bpf_map_update_elem(&map_aggregated_response, &slot, &updated_resp, 0);

*/
}

SEC("tc")
int notify_gather_ctrl_prog(struct __sk_buff* skb) {
    // START_TIMER(""); // hot path takes around 3 to 5 us

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
	if ((void *)(iph + 1) > data_end || iph->protocol != IPPROTO_UDP)
		return TC_ACT_OK;

    udph = (struct udphdr*)(iph + 1);
    if ((void *)(udph + 1) > data_end)
        return TC_ACT_OK;

    __u32 payload_size = bpf_ntohs(udph->len) - sizeof(struct udphdr);
    char* payload = (char*) udph + sizeof(struct udphdr);
    if (payload_size != sizeof(sg_msg_t) || (void*) payload + payload_size > data_end)
        return TC_ACT_OK;

    sg_msg_t* resp_msg = (sg_msg_t*) payload;
    if (resp_msg->hdr.flags == SG_MSG_F_LAST_CLONED || resp_msg->hdr.flags != SG_MSG_F_PROCESSED
        || resp_msg->hdr.msg_type != GATHER_MSG)
        return TC_ACT_OK;

    __u32 req_id_copy = resp_msg->hdr.req_id;   // used after modifying pk pointers
    __u32 slot = GET_REQ_MAP_SLOT(req_id_copy);

    struct req_state* rs = bpf_map_lookup_elem(&map_req_state, &slot);
    CHECK_MAP_LOOKUP(rs, TC_ACT_SHOT);

    // If post_agg_count is -1, then it must have been set in the post aggregation
    // function if DISCARD_PK is specified and all required packets been aggregated.
    // If post_agg_count is N, then it was not modified after the increment in the post
    // aggregation function because ALLOW_PK was specified.
    __u8 completed_discard_pk = __sync_val_compare_and_swap(&rs->post_agg_count, -1, 0) == -1;
    __u8 completed_allow_pk = __sync_val_compare_and_swap(&rs->post_agg_count, rs->num_workers, 0) == rs->num_workers;
    if (completed_allow_pk || completed_discard_pk) {
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("!!! REQUEST %d COMPLETED WITH COUNT, NOTIFYING CTRL SOCKET !!!", resp_msg->hdr.req_id);
        #endif
        
        // Forward the final packet as usual, but mark it as cloned to avoid duplicate aggregation
        // Only do this if ALLOW_PK was set (otherwise we don't care about the packet)    
        if (completed_allow_pk) {
            static const unsigned char cloned_flag = SG_MSG_F_LAST_CLONED;
            bpf_skb_store_bytes(skb, SG_MSG_FLAGS_OFF, &cloned_flag, sizeof(unsigned char), BPF_F_RECOMPUTE_CSUM);
            bpf_clone_redirect(skb, skb->ifindex, 0);
        }
        
        // Notify the ctrl socket with the aggregated response in the packet body
        struct aggregation_entry* agg_entry = bpf_map_lookup_elem(&map_aggregated_response, &slot);
        CHECK_MAP_LOOKUP(agg_entry, TC_ACT_SHOT);

        #ifdef BPF_DEBUG_PRINT
        bpf_printk("!!! Final agg value in kernel = %d !!!", agg_entry->data[300]);
        #endif

        // Note: spinlock not needed for reading the aggregated data because 
        // at this point, any redundant packet trying to update the aggregated 
        // response is dropped before executing the aggregation logic
        
        const __u32 zero = 0;
        struct ctrl_sk_info* ctrl_sk = bpf_map_lookup_elem(&map_gather_ctrl_port, &zero);
        CHECK_MAP_LOOKUP(ctrl_sk, TC_ACT_SHOT);

        // Perform all-gather broadcast with final result
        if (ctrl_sk->all_gather) {
            static const unsigned char all_gather_msg_type = ALL_GATHER_MSG;
            bpf_skb_store_bytes(skb, SG_MSG_BODY_OFF, (char*)agg_entry->data, sizeof(RESP_VECTOR_TYPE) * RESP_MAX_VECTOR_SIZE, 0);
            bpf_skb_store_bytes(skb, SG_MSG_MSGTYPE_OFF, &all_gather_msg_type, sizeof(unsigned char), 0);
            struct send_worker_ctx send_worker_ctx_data = {
                .skb = skb,
            };
            bpf_for_each_map_elem(&map_workers, send_worker, &send_worker_ctx_data, 0);

            // Reset the destination IP address to localhost to receive the data on the ctrl socket
            static const __u32 LOCALHOST_IP = bpf_htonl(0x7F000001);
            bpf_skb_store_bytes(skb, IP_DEST_OFF, &LOCALHOST_IP, sizeof(__u32), 0);
        }

        if (!ctrl_sk->use_ring_buf) {
            // Notify ctrl sock by writing the aggregated value via packet
            __u16 ctrl_sk_port = ctrl_sk->port;
            bpf_skb_store_bytes(skb, UDP_DEST_OFF, &ctrl_sk_port, sizeof(__u16), BPF_F_RECOMPUTE_CSUM);

            if (!ctrl_sk->all_gather)
                bpf_skb_store_bytes(skb, SG_MSG_BODY_OFF, (char*)agg_entry->data, sizeof(RESP_VECTOR_TYPE) * RESP_MAX_VECTOR_SIZE, 0);

            clear_vector(agg_entry->data);
            return TC_ACT_OK;
        }

        // Otherwise, notify ctrl sock by writing the aggregated value to the ringbuf
        // Only reached if ringbuf mode is chosen and all_gather mode is enabled 
        // if ringbuf mode is enabled and all_gather mode is disabled, this is done in XDP

        // This is reached only iff ctrl_sk->use_ring_buf && !ctrl_sk->all_gather
        if (write_data_to_ringbuf(req_id_copy, (RESP_VECTOR_TYPE*) agg_entry->data) == -1)
            return TC_ACT_SHOT;

        clear_vector(agg_entry->data);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "GPL";
