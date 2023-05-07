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
#include "helpers.bpf.h"
#include "maps.bpf.h"

// #define CUSTOM_AGGREGATION 1

#ifdef CUSTOM_AGGREGATION
#include "custom_aggregation.bpf.h"
#endif // CUSTOM_AGGREGATION

static const __u32 ZERO_IDX = 0;


// Offsets for specific fields in the packets
#define IP_DEST_OFF (ETH_HLEN + offsetof(struct iphdr, daddr))
#define UDP_DEST_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_SRC_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define SG_MSG_FLAGS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + offsetof(sg_msg_t, hdr) + offsetof(struct sg_msg_hdr, flags))
#define SG_MSG_BODY_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + offsetof(sg_msg_t, body))

static void __always_inline clone_and_send_packet(struct __sk_buff* skb, 
                                                  struct iphdr* iph, 
                                                  struct udphdr* udph,
                                                  uint32_t worker_ip,   // Network byte order
                                                  uint16_t worker_port, // Network byte order
                                                  uint16_t app_port)    // Network byte order
{
    (void) iph;
    (void) udph;

    #ifdef BPF_DEBUG_PRINT
    char str[16] = "";
    __u32 ip_addr_h = bpf_ntohl(worker_ip);
	BPF_SNPRINTF(str, sizeof(str), "%d.%d.%d.%d",
		(ip_addr_h >> 24) & 0xff, (ip_addr_h >> 16) & 0xff,
		(ip_addr_h >> 8) & 0xff, ip_addr_h & 0xff);

    bpf_printk("Sending packet to %s:%d", str, bpf_ntohs(worker_port));
    #endif

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
        if ((void*) payload + payload_size > data_end) {
            // data_end - data = MTU size + ETH_HDR (14 bytes)
            bpf_printk("Invalid packet size: payload might be larger than MTU");
            return TC_ACT_OK;
        }

        sg_msg_t* sgh = (sg_msg_t*) payload; 
        if (sgh->hdr.msg_type != SCATTER_MSG)
            return TC_ACT_OK;

        // Configure request settings from the provided flags (completion policy)
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("Got SCATTER request");
        #endif

        __u32 slot = GET_REQ_MAP_SLOT(sgh->hdr.req_id);

        struct completion_policy_info* cpi = bpf_map_lookup_elem(&map_req_completion_policy, &slot);
        if (!cpi)
            return XDP_ABORTED;

        // Lazy cleanup of map entry if previous entry used the SG_MSG_F_WAIT_ANY policy
        // if (__glibc_unlikely(cpi->policy == SG_MSG_F_WAIT_ANY)) {
        //     __u64* count = bpf_map_lookup_elem(&map_workers_resp_count, &slot);
        //     if (!count)
        //         return XDP_ABORTED;
        //     *count = 0; // UB if num active requests > MAX_ACTIVE_REQUESTS
        // }
        cpi->policy = sgh->hdr.flags;
        cpi->waitN = (sgh->hdr.flags == SG_MSG_F_WAIT_N || sgh->hdr.flags == SG_MSG_F_WAIT_ALL) ? sgh->hdr.num_pks : 0;

        #ifdef BPF_DEBUG_PRINT
        if (sgh->hdr.flags == SG_MSG_F_WAIT_ANY) {
            bpf_printk("Got WAIT_ANY completion policy");
        } else if (sgh->hdr.flags == SG_MSG_F_WAIT_N) {
            bpf_printk("Got WAIT_N completion policy with %d workers to wait", sgh->hdr.num_pks);
        } else {
            bpf_printk("Got default WAIT_ALL completion policy");
        }
        #endif
        // start timer for request
        /*
        struct req_timing* rqt = bpf_map_lookup_elem(&map_req_timing, &slot);
        if (!rqt)
            return TC_ACT_OK;

        rqt->start_ns = bpf_ktime_get_ns();
        rqt->timeout_ns = 10 * 1000000; // default timeout of 10ms
        */
        // Instead of using a syscall to set the timeout for each request, maybe
        // include the timeout value (in micros or millis) in the header when sent out

        // Clone the outgoing packet to all the registered workers
        struct send_worker_ctx data = {
            .skb = skb,
            .ip_header = iph,
            .udp_header = udph,
        };
        bpf_for_each_map_elem(&map_workers, send_worker, &data, 0);

#ifdef BPF_DEBUG_PRINT
        bpf_printk("Finished SCATTER request");
#endif
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

// static __u64 count_workers(void* map, __u32* idx, worker_info_t* worker, __u32* count) {
//     if (!worker || worker->app_port == 0)
//         return 1;

//     (*count)++;
//     return 0;
// }

// static __u64 reset_worker_status(void* map, worker_info_t* worker, worker_resp_status_t* status, __u8* waiting) {
//     if (!status)
//         return 1;

//     worker_resp_status_t updated_status = WAITING_FOR_RESPONSE;
//     bpf_map_update_elem(map, worker, &updated_status, 0);
//     return 0;
// }

// inline static void cleanup_request_state(__u32 reqId) {
//     // TODO cleanup all state for the given request
// }

// // TODO have time out check in userspace, if timed out, invoke syscall to cleanup
// inline static __u8 request_timed_out(struct req_timing* rqt) {
//     return (bpf_ktime_get_ns() - rqt->start_ns > rqt->timeout_ns);
// } 

inline static void reset_aggregated_vector(RESP_VECTOR_TYPE* agg_vector) {
    // ebpf sets a maximum size for memset, so we need to "hack" around it
    #define MAX_CONTIGUOUS_MEMSET_SIZE 256

    #pragma clang loop unroll(full)
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        if (__glibc_unlikely(MOD_POW2(i, MAX_CONTIGUOUS_MEMSET_SIZE) == 0)) {
            barrier(); // dummy instruction needed to break the memset, need something cheap
        }
        agg_vector[i] = 0;
    }
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

    // Check for time-out
    /*
    __u32 slot = GET_REQ_MAP_SLOT(resp_msg->hdr.req_id);
    struct req_timing* rqt = bpf_map_lookup_elem(&map_req_timing, &slot);
    if (!rqt)
        return XDP_ABORTED;

    if (request_timed_out(rqt)) {
        // TODO perform cleanup
        cleanup_request_state(resp_msg->hdr.req_id); // or just pass in the map ptrs directly
        bpf_printk("Request %d timed out!!!!", resp_msg->hdr.req_id);
        return XDP_DROP;
    }*/

    // If this is a multi-packet message, forward the packet without aggregation
    if (resp_msg->hdr.num_pks > 1 && resp_msg->hdr.seq_num <= resp_msg->hdr.num_pks) {
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("[MP] [Worker %d] Got packet with req ID = %d and seq num = %d", bpf_ntohs(worker.worker_port), resp_msg->hdr.req_id, resp_msg->hdr.seq_num);
        #endif
        return XDP_PASS;
    }

    // Single-packet response aggregation:
    #ifdef BPF_DEBUG_PRINT
    bpf_printk("processing msg from worker %d with flags %d", bpf_ntohs(worker.worker_port), resp_msg->hdr.flags);
    #endif
    
    if (resp_msg->hdr.flags == SG_MSG_F_LAST_CLONED) {
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("dropping cloned (final) packet from worker %d", bpf_ntohs(worker.worker_port));
        #endif
        return XDP_PASS;
    }

    // bpf_printk("resp_msg->hdr.req_id = %d", resp_msg->hdr.req_id);
    // bpf_printk("body[33] = %d", ((RESP_VECTOR_TYPE *)resp_msg->body)[33]);
    // bpf_printk("--------------------------------------------");

    bpf_tail_call(ctx, &map_aggregation_progs, CUSTOM_AGGREGATION_PROG);

    // DISCUSS: for performance, maybe just treat it as a function instead
    // of a full program change to avoid overhead of re-parsing packet
    // as a raw function call, this works
#ifdef CUSTOM_AGGREGATION
    aggregate(resp_msg, agg_resp);
    AGGREGATION_PROG_OUTRO(resp_msg);
#endif // CUSTOM_AGGREGATION


#ifdef VECTOR_RESPONSE

    RESP_VECTOR_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
    if (!agg_resp)
        return XDP_ABORTED;

    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        agg_resp[i] += ((RESP_VECTOR_TYPE *)resp_msg->body)[i];
    }

#else
    // Get the int the worker responded with
    __u32 resp = bpf_ntohl(*((__u32 *) resp_msg->body));
    bpf_printk("Got packet with payload = %d for req ID = %d and seq num = %d", resp, resp_msg->hdr.req_id, resp_msg->hdr.seq_num);

    // Aggregate the value
    RESP_AGGREGATION_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
    if (!agg_resp)
        return XDP_ABORTED;

    // CAN THIS BE REPLACED WITH *agg_resp = *agg_resp + resp; without the update call
    // like in the vector version? it would make the aggregation API consistent
    const __u32 updated_resp = *agg_resp + resp;
    bpf_map_update_elem(&map_aggregated_response, &ZERO_IDX, &updated_resp, 0);

#endif

    AGGREGATION_PROG_OUTRO(ctx, resp_msg); 
}

#define ATOMIC_LOAD_HACK(ptr, dest) asm volatile("lock *(u64 *)(%0+0) += %1" : "=r"(dest) : "r"(ZERO_IDX), "0"(ptr));

static inline __u8 num_workers_satisfied(__u64* count, struct completion_policy_info* cpi) {
    // Note: if the function returns true, the value at count will atomically be 
    // reset to zero too, EXCEPT if the policy is SG_MSG_F_WAIT_ANY. Hence the lazy
    // cleanup in the scatter program

    // Getting to this implies at least one packet has arrived, so WAIT_ANY is always satisfied
    if (cpi->policy == SG_MSG_F_WAIT_ANY) {
        __atomic_exchange_n(count, 0, __ATOMIC_ACQ_REL);
        return 1;
    }
    // __sync_store_n(count, 0, __ATOMIC_RELEASE);
    // supported atomic ops in ebpf:
    // https://patchwork.ozlabs.org/project/gcc/patch/20211026122539.186747-1-guillermo.e.martinez@oracle.com/

    __u64 num_workers = cpi->waitN;
    if (cpi->policy == SG_MSG_F_WAIT_ALL) {
        return __atomic_compare_exchange_n(count, &num_workers, 0, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE);
    }
    else if (cpi->policy == SG_MSG_F_WAIT_N) {
        // check >= num_workers
        // Do we drop any packets after the nth? ask marios
        // might be able to do this using per-packet metadata and marking their count

        // This is not in a CAS loop, as it is sufficient to check for stale values
        // since the count is monotonically increasing throughout the request lifetime

        // maybe carry the pk count in the skb like before?
        // then each pk definitely has a non-changing count and we can drop
        // anything after
        // and can use xchg

        // THIS IS STILL ALLOWING MULTPLE CTRL SK NOTIFS!!!
        __u64* c;
        ATOMIC_LOAD_HACK(count, c);
        if (*c >= num_workers) {
            __atomic_exchange_n(count, 0, __ATOMIC_ACQ_REL);
            return 1;
        }
    }
    return 0;
}

// required if we want to get aggregated result using socket read
// not used by multi-packet messages
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
    if (resp_msg->hdr.flags == SG_MSG_F_LAST_CLONED || resp_msg->hdr.flags != SG_MSG_F_PROCESSED
        || resp_msg->hdr.msg_type != GATHER_MSG)
        return TC_ACT_OK;

    // Check for time-out
    __u32 slot = GET_REQ_MAP_SLOT(resp_msg->hdr.req_id);
    
    /*
    struct req_timing* rqt = bpf_map_lookup_elem(&map_req_timing, &slot);
    if (!rqt)
        return TC_ACT_OK;
    if (request_timed_out(rqt)) {
        // TODO perform cleanup
        cleanup_request_state(resp_msg->hdr.req_id); // or just pass in the map ptrs directly
        bpf_printk("Request %d timed out!!!!", resp_msg->hdr.req_id);
        return TC_ACT_SHOT;
    }
    */

    // Lightweight XDP -> TC communication design pattern: data follows the packet
    //    set field in XDP for skb, read in TC (data follows the packet)
    //  atomic add in XDP, read direct from packet
    // __u32* pk_count = (void*)(unsigned long) skb->data_meta;
    // if (pk_count + 1 > (void*)(unsigned long) skb->data) {
    //     return TC_ACT_OK;
    // }
    struct completion_policy_info* cpi = bpf_map_lookup_elem(&map_req_completion_policy, &slot);
    if (!cpi)
        return TC_ACT_SHOT;

    __u64* count = bpf_map_lookup_elem(&map_workers_resp_count, &slot);
    if (!count)
        return TC_ACT_SHOT;

    // Check completion satisfied
    if (num_workers_satisfied(count, cpi)) {
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("!!! REQUEST %d COMPLETED, NOTIFYING CTRL SOCKET !!!", resp_msg->hdr.req_id);
        #endif

        __u16* ctrl_sk_port = bpf_map_lookup_elem(&map_gather_ctrl_port, &ZERO_IDX);
        if (!ctrl_sk_port)
            return TC_ACT_SHOT;
        
        // Forward the final packet as usual, but mark it as cloned to avoid duplicate aggregation
        static const unsigned char cloned_flag = SG_MSG_F_LAST_CLONED;
        bpf_skb_store_bytes(skb, SG_MSG_FLAGS_OFF, &cloned_flag, sizeof(unsigned char), BPF_F_RECOMPUTE_CSUM);
        bpf_clone_redirect(skb, skb->ifindex, 0);

        // Notify the ctrl socket with the aggregated response in the packet body
        RESP_VECTOR_TYPE* agg_resp = bpf_map_lookup_elem(&map_aggregated_response, &ZERO_IDX);
        if (!agg_resp)
            return TC_ACT_SHOT;

        bpf_skb_store_bytes(skb, SG_MSG_BODY_OFF, (char*)agg_resp, sizeof(RESP_VECTOR_TYPE) * RESP_MAX_VECTOR_SIZE, BPF_F_RECOMPUTE_CSUM);
        bpf_skb_store_bytes(skb, UDP_DEST_OFF, ctrl_sk_port, sizeof(*ctrl_sk_port), BPF_F_RECOMPUTE_CSUM);

        // Reset the aggregated vector from this request
        #ifdef BPF_DEBUG_PRINT
        bpf_printk("reset aggregation to 0");
        #endif

        // NOTE: alternatively, we could consider a lazy cleanup: cleanup the resources
        // for a request when a new request is launched and is meant to take the old request's place
        reset_aggregated_vector(agg_resp);
    }

    return TC_ACT_OK;
}


char LICENSE[] SEC("license") = "GPL";