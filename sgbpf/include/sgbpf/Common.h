#ifndef _SGBPF_COMMON_H
#define _SGBPF_COMMON_H

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

// Defines common constants and structures between eBPF and user-space programs

#define MTU_SIZE 1500
#define MAX_SOCKETS_ALLOWED 8192
#define MAX_ACTIVE_REQUESTS_ALLOWED 8192

typedef enum worker_resp_status
{
    WAITING_FOR_RESPONSE = 0,
    RECEIVED_RESPONSE
} worker_resp_status_t;


// Shared types between user space and BPF kernel programs are prefixed with ubpf_
// Note: cannot use any BPF or uapi types

typedef struct worker_info {
    unsigned int    worker_ip;      // The remote worker IP address
    unsigned short  worker_port;    // The remote worker port (likely fixed, except for local testing)
    unsigned short  app_port;       // The assigned port on the application to listen for responses (likely not needed in the long term)
} worker_info_t;

typedef enum sg_msg_flags 
{
    SG_MSG_F_EMPTY       = 0,       
    SG_MSG_F_PROCESSED,     // The packet has been processed by the gather program
    SG_MSG_F_LAST_CLONED,   // The last packet of the request, which is cloned
    
} sg_msg_flags_t;

typedef struct __attribute__((packed)) {
    // Header
    struct __attribute__((packed)) sg_msg_hdr {
        unsigned int    req_id;         // The request ID
        unsigned int    seq_num;        // The sequence number in a multi-packet msg
        unsigned int    num_pks;        // The number of packets in a multi-packet msg (used as waitN value in egress msg)
        unsigned int    body_len;       // The length of the body in bytes
        unsigned char   msg_type;       // The message type (SCATTER or GATHER)
        unsigned char   flags;          // Extra flags
    } hdr;

    // Body
    char body[MTU_SIZE - sizeof(struct iphdr) - sizeof(struct udphdr) - sizeof(struct sg_msg_hdr)];
} sg_msg_t;

#define BODY_LEN (sizeof(sg_msg_t) - __builtin_offsetof(sg_msg_t, body))

#define VECTOR_RESPONSE 1

#ifdef VECTOR_RESPONSE
#define RESP_VECTOR_TYPE uint32_t
#define RESP_MAX_VECTOR_SIZE (BODY_LEN / sizeof(RESP_VECTOR_TYPE))      // 363 4-byte elements
#define RESP_AGGREGATION_TYPE RESP_VECTOR_TYPE[RESP_MAX_VECTOR_SIZE]

#define EBPF_MAX_STACK_SIZE 512
#define VECTOR_AGGREGATION_CHUNK (EBPF_MAX_STACK_SIZE / sizeof(RESP_VECTOR_TYPE) - 10)

#define RESP_VECTOR_MAP_ENTRIES (RESP_MAX_VECTOR_SIZE / VECTOR_AGGREGATION_CHUNK + 1)

#else
#define RESP_AGGREGATION_TYPE unsigned int
#endif

#define CUSTOM_AGGREGATION_PROG_IDX 0

typedef enum msg_type 
{
    SCATTER_MSG = 0,
    GATHER_MSG,
    ALL_GATHER_MSG
} msg_type_t;


#define SG_CLEAN_REQ_MSG_MAGIC 0x649CB338

typedef struct __attribute__((packed)) sg_clean_req_msg {
    unsigned int    magic;
    unsigned int    req_id;    
} sg_clean_req_msg_t; 

#endif // _SGBPF_COMMON_H
