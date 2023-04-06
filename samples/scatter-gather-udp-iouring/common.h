#ifndef COMMON_H
#define COMMON_H


// Defines common constants and structures between eBPF and user-space programs

#define BODY_LEN 256
#define MAX_SOCKETS_ALLOWED 1024
#define RESP_AGGREGATION_TYPE unsigned int


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

typedef struct __attribute__((packed)) {
    unsigned int    req_id;         // The request ID
    unsigned int    seq_num;        // The sequence number in a multi-packet msg
    unsigned int    num_pks;        // The number of packets in a multi-packet msg
    unsigned int    body_len;       // The length of the body in bytes
    unsigned char   msg_type;       // The message type (SCATTER or GATHER)
    unsigned char   flags;          // Extra flags
    char            body[BODY_LEN]; // The body data, up to 256 bytes
} sg_msg_t;

typedef enum msg_type 
{
    SCATTER_MSG = 0,
    GATHER_MSG
} msg_type_t;

#endif // COMMON_H
