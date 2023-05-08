#ifndef CUSTOM_AGGREGATION_BPF_H
#define CUSTOM_AGGREGATION_BPF_H

#include "bpf_h/helpers.bpf.h"

static inline enum xdp_action aggregate(sg_msg_t* msg, RESP_VECTOR_TYPE* current_data) {
    
    for (__u32 i = 0; i < RESP_MAX_VECTOR_SIZE; ++i) {
        current_data[i] += ((RESP_VECTOR_TYPE*)msg->body)[i];
    }

    return XDP_PASS;
}


#endif // CUSTOM_AGGREGATION_BPF_H
