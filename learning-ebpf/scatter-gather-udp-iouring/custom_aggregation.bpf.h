#ifndef CUSTOM_AGGREGATION_BPF_H
#define CUSTOM_AGGREGATION_BPF_H

#include "helpers.bpf.h"

static inline enum xdp_action aggregate(sg_msg_t* msg, RESP_VECTOR_TYPE* current_data) {
    bpf_printk("FROM AGGREGATE()");
    return XDP_PASS;
}


#endif // CUSTOM_AGGREGATION_BPF_H
