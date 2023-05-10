#ifndef _SGBPF_EBPF_UTIL_H
#define _SGBPF_EBPF_UTIL_H

#include "Program.h"

#include <sstream>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"
#include <linux/bpf.h>

namespace ebpf {

struct Util {

    static void attachXDP(const Program& program, int ifindex, unsigned int xdpFlags);

    static void dettachXDP(int ifindex, uint32_t xdpFlags);

};

} // close namespace ebpf

#endif // !_SGBPF_EBPF_UTIL_H