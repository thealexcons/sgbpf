#ifndef _EBPFPP_HOOK_H
#define _EBPFPP_HOOK_H

#include <string>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

namespace ebpf {

////////// XDP programs //////////

struct XDPHook
{
    struct Handle 
    {
        int ifindex;
        int progFd;
    };

    static Handle attach(int ifindex, const Program& program);

    static void detach(Handle& handle);
};


////////// TC programs //////////

struct TCHook
{
    struct Handle 
    {
        bpf_tc_hook hook;
        bpf_tc_opts opts;
    };
    
    static Handle attach(int ifindex, const Program& prog, bpf_tc_attach_point attachPoint);

    static void detach(Handle& handle);
};


////////// Socket programs //////////

struct SocketHook
{
    constexpr static auto NET_NAMESPACE = "/proc/self/ns/net";

    struct Handle
    {
        bpf_link* link;
    };

    static Handle attach(const Program& prog);

    static void detach(Handle& handle);
};


} // close namespace ebpf

#endif // !_EBPFPP_HOOK_H