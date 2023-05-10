#include "ebpf/Util.h"

namespace ebpf {

void Util::attachXDP(const Program& program, int ifindex, unsigned int xdpFlags) {
    if (bpf_program__type(program.get()) != BPF_PROG_TYPE_XDP)
        throw std::runtime_error{"Cannot attach non-XDP program using attachXDP()"};

    bpf_xdp_attach_opts opts;
    auto err = bpf_xdp_attach(ifindex, program.fd(), xdpFlags, &opts);
    
    if (err < 0) {
        std::ostringstream oss;
        oss << "ERR: ifindex " << ifindex << " link set xdp fd failed "
            << -err << " : " << strerror(-err);

        switch (-err) {
        case EBUSY:
        case EEXIST:
            oss << "Hint: XDP already loaded on device, use --force to swap/replace";
            break;
        case EOPNOTSUPP:
            oss << "Hint: Native-XDP not supported, use --skb-mode or --auto-mode\n";
            break;
        default:
            break;
        }
        throw std::runtime_error{oss.str()};
    }
}

void Util::dettachXDP(int ifindex, uint32_t xdpFlags) {
    uint32_t currProgId;
    std::ostringstream oss;

    auto err = bpf_xdp_query_id(ifindex, xdpFlags, &currProgId);
    if (err) {
        oss << "ERR: ifindex " << ifindex << " link get xdp fd failed "
            << -err << " : " << strerror(-err);
        throw std::runtime_error{oss.str()};
    }

    bpf_xdp_attach_opts opts;
    if ((err = bpf_xdp_detach(ifindex, xdpFlags, &opts)) < 0) {
        oss << "ERR: ifindex " << ifindex << " link set xdp fd failed "
            << -err << " : " << strerror(-err);
        throw std::runtime_error{oss.str()};
    }
}

} // close namespace ebpf
