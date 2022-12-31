#include "Util.h"

namespace ebpf {

void Util::attachXDP(const Program& program, int ifindex, unsigned int xdpFlags) {
    if (!bpf_program__is_xdp(program.get()))
        throw std::runtime_error{"Cannot attach non-XDP program using attachXDP()"};

    // see https://github.com/xdp-project/xdp-tutorial/blob/master/common/common_user_bpf_xdp.c#L19
    auto err = bpf_set_link_xdp_fd(ifindex, program.fd(), xdpFlags);
    
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

    auto err = bpf_get_link_xdp_id(ifindex, &currProgId, xdpFlags);
    if (err) {
        oss << "ERR: ifindex " << ifindex << " link get xdp fd failed "
            << -err << " : " << strerror(-err);
        throw std::runtime_error{oss.str()};
    }


    if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdpFlags)) < 0) {
        oss << "ERR: ifindex " << ifindex << " link set xdp fd failed "
            << -err << " : " << strerror(-err);
        throw std::runtime_error{oss.str()};
    }
}

} // close namespace ebpf
