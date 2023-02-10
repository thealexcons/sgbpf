#include "Hook.h"
#include "Program.h"

#include <iostream>

extern "C" {
#include <fcntl.h>
#include <unistd.h>
}

namespace ebpf {

////////// XDP programs //////////

XDPHook::Handle XDPHook::attach(int ifindex, const Program& program) {
    bpf_xdp_attach(ifindex, program.fd(), 0, 0);
    return XDPHook::Handle{ .ifindex = ifindex, .progFd = program.fd() };
}


void XDPHook::detach(XDPHook::Handle& handle) {
    bpf_xdp_detach(handle.ifindex, 0, 0);
}



////////// TC programs //////////

TCHook::Handle TCHook::attach(int ifindex, const Program& prog, bpf_tc_attach_point attachPoint) {
    TCHook::Handle handle;
    memset(&handle, 0, sizeof(TCHook::Handle));

    handle.hook.attach_point = attachPoint;
    handle.hook.ifindex = ifindex;
    handle.hook.sz = sizeof(bpf_tc_hook);

    auto err = bpf_tc_hook_create(&handle.hook);
	if (err && err != -EEXIST) {
		std::cerr << "Failed to create TC hook: " << err << "\n";
		exit(EXIT_FAILURE);
	}

    handle.opts.prog_fd = prog.fd();
    handle.opts.sz = sizeof(bpf_tc_opts);

    if (bpf_tc_attach(&handle.hook, &handle.opts) < 0) {
        std::cerr << "Could not attach TC hook for egress\n";
        exit(EXIT_FAILURE);    
    }

    return handle;
}


void TCHook::detach(TCHook::Handle& handle) {
    bpf_tc_detach(&handle.hook, &handle.opts);
    bpf_tc_hook_destroy(&handle.hook);
}



////////// Socket programs //////////

SocketHook::Handle attach(const Program& prog) {
    int netFd = open(SocketHook::NET_NAMESPACE, O_RDONLY);
    if (netFd < 0) {
        std::cerr << "Could not open network namespace for socket attaching\n";
        exit(EXIT_FAILURE);
    }
    close(netFd);
    
    SocketHook::Handle handle;
    handle.link = bpf_program__attach_netns(prog.get(), netFd);
    return handle;
}


void SocketHook::detach(SocketHook::Handle& handle) {
    bpf_link__destroy(handle.link);
}


} // close namespace ebpf
