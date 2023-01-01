// #include <bpf/bpf.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>

#include "ebpfpp/Program.h"
#include "ebpfpp/Map.h"
#include "ebpfpp/Object.h"
#include "ebpfpp/Util.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <csignal>

extern "C" {
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
}

static int ifindex = -1;


int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "ERROR - Usage is: " << argv[0] << "<BPF_FILE> <PROG_NAME> <INTERFACE>" << "\n";
        return 1;
    }
    
    // Attach the programs to the interface
    ifindex = ::if_nametoindex(argv[3]);
    if (!ifindex) {
        std::cerr << "Cannot resolve ifindex for interface name '" << argv[3] << "'\n";
        return 1;
    }
    
    ebpf::Object obj{argv[1]};

    auto prog = obj.findProgramByName("tc_ingress_filter_prog").value();
    std::cout << "Loaded TC prog with fd " << prog.fd() << " and name " << prog.name() << '\n';

    std::cout << "Prog type: " << bpf_program__type(prog.get()) << "\n";

    auto maps = obj.maps();
    for (const auto& m : maps) {
        std::cout << "Map " << m.name() << ", ";
    }
    std::cout << '\n';

    // TC API: https://github.com/libbpf/libbpf/commit/d71ff87a2dd7b92787719aab233767e9c74fbd48
    // SEE EXAMPLE AT THE BOTTOM
    bpf_tc_hook tcHook;
    memset(&tcHook, 0, sizeof(bpf_tc_hook));
    tcHook.attach_point = BPF_TC_INGRESS;
    tcHook.ifindex = ifindex;
    tcHook.sz = sizeof(bpf_tc_hook);    // this is needed for some reason, otherwise it fails

    auto err = bpf_tc_hook_create(&tcHook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		return 1;
	}

    bpf_tc_opts tcOpts;
    memset(&tcOpts, 0, sizeof(bpf_tc_opts));
    tcOpts.prog_fd = prog.fd();
    tcOpts.sz = sizeof(bpf_tc_opts);    // this is needed for some reason, otherwise it fails

    if (bpf_tc_attach(&tcHook, &tcOpts) < 0) {
        std::cerr << "Could not attach TC hook for ingress\n";
        return 1;    
    }

    auto localPortsMap = obj.findMapByName("map_local_ports").value();

    uint16_t port = htons(9212);
    bool is_open = true;
    localPortsMap.update(&port, &is_open, 0);

    port = htons(9921);
    localPortsMap.update(&port, &is_open, 0);

    uint16_t port2 = 9214;
    bool isOpen;
    if (localPortsMap.find(&port2, &isOpen)) {
        std::cout << "Port is open in map!" << std::endl;
    }
    
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10s);

    bpf_tc_detach(&tcHook, &tcOpts);
    bpf_tc_hook_destroy(&tcHook);

    return 0;
}
