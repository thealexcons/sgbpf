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
        std::cerr << "ERROR - Usage is: " << argv[0] << " <BPF_FILE> <PROG_NAME> <INTERFACE>" << "\n";
        return 1;
    }
    
    // Attach the programs to the interface
    ifindex = ::if_nametoindex(argv[3]);
    if (!ifindex) {
        std::cerr << "Cannot resolve ifindex for interface name '" << argv[3] << "'\n";
        return 1;
    }
    
    ebpf::Object obj{argv[1]};

    auto prog = obj.findProgramByName(argv[2]).value();
    std::cout << "Loaded SK prog with fd " << prog.fd() << " and name " << prog.name() << '\n';

    std::cout << "Prog type: " << bpf_program__type(prog.get()) << "\n";

    // TODO: attach program to network namespace
    // SEE http://tomoyo.osdn.jp/cgi-bin/lxr/source/tools/testing/selftests/bpf/prog_tests/sk_lookup.c?a=mips#L470
    // auto progLink = bpf_program__attach(prog.get());

    auto maps = obj.maps();
    for (const auto& m : maps) {
        std::cout << "Map " << m.name() << ", ";
    }
    std::cout << '\n';

    // Define the list of open ports to multiplex into the echo socket
    auto localPortsMap = obj.findMapByName("map_ports").value();
    const bool open = true;
    std::vector<uint16_t> ports = { 9212, 9213, 9214 };
    for (auto port : ports) {
        localPortsMap.update(&port, &open, 0);
    }

    // TODO: create the server socket
    
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10s);

    bpf_link__destroy(progLink);    // this will dettach and destroy the FD (not sure if needed)

    return 0;
}
