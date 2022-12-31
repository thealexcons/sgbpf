// #include <bpf/bpf.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>

#include "../../ebpfpp/include/ebpfpp/Program.h"
#include "../../ebpfpp/include/ebpfpp/Map.h"
#include "../../ebpfpp/include/ebpfpp/Object.h"
#include "../../ebpfpp/include/ebpfpp/Util.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <csignal>

extern "C" {
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
}

static int ifindex = -1;

void sigintHandlerDettach(int _) {
    (void) _;
    ebpf::Util::dettachXDP(ifindex, 0);
}


int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "ERROR - Usage is: " << argv[0] << "<BPF_FILE> <INTERFACE>" << "\n";
        return 1;
    }
    
    ebpf::Object obj{argv[1]};

    auto prog = obj.findProgramByName("rx_filter_prog").value();
    std::cout << "Loaded XDP prog with fd " << prog.fd() << " and name " << prog.name() << '\n';

    auto maps = obj.maps();
    for (const auto& m : maps) {
        std::cout << "Map " << m.name() << ", ";
    }
    std::cout << '\n';

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

    // Attach the programs to the interface
    ifindex = ::if_nametoindex(argv[2]);
    if (!ifindex) {
        std::cerr << "Cannot resolve ifindex for interface name '" << argv[2] << "'\n";
        return 1;
    }
    signal(SIGINT, sigintHandlerDettach);

    ebpf::Util::attachXDP(prog, ifindex, 0);
    
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10s);

    ebpf::Util::dettachXDP(ifindex, 0);

    return 0;
}
