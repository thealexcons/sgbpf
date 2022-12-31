#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>

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
    bpf_set_link_xdp_fd(ifindex, -1, 0);
}


int main(int argc, char** argv) {
    if (argc < 4) {
        std::cerr << "ERROR - Usage is: " << argv[0] << " <BPF_FILE> <PROG_SECTION_NAME> <INTERFACE>" << "\n";
        return 1;
    }
    
    // Open and load the BPF program
    auto obj = bpf_object__open(argv[1]);
    bpf_object__load(obj);

    auto prog = bpf_object__find_program_by_title(obj, argv[2]);
    auto progFd = bpf_program__fd(prog);
    auto progName = bpf_program__name(prog);
    std::cout << "Loaded XDP prog with fd " << progFd << " and name " << progName << '\n';


    // Print all the maps in the program
    bpf_map* map;
    bpf_object__for_each_map(map, obj) {
        std::cout << "Map: '" << bpf_map__name(map) << "', ";
    }
    std::cout << '\n';


    // Add some blocked ports to the map 
    auto portsMap = bpf_object__find_map_by_name(obj, "map_local_ports");
    auto portsMapFd = bpf_map__fd(portsMap);

    bool open = true;

    uint16_t port = htons(9212);
    bpf_map_update_elem(portsMapFd, &port, &open, BPF_NOEXIST);

    port = htons(9921);
    bpf_map_update_elem(portsMapFd, &port, &open, BPF_NOEXIST);


    // Attach the XDP program to the interface
    ifindex = ::if_nametoindex(argv[3]);
    if (!ifindex) {
        std::cerr << "Cannot resolve ifindex for interface name '" << argv[3] << "'\n";
        return 1;
    }
    signal(SIGINT, sigintHandlerDettach);

    bpf_set_link_xdp_fd(ifindex, progFd, 0);

    using namespace std::chrono_literals;
    std::this_thread::sleep_for(10s);

    bpf_set_link_xdp_fd(ifindex, -1, 0);

    return 0;
}
