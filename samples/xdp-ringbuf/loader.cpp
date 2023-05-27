// #include <bpf/bpf.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>

#include "sgbpf/ebpf/Program.h"
#include "sgbpf/ebpf/Map.h"
#include "sgbpf/ebpf/Object.h"
#include "sgbpf/ebpf/Hook.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <csignal>

extern "C" {
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
}

static int ifindex = -1;
static bool exiting = false;

void sigintHandlerDettach(int _) {
    (void) _;
    // ebpf::Util::dettachXDP(ifindex, 0);
    exiting = true;
}

int handle_rb_data(void *ctx, void *data, size_t data_sz)
{
    auto ctxString = (std::string*) ctx;
	// const struct event *e = data;
	// struct tm *tm;
	// char ts[32];
	// time_t t;

	// time(&t);
	// tm = localtime(&t);
	// strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	// printf("%-8s %-5s %-7d %-16s %s\n", ts, "EXEC", e->pid, e->comm, e->filename);
    std::cout << "got data from rb " << *((uint32_t*) data);
    std::cout << " ctx = " << *ctxString << std::endl;

	return 0;
}


int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "ERROR - Usage is: " << argv[0] << "<BPF_FILE> <INTERFACE>" << "\n";
        return 1;
    }
    
    ebpf::Object obj{argv[1]};

    auto prog = obj.findProgramByName("ringbuf_prog").value();
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

    // Attach the programs to the interface
    ifindex = ::if_nametoindex(argv[2]);
    if (!ifindex) {
        std::cerr << "Cannot resolve ifindex for interface name '" << argv[2] << "'\n";
        return 1;
    }
    signal(SIGINT, sigintHandlerDettach);

    auto ringbufmap = obj.findMapByName("map_ringbuf").value();

    std::string ctx = "some global context obj accessible to the callback";
    auto rb = ring_buffer__new(ringbufmap.fd(), handle_rb_data, &ctx, NULL);
    if (!rb) {
		fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
	}

    auto xdpHandle = ebpf::XDPHook::attach(ifindex, prog);
    
    while (!exiting) {
		auto err = ring_buffer__poll(rb, 10000 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}
	}

    std::cout << "Exitting prog" << std::endl;
    ebpf::XDPHook::detach(xdpHandle);
	ring_buffer__free(rb);

    return 0;
}
