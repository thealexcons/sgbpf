// #include <bpf/bpf.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>

#include "sgbpf/ebpf/Program.h"
#include "sgbpf/ebpf/Map.h"
#include "sgbpf/ebpf/Object.h"
#include "sgbpf/ebpf/Util.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <csignal>

extern "C" {
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
}

static int ifindex = -1;


int main(int argc, char** argv) {
    // sudo ./loader sk_lookup.bpf.o dispatch_prog lo
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

    // SEE http://tomoyo.osdn.jp/cgi-bin/lxr/source/tools/testing/selftests/bpf/prog_tests/sk_lookup.c?a=mips#L470
    int netFd = open("/proc/self/ns/net", O_RDONLY);
    if (netFd < 0) {
        std::cerr << "Could not open network namespace\n";
        return 1;  
    }

    auto progLink = bpf_program__attach_netns(prog.get(), netFd);
    close(netFd);


    // Define the list of open ports to multiplex into the echo socket
    auto localPortsMap = obj.findMapByName("map_ports").value();
    const bool open = true;
    std::vector<uint16_t> ports = { 9212, 9213, 9214 };
    for (auto port : ports) {
        localPortsMap.update(&port, &open, 0);
    }


    // Create the server socket    
    int skfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (skfd < 0) {
        std::cerr << "Could not create socket\n";
        return 1;  
    }

    // Setup server
    sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = INADDR_ANY;
    servAddr.sin_port = htons(9200);

    if ( bind(skfd, (const struct sockaddr *) &servAddr, sizeof(servAddr)) < 0 ) {
        std::cerr << "Could not bind socket\n";
        return 1;  
    }

    // Add the socket to the BPF map
    auto socketMap = obj.findMapByName("map_socket").value();
    const int zero = 0;
    auto sockfd = static_cast<uint64_t>(skfd);
    socketMap.update(&zero, &sockfd, BPF_NOEXIST);

    std::cout << "added skfd to map:" << skfd << std::endl;
    int verifyFd = -2;
    socketMap.find(&zero, &verifyFd);
    std::cout << "verify map sk: " << verifyFd << std::endl;
    
    sockaddr_in clientAddr;
    memset(&clientAddr, 0, sizeof(clientAddr));
    socklen_t len = sizeof(clientAddr);
    char buffer[1024];
    while (1) {

        /*
            Note: the incoming packets to the server socket port + all the other
            ports added to the map will be received below.

            However, sendto() only sends to clients that directly sent to this port.
            TODO: is this because this example uses UDP? need to test with TCP

            Send UDP packets to test:
            $ echo "hi" | nc -u localhost <PORT>
        */

        int n = recvfrom(skfd, buffer, sizeof(buffer), MSG_WAITALL, 
                    (struct sockaddr *) &clientAddr, &len);
        
        buffer[n] = '\0';
        std::string data{buffer, n-1};
        std::cout << "Got: '" << data << "' from client\n";

        std::string resp = "ack";
        sendto(skfd, resp.c_str(), strlen(resp.c_str()), MSG_CONFIRM,
            (const struct sockaddr*) &clientAddr, len);

        break;
    }

    bpf_link__destroy(progLink);    // this will dettach and destroy the FD (not sure if needed)
    close(skfd);

    return 0;
}
