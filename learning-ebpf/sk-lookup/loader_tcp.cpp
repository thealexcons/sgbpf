// #include <bpf/bpf.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
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

#define MAX_CLIENTS 10

int main(int argc, char** argv) {
    // sudo ./loader sk_lookup.bpf.o dispatch_prog lo
    if (argc < 4) {
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
    int skfd = socket(AF_INET, SOCK_STREAM, 0);
    if (skfd < 0) {
        std::cerr << "Could not create socket\n";
        return 1;  
    }
    int opt = 1;
    if (setsockopt(skfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Bind socket to port
    sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_addr.s_addr = INADDR_ANY;
    servAddr.sin_port = htons(9200);

    if ( bind(skfd, (const struct sockaddr *) &servAddr, sizeof(servAddr)) < 0 ) {
        std::cerr << "Could not bind socket\n";
        return 1;  
    }
    
    if (listen(skfd, MAX_CLIENTS) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

        // Add the socket to the BPF map
    auto socketMap = obj.findMapByName("map_socket").value();
    const int zero = 0;
    int sockfd = static_cast<int>(skfd);
    socketMap.update(&zero, &sockfd, BPF_NOEXIST); // looks like my version of kernel does not support this??

    std::cout << "added skfd to map:" << skfd << std::endl;
    int verifyFd = -2;
    socketMap.find(&zero, &verifyFd);
    std::cout << "verify map sk: " << verifyFd << std::endl;

    // Accept and handle incoming connections
    while (1) {
        int client_fd;
        int addrlen = sizeof(sockaddr_in);
        if ((client_fd = accept(skfd, (struct sockaddr *)&servAddr, (socklen_t *)&addrlen)) < 0) {
            perror("accept failed");
            exit(EXIT_FAILURE);
        }

        // Read data from client and echo it back
        while (1)
        {
            char buffer[1024] = {0};
            int num_bytes = read(client_fd, buffer, sizeof(buffer));
            if (num_bytes < 0) {
                perror("read failed");
                exit(EXIT_FAILURE);
            }
            else if (num_bytes == 0) {
                break;
            }
            else {
                std::stringstream ss;
                ss << "THANK YOU FOR YOUR MSG: " << buffer;
                std::string s = ss.str();
                write(client_fd, s.c_str(), strnlen(s.c_str(), 1024));
            }
        }

        // Close connection
        close(client_fd);
    }

    bpf_link__destroy(progLink);    // this will dettach and destroy the FD (not sure if needed)
    close(skfd);

    return 0;
}
