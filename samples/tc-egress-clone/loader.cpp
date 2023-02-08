// #include <bpf/bpf.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <sstream>
#include <fstream>

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

using namespace std::chrono_literals;


static int ifindex = -1;
static const uint16_t PORT = 9223;


struct Destination {
    std::string ipAddr;
    uint32_t    ipAddrNetBytes;
    uint16_t    port;
    uint16_t    portNetBytes;
};

std::vector<Destination> readWorkerDestinations(const std::string& fileName) {
    std::vector<Destination> dests;

    std::ifstream file(fileName);
    if (file.is_open()) {
        std::string line;
        while (std::getline(file, line) && !line.empty()) {
            Destination dest;
            char *ptr;
            ptr = strtok(line.data(), ":");
            if (!ptr)
                throw std::runtime_error{"Invalid workers config file"};
                
            dest.ipAddr = ptr;

            // Convert the IP string to network-order bytes
            uint32_t ip_bytes;
            inet_pton(AF_INET, ptr, &ip_bytes);
            dest.ipAddrNetBytes = ip_bytes;

            ptr = strtok(NULL, ":");
            if (!ptr)
                throw std::runtime_error{"Invalid workers config file"};
            
            std::string port{ptr};
            dest.port = static_cast<uint16_t>(std::stoi(port));
            dest.portNetBytes = htons(dest.port);

            dests.emplace_back(std::move(dest));
        }
        file.close();
    }

    return dests;
}


void scatterMessage(int skfd, const sockaddr_in* servAddr, const std::string& msg) {
    if (sendto(skfd, msg.c_str(), msg.size(), 0, (const sockaddr *)&servAddr, sizeof(sockaddr_in)) < 0)
    { 
        std::cerr << "Failed: sendto()\n";
        return;
    }
    std::cout << "Send scatter message\n";
}


int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "ERROR - Usage is: " << argv[0] << " <BPF_FILE> <PROG_NAME> <INTERFACE> <WORKERS_CFG>" << "\n";
        return 1;
    }

    // Read the worker destinations
    auto workerDestinations = readWorkerDestinations(argv[4]);
    
    // Attach the programs to the interface
    ifindex = ::if_nametoindex(argv[3]);
    if (!ifindex) {
        std::cerr << "Cannot resolve ifindex for interface name '" << argv[3] << "'\n";
        return 1;
    }
    
    ebpf::Object obj{argv[1]};

    auto prog = obj.findProgramByName(argv[2]).value();
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
    memset(&tcHook, 0, sizeof(bpf_tc_hook));    // also needed
    tcHook.attach_point = BPF_TC_EGRESS;
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
        std::cerr << "Could not attach TC hook for egress\n";
        return 1;    
    }

    // Register the application's outgoing port
    auto applicationPortMap = obj.findMapByName("map_application_port").value();
    const uint32_t idx = 0;
    const auto portNetBytes = htons(PORT);
    applicationPortMap.update(&idx, &portNetBytes);


    // Register the destination worker IPs and ports
    auto workerIpMap = obj.findMapByName("map_worker_ips").value();
    auto workerPortMap = obj.findMapByName("map_worker_ports").value();
    for (auto i = 0u; i < workerDestinations.size(); ++i) {
        workerIpMap.update(&i, &(workerDestinations[i].ipAddrNetBytes));
        workerPortMap.update(&i, &(workerDestinations[i].portNetBytes));
    }
    

    // Create the server UDP sending socket    
    int skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (skfd < 0) {
        std::cerr << "Could not create socket\n";
        return 1;  
    }

    // Setup server
    sockaddr_in servAddr;
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(PORT);
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY); //inet_addr("127.0.0.1");

    if ( bind(skfd, (const struct sockaddr *) &servAddr, sizeof(servAddr)) < 0 ) {
        std::cerr << "Could not bind socket\n";
        return 1;  
    }

    std::cout << "Binded" << std::endl;

    std::cout << "APP port (host) = " << PORT << " (net) = " << htons(PORT) << std::endl;
    std::cout << "WORKER port (host) = " << workerDestinations[0].port << " (net) = " << htons(workerDestinations[0].port) << std::endl;
   
    std::string msg = "SCATTER";
    // scatterMessage(skfd, &servAddr, msg);   

    char buf[256];
    strncpy(buf, "SCATTER", 8); 

    struct sockaddr_in client;
    socklen_t slen = sizeof(client);

    // Send the message to itself
    if (sendto(skfd, buf, strlen(buf), 0, (const struct sockaddr *)&servAddr, slen) == -1) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    std::cout << "Sent, waiting to receive" << std::endl;

    // Use: nc -u -l -p 5556 to open a worker process listening for udp packets


    // if (recvfrom(skfd, buf, 256, 0, (struct sockaddr *)&client, &slen) == -1) {
    //     perror("recvfrom");
    //     exit(EXIT_FAILURE);
    // }
    
    // printf("Received packet from %s:%d\nData: %s\n\n", inet_ntoa(client.sin_addr), ntohs(client.sin_port), buf);
    
    // sockaddr_in clientAddr;
    // memset(&clientAddr, 0, sizeof(clientAddr));
    // socklen_t len = sizeof(clientAddr);
    // char buffer[1024];
    // while (1) {

    //     /*
    //         Send UDP packets to test:
    //         $ echo "hi" | nc -u localhost <PORT>
    //     */

    //     int n = recvfrom(skfd, buffer, sizeof(buffer), MSG_WAITALL, 
    //                 (struct sockaddr *) &clientAddr, &len);
        
    //     buffer[n] = '\0';
    //     std::string data{buffer, n-1};
    //     std::cout << "Got: '" << data << "' from client\n";

    //     std::string resp = "ack";
    //     sendto(skfd, resp.c_str(), strlen(resp.c_str()), MSG_CONFIRM,
    //         (const struct sockaddr*) &clientAddr, len);
    // }

    std::this_thread::sleep_for(10s);

    close(skfd);
    bpf_tc_detach(&tcHook, &tcOpts);
    bpf_tc_hook_destroy(&tcHook);

    return 0;
}
