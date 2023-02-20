// #include <bpf/bpf.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <algorithm>
#include <sstream>
#include <fstream>

#include "ebpfpp/Program.h"
#include "ebpfpp/Map.h"
#include "ebpfpp/Object.h"
#include "ebpfpp/Util.h"
#include "ebpfpp/Hook.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <liburing.h>
#include <csignal>

#include "common.h"

extern "C" {
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
}

using namespace std::chrono_literals;


#define MAX_MESSAGE_LEN     sizeof(sg_msg_t)
#define BUFFERS_COUNT       1024

static int ifindex = -1;
static const uint16_t PORT = 9223;


struct Destination {
    std::string ipAddr;
    uint32_t    ipAddrNetBytes;
    uint16_t    port;
    uint16_t    portNetBytes;
    int         fd;
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


std::pair<int, uint16_t> open_worker_socket() {
    sockaddr_in workerAddr;
    workerAddr.sin_family = AF_INET;
    workerAddr.sin_port = 0;    // use any
    workerAddr.sin_addr.s_addr = 0;

    int workerSk = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( bind(workerSk, (const struct sockaddr *) &workerAddr, sizeof(workerAddr)) < 0 ) {
        std::cerr << "Could not bind socket\n";
        exit(EXIT_FAILURE);  
    }

    // Get the port assigned
    socklen_t namelen = sizeof(sockaddr_in);
    if (getsockname(workerSk, (struct sockaddr *) &workerAddr, &namelen) < 0) {
        perror("getsockname()");
        exit(EXIT_FAILURE);
    }

    return { workerSk, workerAddr.sin_port };
}


std::pair<bpf_tc_hook, bpf_tc_opts> attach_tc_program(int ifindex, int progFd, bpf_tc_attach_point attach_point) {
    // TC API: https://github.com/libbpf/libbpf/commit/d71ff87a2dd7b92787719aab233767e9c74fbd48
    // SEE EXAMPLE AT THE BOTTOM
    bpf_tc_hook tcHook;
    memset(&tcHook, 0, sizeof(bpf_tc_hook));    // also needed
    tcHook.attach_point = attach_point;
    tcHook.ifindex = ifindex;
    tcHook.sz = sizeof(bpf_tc_hook);    // this is needed for some reason, otherwise it fails

    auto err = bpf_tc_hook_create(&tcHook);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create TC hook: %d\n", err);
		exit(EXIT_FAILURE);
	}

    bpf_tc_opts tcOpts;
    memset(&tcOpts, 0, sizeof(bpf_tc_opts));
    tcOpts.prog_fd = progFd;
    tcOpts.sz = sizeof(bpf_tc_opts);    // this is needed for some reason, otherwise it fails

    if (bpf_tc_attach(&tcHook, &tcOpts) < 0) {
        std::cerr << "Could not attach TC hook for egress\n";
        exit(EXIT_FAILURE);    
    }

    return { tcHook, tcOpts };
}

enum {
    ACCEPT,
    READ,
    WRITE,
    PROV_BUF,
};

typedef struct conn_info {
    __u32 fd;
    __u16 type;
    __u16 bid;
} conn_info;

void add_socket_read(struct io_uring *ring, int fd, unsigned gid, size_t message_size, unsigned flags) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_recv(sqe, fd, NULL, message_size, MSG_WAITALL); // wait for all fragments to arrive
    io_uring_sqe_set_flags(sqe, flags);
    sqe->buf_group = gid;

    conn_info conn_i = {
        .fd = fd,
        .type = READ,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "ERROR - Usage is: " << argv[0] << " <BPF_FILE> <INTERFACE>" << "\n";
        return 1;
    }

    // Read the worker destinations
    auto workerDestinations = readWorkerDestinations("workers.cfg");
    
    // Attach the programs to the interface
    ifindex = ::if_nametoindex(argv[2]);
    if (!ifindex) {
        std::cerr << "Cannot resolve ifindex for interface name '" << argv[3] << "'\n";
        return 1;
    }
    
    ebpf::Object obj{argv[1]};

    auto scatterTCProg = obj.findProgramByName("scatter_prog").value();
    std::cout << "Loaded TC prog with fd " << scatterTCProg.fd() << " and name " << scatterTCProg.name() << '\n';

    std::cout << "Prog type: " << bpf_program__type(scatterTCProg.get()) << "\n";

    auto maps = obj.maps();
    for (const auto& m : maps) {
        std::cout << "Map " << m.name() << ", ";
    }
    std::cout << '\n';


    // bpf_tc_hook scatterProgTCHook;
    // bpf_tc_opts scatterProgTCOpts;
    // const auto tcConfig = attach_tc_program(ifindex, scatterTCProg.fd(), BPF_TC_EGRESS);
    // std::tie(tcConfig, scatterProgTCHook, scatterProgTCOpts);
    auto scatterProgHookHandle = ebpf::TCHook::attach(ifindex, scatterTCProg, BPF_TC_EGRESS);
    

    auto gatherNotifyTCProg = obj.findProgramByName("notify_gather_ctrl_prog").value();
    // bpf_tc_hook gatherNotifyProgTCHook;
    // bpf_tc_opts gatherNotifyProgTCOpts;
    // const auto tcConfig2 = attach_tc_program(ifindex, gatherNotifyTCProg.fd(), BPF_TC_INGRESS);
    // std::tie(tcConfig2, gatherNotifyProgTCHook, gatherNotifyProgTCOpts);
    auto gatherNotifyProgHookHandle = ebpf::TCHook::attach(ifindex, gatherNotifyTCProg, BPF_TC_INGRESS);


    // Attach the gather XDP program
    auto gatherXdpProg = obj.findProgramByName("gather_prog").value();
    // bpf_xdp_attach_opts opts; // I think we can just pass in NULL
    // bpf_xdp_attach(ifindex, gatherXdpProg.fd(), 0, 0);
    auto gatherProgHookHandle = ebpf::XDPHook::attach(ifindex, gatherXdpProg);
    
    ////////////////////////////////////////////////////////////////////////////////////////


    // Register the application's outgoing port
    auto applicationPortMap = obj.findMapByName("map_application_port").value();
    const uint32_t zero = 0;
    const auto portNetBytes = htons(PORT);
    applicationPortMap.update(&zero, &portNetBytes);


    // Register the destination worker IPs and ports
    // auto workerIpMap = obj.findMapByName("map_worker_ips").value();
    // auto workerPortMap = obj.findMapByName("map_worker_ports").value();
    auto workersMap = obj.findMapByName("map_workers").value();
    auto workersHashMap = obj.findMapByName("map_workers_resp_status").value();

    std::vector<int> workerFds; // TODO make this part of the Worker class
    for (auto i = 0u; i < workerDestinations.size(); ++i) {

        const auto [ workerSkFd, workerLocalPort ] = open_worker_socket();
        workerFds.push_back(workerSkFd);

        worker_info_t w = {
            .worker_ip = workerDestinations[i].ipAddrNetBytes,
            .worker_port = workerDestinations[i].portNetBytes,
            .app_port = workerLocalPort,
        };
        workersMap.update(&i, &w);

        const worker_resp_status_t resp_status = WAITING_FOR_RESPONSE;
        workersHashMap.update(&w, &resp_status);
    }
    std::sort(workerFds.begin(), workerFds.end());

    // Prepare the gather control socket
    uint16_t ctrlPort = htons(9999);
    int ctrlSkFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in ctrlAddr;
    ctrlAddr.sin_family = AF_INET;
    ctrlAddr.sin_port = ctrlPort;    // TODO use any
    ctrlAddr.sin_addr.s_addr = 0;
    if ( bind(ctrlSkFd, (const struct sockaddr *) &ctrlAddr, sizeof(ctrlAddr)) < 0 ) {
        std::cerr << "Could not bind socket\n";
        exit(EXIT_FAILURE);  
    }

    auto gatherCtrlPortMap = obj.findMapByName("map_gather_ctrl_port").value();
    gatherCtrlPortMap.update(&zero, &ctrlPort);

    //////////////////////////////////////////////////////////////////////////////////

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
    servAddr.sin_addr.s_addr = 0; //inet_addr("127.0.0.1");

    if ( bind(skfd, (const struct sockaddr *) &servAddr, sizeof(servAddr)) < 0 ) {
        std::cerr << "Could not bind socket\n";
        return 1;  
    }
    std::cout << "APP port (host) = " << PORT << " (net) = " << htons(PORT) << std::endl;
   

    // initialize io_uring
    io_uring_params params;
    io_uring ring;
    memset(&params, 0, sizeof(params));

    if (io_uring_queue_init_params(2048, &ring, &params) < 0) {
        perror("io_uring_init_failed...\n");
        exit(1);
    }

    #define GROUP_ID 1337

    // register buffers for buffer selection
    io_uring_sqe *sqe;
    io_uring_cqe *cqe;

    sqe = io_uring_get_sqe(&ring);
    char bufs[BUFFERS_COUNT][MAX_MESSAGE_LEN] = {0};
    io_uring_prep_provide_buffers(sqe, bufs, MAX_MESSAGE_LEN, BUFFERS_COUNT, GROUP_ID, 0);
    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0) {
        printf("cqe->res = %d\n", cqe->res);
        exit(1);
    }
    io_uring_cqe_seen(&ring, cqe);


    // Send the message to itself
    const auto SCATTER_STR = "SCATTER";

    // TODO add the send to the io_uring queue too

    sg_msg_t hdr;
    memset(&hdr, 0, sizeof(sg_msg_t));
    hdr.req_id = 1;
    hdr.msg_type = SCATTER_MSG;
    hdr.body_len = strnlen(SCATTER_STR, BODY_LEN);
    strncpy(hdr.body, SCATTER_STR, hdr.body_len);

    // if (sendto(skfd, &hdr, sizeof(sg_msg_t), 0, (const struct sockaddr *)&servAddr, sizeof(sockaddr_in)) == -1) {
    //     perror("sendto");
    //     exit(EXIT_FAILURE);
    // }

    // this auxilary struct is needed for the sendmsg io_uring operation
    struct iovec iov = {
		.iov_base = &hdr,
		.iov_len = sizeof(sg_msg_t),
	};

	struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
	msg.msg_name = &servAddr;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_sendmsg(sqe, skfd, &msg, 0);
    io_uring_sqe_set_flags(sqe, 0);

    conn_info conn_i = {
        .fd = skfd,
        .type = WRITE,
    };
    memcpy(&sqe->user_data, &conn_i, sizeof(conn_i));
    io_uring_submit(&ring);
    
    std::cout << "Sent scatter message" << std::endl;

    // Add a socket read operation to the SQE for the ctrl socket 
    add_socket_read(&ring, ctrlSkFd, GROUP_ID, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);

    RESP_AGGREGATION_TYPE userspace_aggregated_value;
    std::vector<int> processedWorkerFds;

    while (1) {
        std::cout << "entering event loop\n";
        // Submit and wait for completion (alternatively, omit _and_wait() for busy wait polling)
        // Also, see kernel thread polling mode to avoid any syscalls at all (but has high CPU usage)
        io_uring_submit_and_wait(&ring, 1);
        io_uring_cqe *cqe;
        unsigned head;
        unsigned count = 0;

        io_uring_for_each_cqe(&ring, head, cqe) {
            ++count;

            conn_info conn_i;
            memcpy(&conn_i, &cqe->user_data, sizeof(conn_i));

            int type = conn_i.type;
            if (cqe->res == -ENOBUFS) {
                fprintf(stdout, "bufs in automatic buffer selection empty, this should not happen...\n");
                fflush(stdout);
                exit(1);
            }
            
            if (conn_i.type == READ) {
                // int bytes_read = cqe->res;
                int buff_id = cqe->flags >> 16;
                if (cqe->res <= 0) {
                    // read failed, re-add the buffer
                    // add_provide_buf(&ring, buff_id, group_id);
                    // connection closed or error
                    close(conn_i.fd);
                } else {
                    
                    // this is a notification on the ctrl socket
                    if (conn_i.fd == ctrlSkFd) {
                        auto r = (sg_msg_t*) bufs[buff_id];
                        std::cout << "got response: " << ntohl(*(uint32_t*)r->body) << '\n';

                        // add requests to read from worker sockets
                        // DISCUSSION: is this even needed now? io_uring will automatically
                        // know when these sockets are ready to read, so this initial check on the
                        // control socket is not really necessary

                        // TODO check when io_uring returns (multi-packet messages)
                        // if io_uring returns as soon as any data is available, keep the ctrl socket
                        // otherwise, the ctrl socket is not needed and we can batch all the submissions
                        // into the queue, without any syscalls
                        // if so, can we set the wait_nr in the io_uring_submit_and_wait() call to the number
                        // of workers + 1???

                        // TODO Investigate io_uring thread mapping?
                        // can we have multiple io_uring instances
                        // is the instance shared across multiple user threads?

                        for (auto wfd : workerFds) {
                            add_socket_read(&ring, wfd, GROUP_ID, MAX_MESSAGE_LEN, IOSQE_BUFFER_SELECT);
                        }

                        userspace_aggregated_value = 0; // reset value
                        processedWorkerFds = {};

                    } else {
                        // get individual response from worker socket
                        // need to keep track whether we have received all responses
                        // because we cannot loop over them explicity

                        processedWorkerFds.push_back(conn_i.fd);
                        auto r = (sg_msg_t*) bufs[buff_id];
                        auto data = ntohl(*(uint32_t*) r->body);
                        userspace_aggregated_value += data;
                    }
                }
            }
        }

        io_uring_cq_advance(&ring, count);

        // Have we read all the individual responses from the worker sockets?
        std::sort(processedWorkerFds.begin(), processedWorkerFds.end());
        if (processedWorkerFds == workerFds) {
            std::cout << "Aggregated value in user-space = " << userspace_aggregated_value << std::endl;
            break;
        }
    }


    //////////////////////////////////////////////////////////////////////////////////////////

    // Use: nc -u -l -p 5556 to open a worker process listening for udp packets


    // TODO this week. goal is to reduce the syscalls to O(1)
    // - use the ctrl socket to get the aggregated value back
    // - use io_uring to perform batch reads over the worker sockets
    // In another folder (alternative design), drop all packets and only send
    // back the final value

    // Wait on ctrlSkFd until we receive a notification
    // sg_msg_t ctrlResp;
    // if (read(ctrlSkFd, &ctrlResp, sizeof(sg_msg_t)) > 0) {        
    //     std::cout << "Got notification on ctrl socket (got aggregated value = "
    //               << ntohl(*(uint32_t*)ctrlResp.body) << "), ready to read from worker sockets\n";


    //     // We can read the individual sockets now
    //     RESP_AGGREGATION_TYPE userspace_aggregated_value = 0;
    //     sg_msg_t resp;

    //     // instead of this loop, can we use io_uring to batch the reads into a single syscall

    //     for (const auto workerSock : workerFds) {
    //         if (read(workerSock, &resp, sizeof(sg_msg_t)) > 0) {
    //             auto data = ntohl(*(uint32_t*)resp.body);
    //             userspace_aggregated_value += data;
    //             std::cout << "Got resp from worker " << workerSock << ": " << data << " for request ID " << resp.req_id << std::endl;
    //         }
    //     }
    //     std::cout << "Aggregated value in user-space = " << userspace_aggregated_value << std::endl;
    // }

 

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

    // Get the aggregated value
    auto aggregatedValueMap = obj.findMapByName("map_aggregated_response").value();
    RESP_AGGREGATION_TYPE value;
    aggregatedValueMap.find(&zero, &value);

    std::cout << "Final aggregated value (from BPF map) = " << value << std::endl;

    close(skfd);

    // bpf_tc_detach(&scatterProgTCHook, &scatterProgTCOpts);
    // bpf_tc_hook_destroy(&scatterProgTCHook);
    ebpf::TCHook::detach(scatterProgHookHandle);

    // bpf_tc_detach(&gatherNotifyProgTCHook, &gatherNotifyProgTCOpts);
    // bpf_tc_hook_destroy(&gatherNotifyProgTCHook);
    ebpf::TCHook::detach(gatherNotifyProgHookHandle);


    // bpf_xdp_detach(ifindex, 0, 0);
    ebpf::XDPHook::detach(gatherProgHookHandle);

    return 0;
}
