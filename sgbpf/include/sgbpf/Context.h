#ifndef _SGBPF_CONTEXT_H
#define _SGBPF_CONTEXT_H

#include "ebpf/Object.h"
#include "ebpf/Program.h"
#include "ebpf/Hook.h"
#include "ebpf/Map.h"
#include "Worker.h"
#include "Common.h"

#include <filesystem>
#include <iostream>
#include <net/if.h>
#include <sys/resource.h>
#include <liburing.h>

namespace sgbpf {

/**
 * @brief Initialises the eBPF environment for scatter gather operations.
 * 
 */
class Context
{
private:
    // DATA
    ebpf::Object            d_object;
    ebpf::Object            d_aggregationProgObject;
    uint32_t                d_ifindex;
    std::vector<Worker>     d_workers;
    ebpf::Program           d_scatterProg;
    ebpf::Program           d_gatherNotifyProg;
    ebpf::Program           d_gatherProg;
    ebpf::TCHook::Handle    d_scatterProgHandle;
    ebpf::TCHook::Handle    d_gatherNotifyProgHandle;
    ebpf::XDPHook::Handle   d_gatherProgHandle;

    ebpf::Map               d_workersMap;   
    ebpf::Map               d_workersHashMap;   
    ebpf::Map               d_appPortMap;   
    ebpf::Map               d_gatherCtrlPortMap;   
    ebpf::Map               d_ctrlSkRingBufMap;   

    // Object names
    constexpr static const auto MAIN_SG_BPF_OBJ_NAME = "scatter_gather.bpf.o";
    constexpr static const auto AGGREGATION_BPF_OBJ_NAME = "aggregation.bpf.o";

    // Map names
    constexpr static const auto WORKERS_MAP_NAME = "map_workers";
    constexpr static const auto WORKERS_HASH_MAP_NAME = "map_workers_resp_status";
    constexpr static const auto APP_PORT_MAP_NAME = "map_application_port";
    constexpr static const auto GATHER_CTRL_PORT_MAP_NAME = "map_gather_ctrl_port";
    constexpr static const auto CTRL_SOCK_RINGBUF_MAP = "map_ctrl_sk_ringbuf";

    constexpr static const auto ZERO = 0;

public:
    /**
     * @brief Construct a new Context object
     * 
     * @param bpfObjectsPath The path to directory containing the BPF object files
     * @param interfaceName The name of the network interface
     */
    Context(const char* bpfObjectsPath, const char* interfaceName);
    ~Context();

    void setScatterPort(uint16_t port);
    void setGatherControlPort(uint16_t port, bool useRingBufNotifs, bool enableAllGatherBroadcast);

    ebpf::Map& workersMap() { return d_workersMap; };
    ebpf::Map& workersHashMap() { return d_workersHashMap; };
    ebpf::Map& ctrlSkRingBufMap() { return d_ctrlSkRingBufMap; };
};


/**
 * @brief An io_uring instance in an RAII wrapper class
 */
struct IOUringContext 
{
    io_uring ring;
    
    /**
     * @brief Construct a new IOUringContext object
     * 
     * @param numEntries the number of entries for the SQ
     */
    IOUringContext(uint32_t numEntries) 
    {
        // Initialise io_uring
        io_uring_params params;
        memset(&params, 0, sizeof(params));

        if (io_uring_queue_init_params(numEntries, &ring, &params) < 0)
            throw std::runtime_error{"Failed to initialise io_uring queue"}; 
    }

    ~IOUringContext() {
        io_uring_queue_exit(&ring);
    }
};

} // close namespace sgbpf


#endif // !_SGBPF_CONTEXT_H
