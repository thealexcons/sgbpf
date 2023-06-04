#include "Context.h"

namespace sgbpf
{

namespace fs = std::filesystem;

Context::Context(const char* bpfObjectsPath, const char* interfaceName)
    : d_object{(fs::path(bpfObjectsPath) / fs::path(MAIN_SG_BPF_OBJ_NAME)).c_str()}
    , d_aggregationProgObject{(fs::path(bpfObjectsPath) / fs::path(AGGREGATION_BPF_OBJ_NAME)).c_str()}
    , d_ifindex{::if_nametoindex(interfaceName)}
    , d_scatterProg{d_object.findProgramByName("scatter_prog").value()}
    , d_gatherNotifyProg{d_object.findProgramByName("notify_gather_ctrl_prog").value()}
    , d_gatherProg{d_object.findProgramByName("gather_prog").value()}
    , d_workersMap{d_object.findMapByName(WORKERS_MAP_NAME).value()}
    , d_workersHashMap{d_object.findMapByName(WORKERS_HASH_MAP_NAME).value()}
    , d_appPortMap{d_object.findMapByName(APP_PORT_MAP_NAME).value()}
    , d_gatherCtrlPortMap{d_object.findMapByName(GATHER_CTRL_PORT_MAP_NAME).value()}
    , d_ctrlSkRingBufMap{d_object.findMapByName(CTRL_SOCK_RINGBUF_MAP).value()}
{
    if (!d_ifindex)
        throw std::invalid_argument{"Cannot resolve interface index"};
    
    d_scatterProgHandle = ebpf::TCHook::attach(d_ifindex, d_scatterProg, BPF_TC_EGRESS);

    d_gatherNotifyProgHandle = ebpf::TCHook::attach(d_ifindex, d_gatherNotifyProg, BPF_TC_INGRESS);

    d_gatherProgHandle = ebpf::XDPHook::attach(d_ifindex, d_gatherProg);

    auto vecAggProgsMap = d_object.findMapByName("map_aggregation_progs").value();
    auto progIdx = CUSTOM_AGGREGATION_PROG_IDX;
    auto customAggregationProg = d_aggregationProgObject.findProgramByName("aggregation_prog").value();
    auto customAggregationProgFd = customAggregationProg.fd();
    vecAggProgsMap.update(&progIdx, &customAggregationProgFd);

    // Increase max num open files for large number of workers
    rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        auto curr = rlim.rlim_cur;
        rlim.rlim_cur = rlim.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rlim) == -1) {
            std::cout << "[sgbpf - WARNING] Unable to increase file descriptor limits from " 
                      << curr << " to " << rlim.rlim_max << std::endl;
            exit(1);
        }
    } else {
        std::cout << "[sgbpf - WARNING] Unable to get file descriptor limits, continuing" << std::endl;
    }

}

Context::~Context()
{
    ebpf::TCHook::detach(d_scatterProgHandle);
    ebpf::TCHook::detach(d_gatherNotifyProgHandle);
    ebpf::XDPHook::detach(d_gatherProgHandle);
}

void Context::setScatterPort(uint16_t port)
{
    // Register the application's outgoing port
    const auto portNetBytes = htons(port);
    d_appPortMap.update(&ZERO, &portNetBytes);
}

void Context::setGatherControlPort(uint16_t port, bool useRingBufNotifs, bool enableAllGatherBroadcast)
{
    // Register the control socket port for the gather stage
    struct ctrl_sk_info {
        __u16 port;
        __u16 use_ring_buf;
        __u8  all_gather;
    } data = {
        .port = htons(port),
        .use_ring_buf = (uint16_t) useRingBufNotifs,
        .all_gather = (uint8_t) enableAllGatherBroadcast,
    };
    d_gatherCtrlPortMap.update(&ZERO, &data);
}


} // close namespace sgbpf
