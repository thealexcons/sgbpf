#include "Context.h"

namespace sgbpf
{

Context::Context(const char* objFile, const char* aggObjFile, const char* ifname)
    : d_object{objFile}
    , d_aggregationProgObject{aggObjFile}
    , d_ifindex{::if_nametoindex(ifname)}
    , d_scatterProg{d_object.findProgramByName("scatter_prog").value()}
    , d_gatherNotifyProg{d_object.findProgramByName("notify_gather_ctrl_prog").value()}
    , d_gatherProg{d_object.findProgramByName("gather_prog").value()}
    , d_workersMap{d_object.findMapByName(WORKERS_MAP_NAME).value()}
    , d_workersHashMap{d_object.findMapByName(WORKERS_HASH_MAP_NAME).value()}
    , d_appPortMap{d_object.findMapByName(APP_PORT_MAP_NAME).value()}
    , d_gatherCtrlPortMap{d_object.findMapByName(GATHER_CTRL_PORT_MAP_NAME).value()}
{
    if (!d_ifindex)
        throw std::invalid_argument{"Cannot resolve interface index"};
    
    d_scatterProgHandle = ebpf::TCHook::attach(d_ifindex, d_scatterProg, BPF_TC_EGRESS);

    d_gatherNotifyProgHandle = ebpf::TCHook::attach(d_ifindex, d_gatherNotifyProg, BPF_TC_INGRESS);

    d_gatherProgHandle = ebpf::XDPHook::attach(d_ifindex, d_gatherProg);

    auto vecAggProgsMap = d_object.findMapByName("map_aggregation_progs").value();
    auto progIdx = CUSTOM_AGGREGATION_PROG;
    auto customAggregationProg = d_aggregationProgObject.findProgramByName("aggregation_prog").value();
    auto customAggregationProgFd = customAggregationProg.fd();
    vecAggProgsMap.update(&progIdx, &customAggregationProgFd);

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

void Context::setGatherControlPort(uint16_t port)
{
    // Register the control socket port for the gather stage
    const auto portNetBytes = htons(port);
    d_gatherCtrlPortMap.update(&ZERO, &portNetBytes);
}


} // close namespace sgbpf
