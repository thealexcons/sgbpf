#include <iostream>
#include <cstring>
#include <algorithm>

#include <net/if.h>
#include <unistd.h>

#include "sgbpf/Worker.h"
#include "sgbpf/Context.h"
#include "sgbpf/Request.h"
#include "sgbpf/Service.h"
#include "sgbpf/Common.h"


int main(int argc, char** argv) {

    // Disable all cout
    // std::cout.rdbuf(nullptr);

    // globally initialises the library and prepares eBPF environment
    // ScatterGather::init("scatter_gather.json");
    
    // sudo ./sg_loader . lo
    sgbpf::ContextParams params;
    params.bpfObjsPath = argv[1];
    params.customAggregationMode = sgbpf::AggregationMode::Program;
    params.ifname = argv[2];
    sgbpf::Context ctx{params};

    auto workers = sgbpf::Worker::fromFile("worker/workers.cfg");
    sgbpf::Service service{ctx, workers};

    // User can configure the ctrl socket as they wish, eg: set non blocking flag
    // int flags = fcntl(sg.ctrlSkFd(), F_GETFL, 0);
    // fcntl(sg.ctrlSkFd(), F_SETFL, flags | O_NONBLOCK);
    
    // EXAMPLE 1: Vector-based data (with in-kernel aggregation)
    sgbpf::ReqParams params; // set params here....
    params.completionPolicy = sgbpf::GatherCompletionPolicy::WaitN;
    params.numWorkersToWait = 10;
    auto req = service.scatter("SCATTER", 8, params);
    std::cout << "sent scatter request" << std::endl;

    // Wait on the ctrl socket to finish
    sg_msg_t buf;
    auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    assert(b == sizeof(sg_msg_t));
    // Important: it is up to the user to verify that this corresponds to the
    // request's ID, since the ctrl sk is global to all ongoing requests
    assert(buf.hdr.req_id == req->id());

    // Process the completed events in the io_uring queue
    // decouple threading model from library
    // To be called periodically or directly after an event on the ctrl sk

    // TODO processEvents may process more packets than those reflected in the aggregated
    // value returned by the ctrl sk (ie: aggregates 2 pks, but the 3rd pk arrives later
    // and is captured by processEvents(). need a way to synchronise this?????)
    service.processEvents();
    
    auto aggregatedData = (uint32_t*)(buf.body);
    std::cout << "control socket packet received\n";
    for (auto i = 0u; i < RESP_MAX_VECTOR_SIZE; i++) {
        if (i % 25 == 0)
            std::cout << "vec[" << i << "] = " << aggregatedData[i] << std::endl;
    }

    std::cout << "Got a total of " << req->bufferPointers().size() << std::endl;
    

    // ASSUMPTION: the number of packets in the response message must be specified
    // in advance if calling processEvents() AFTER the ctrl sk event. Otherwise,
    // a separate thread is needed to periodically call processEvents() to submit
    // any remaining read operations to the IO event queue (io_uring).

    // ASSUMPTION 2: for multi-packet aggregation, this must be done in userspace
    // and there is no notification to the ctrl socket. Therefore, the user must
    // periodically call processEvents() and wait until all packets have arrived.
    // One way to do this is to call processEvents() while waiting under req->isReady();

    /*

    // EXAMPLE TWO: multi-packet response, with userspace aggregation over individual packets
    // this is useful for multi-packet responses, so the user can perform the aggregation
    // themselves in user-space
    sgbpf::ReqParams params2;
    params2.completionPolicy = sgbpf::GatherCompletionPolicy::WaitN;
    params2.numWorkersToWait = 2;
    auto req2 = service.scatter("SCATTER", 8, params2);

    // Can this polling loop (ready and expired check) be simplified
    // including the later check for expiration?
    while (!req2->isReady() && !req2->isExpired()) {
        // Because we have no notification on the ctrl socket in this case, we must
        // manually check whether we have received the packets by periodically calling
        // the process function
        service.processEvents(req2->id());
    }

    if (req2->isExpired()) {
        // req2->cleanup(); // what exactly is needed here? can also do lazy cleanup on scatter
        std::cout << "Request expired\n";
        return 0;
    }

    for (const auto& w : req2->workers()) {
        if (req2->bufferPointers().count(w.socketFd())) {
            auto buffIdxs = req2->bufferPointers().at(w.socketFd());
            std::cout << "Num packets received per msg: " << buffIdxs.size() << std::endl;
            
            for (auto buffIdx : buffIdxs) {
                auto pk = (sg_msg_t*) req2->data(buffIdx);
                std::cout << "Pk: " << buffIdx << " - " << ((uint32_t*)(pk->body)) << std::endl;
            }
        }
    }
    */
}
