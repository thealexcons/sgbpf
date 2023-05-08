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

    // sudo ./sg_loader scatter_gather.bpf.o aggregation.bpf.o lo
    sgbpf::Context ctx{argv[1], argv[2], argv[3]};

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    sgbpf::Service service{ctx, workers};
    
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
    assert(buf.hdr.req_id == req->id());

    service.processEvents();
    
    auto aggregatedData = (uint32_t*)(buf.body);
    std::cout << "control socket packet received\n";
    for (auto i = 0u; i < RESP_MAX_VECTOR_SIZE; i++) {
        if (i % 25 == 0)
            std::cout << "vec[" << i << "] = " << aggregatedData[i] << std::endl;
    }

    std::cout << "Got a total of " << req->bufferPointers().size() << std::endl;
}
