#include <iostream>
#include <cstring>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cmath>

#include <net/if.h>
#include <unistd.h>
#include <sys/epoll.h> 

#include <sgbpf/Worker.h>
#include <sgbpf/Context.h>
#include <sgbpf/Request.h>
#include <sgbpf/Service.h>
#include <sgbpf/Common.h>


void busyWaitCtrlSkExample(char** argv);
void busyWaitWorkerPacketsExample(char** argv);

int main(int argc, char** argv) {

    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <path/to/bpfobjs> <ifname>" << std::endl;
        return 1;
    }

    busyWaitWorkerPacketsExample(argv);
    return 0;


    // start with ctrl sk io_uring support
    // test and benchmark compared with read()

    // IS EPOLL ON CTRL SK WORTH IT?? maybe if we get multiple notifs then yes...
    // then move onto epoll via ringbuf
    // test and benchmark compared with read()


    // sudo ./sg_program bpfobjs lo
    // export OUTPUT_BPF_OBJ_DIR=$(pwd)/bpfobjs

    // Standard method (BPF program)
    // export CUSTOM_AGGREGATION_BPF_PROG=$(pwd)/custom_aggregation.bpf.c
    // Using make --directory=../sgbpf bpf
    sgbpf::Context ctx{argv[1], argv[2]};

    // int flags = fcntl(sg.ctrlSkFd(), F_GETFL, 0);
    // fcntl(service.ctrlSkFd(), F_SETFL, flags | O_NONBLOCK);

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    sgbpf::Service service{
        ctx, 
        workers, 
        sgbpf::PacketAction::Discard,
        sgbpf::CtrlSockMode::BusyWait
    };

    service.setCtrlSkCallback([](char* data, int reqID) -> void {
        std::cout << "got agg data for req " << reqID << std::endl;
        for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
            std::cout << "vec[" << j << "] = " << ((uint32_t*) data)[j] << std::endl;
        }
    });


    sgbpf::ReqParams params; // set params here....
    params.completionPolicy = sgbpf::GatherCompletionPolicy::WaitAll;
    params.numWorkersToWait = workers.size();
    params.timeout = std::chrono::microseconds{50000 * 100};

    auto req = service.scatter("SCATTER", 8, params);

    while (1) {
        int completions = service.epollWaitCtrlSock(50);
        if (completions > 0)
            break;
    }
    service.processEvents();


    // std::cout << req->isReady() << std::endl;
    // assert(req->isReady());

    // auto buf = req->ctrlSockData();
    
    // for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
    //     std::cout << "vec[" << j << "] = " << ((uint32_t*) buf->body)[j] << std::endl;
    //     assert(((uint32_t*) buf->body)[j] == workers.size() * j);
    // }
    
    // std::cout << "\n\n";
    // for (auto [wfd, ptrs] : req->bufferPointers()) {
    //     std::cout << "Worker " << wfd  << std::endl;
    //     for (auto ptr : ptrs) {
    //         auto r = (sg_msg_t*) req->data(ptr);
    //         std::cout << "  " << ((uint32_t*)r->body)[10] << std::endl;
    //     }
    // }

    // WAIT ALL WORKS PERFECTLY FINE
    // MUST BE RELATED TO THE DROPPED PACKETS IN WAIT_N ??
    // also not UDP reliability issues because setting WAIT N = all - 1 still fails
    // IF WE DON'T DROP REDUNDANT PACKETS (LINE 368 IN EBPF), WE CAN JUST IGNORE THEM IN USERSPACE
    // still seems to be a bug...
    // idek, goes on streaks where it works, sometimes randomly gives num pk mismatch??
    // can we just assume reliability isn't perfect??

    // WHEN SENDING MANY REQUESTS, AT SOME POINT IT LOOKS LIKE THEY GET STUCK
    // AROUND REQ 427.
    // looks like workers ARE NOT sending data back? maybe they crashed?

    // todo send requests, do not expect reply

    // std::cout << "sent scatter request" << std::endl;
    // for (auto i = 0u; i < 3; i++) {
    //     auto req = service.scatter("SCATTER", 8, params);

    //     sg_msg_t buf;
    //     auto b = read(service.ctrlSkFd(), &buf, sizeof(sg_msg_t));
    //     assert(b == sizeof(sg_msg_t));
    //     assert(buf.hdr.req_id == req->id());

    //     // while (req->bufferPointers().size() != params.numWorkersToWait)
    //     service.processEvents();
        
    //     auto aggregatedData = (uint32_t*)(buf.body);
    //     // std::cout << "control socket packet received\n";
    //     for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
    //         bool c = aggregatedData[j] == j * params.numWorkersToWait;
    //         if(!c) {
    //             std::cout << "DATA MISMATCH on REQ " << i << " - Got " << aggregatedData[j] << " at idx " << j << " instead of " << j * params.numWorkersToWait << std::endl;
    //             throw;
    //         }
    //         std::cout << "vec[" << j << "] = " << aggregatedData[j] << std::endl;
    //     }
    //     bool c = req->bufferPointers().size() == params.numWorkersToWait;
    //     if(!c) {
    //         std::cout << "NUM PKS MISMATCH on REQ " << i << " - Got " << req->bufferPointers().size() << " instead of " << params.numWorkersToWait << std::endl;
    //         throw;
    //     }
    //     // service.freeRequest(req);
    // }
    
}



// Example: busy wait with Request::isReady() while calling Service::processEvents, only checking
// for the aggregated data on the control socket
void busyWaitCtrlSkExample(char** argv) {
    sgbpf::Context ctx{argv[1], argv[2]};

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    sgbpf::Service service{
        ctx, 
        workers, 
        sgbpf::PacketAction::Discard,   // drop worker packets
        sgbpf::CtrlSockMode::BusyWait   // we will busy wait on the final aggregated data
    };

    auto req = service.scatter("SCATTER", 8);

    while (!req->isReady(true)) {
        service.processEvents(req->id());
    }

    std::cout << "control socket ready, got data: " << std::endl;
    for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
        std::cout << "vec[" << j << "] = " << ((uint32_t*) req->ctrlSockData()->body)[j] << std::endl;
    }

}



// Example: busy wait with Request::isReady() while calling Service::processEvents, checking for
// all individual worker response packets
void busyWaitWorkerPacketsExample(char** argv) {
    sgbpf::Context ctx{argv[1], argv[2]};

    auto workers = sgbpf::Worker::fromFile("workers.cfg");
    sgbpf::Service service{
        ctx, 
        workers, 
        sgbpf::PacketAction::Allow,     // drop worker packets
        sgbpf::CtrlSockMode::BusyWait   // we will busy wait on the worker packets
    };

    // Reminder: ALLOW_PK must be set in the custom aggregation logic

    auto req = service.scatter("SCATTER", 8);

    while (!req->isReady()) {
        service.processEvents(req->id());
    }

    std::cout << "reading all individual packets:\n";
    uint32_t data2[RESP_MAX_VECTOR_SIZE] = {0};
    for (auto [wfd, ptrs] : req->bufferPointers()) {
        assert(ptrs.size() == 1);
        auto ptr = ptrs[0];

        for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
            auto buf = (sg_msg_t*) req->data(ptr);
            data2[j] += ((uint32_t*) buf->body)[j];
            std::cout << j << std::endl;
        }
    }

    std::cout << "control socket ready, got data: " << std::endl;
    const char* data = req->ctrlSockData()->body;
    for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
        std::cout << "vec[" << j << "] = " << ((uint32_t*) data)[j] << std::endl;
    }

    // ensure both are equal
    for (auto j = 0u; j < RESP_MAX_VECTOR_SIZE; j++) {
        assert( ((uint32_t*) data)[j] == data2[j] );
        std::cout << j << std::endl;
    }

    std::cout << "Both vectors are equal!" << std::endl;

}

