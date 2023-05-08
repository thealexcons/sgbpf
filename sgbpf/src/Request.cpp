#include "Request.h"

namespace sgbpf
{

Request::Request(int requestID, 
                 std::vector<Worker> workers, 
                 const ReqParams& params)
    : d_requestID{requestID}
    , d_workers{workers}
    , d_expectedPacketsPerMessage{params.numPksPerRespMsg}
    , d_status{Status::Waiting}
    , d_timeOut{params.timeout}
    , d_completionPolicy{params.completionPolicy}
    , d_numWorkersToWait{params.numWorkersToWait}
{}


bool Request::hasTimedOut() const {
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - d_startTime);
    return duration >= d_timeOut; 
}

void Request::addBufferPtr(int workerFd, int ptr) {
    d_workerBufferPtrs[workerFd].push_back(ptr);
}

void Request::startTimer() {
    d_startTime = std::chrono::steady_clock::now();
}

bool Request::receivedSufficientPackets() const {
    if (d_completionPolicy == GatherCompletionPolicy::WaitAll) {
        return receivedWaitN(d_workers.size());
    }
    else if (d_completionPolicy == GatherCompletionPolicy::WaitN) {
        return receivedWaitN(d_numWorkersToWait);
    }
    else if (d_completionPolicy == GatherCompletionPolicy::WaitAny) {
        return receivedWaitAny();
    }
    return false;
};

bool Request::receivedWaitAny() const {
    if (d_expectedPacketsPerMessage == 1)
        return d_workerBufferPtrs.size() > 0;
    
    // For multi-packet messages, we need to check that at least one worker
    // has delivered a full message
    for (const auto& [_, ptrs] : d_workerBufferPtrs) {
        if (ptrs.size() == d_expectedPacketsPerMessage)
            return true;
    }
    return false;
}

bool Request::receivedWaitN(uint32_t numWorkers) const {
    if (d_expectedPacketsPerMessage == 1)
        return d_workerBufferPtrs.size() == numWorkers;

    // For multi-packet messages, we need to check that N workers have
    // delivered a full message
    auto fullMessagesReceived = 0u;
    for (const auto& [_, ptrs] : d_workerBufferPtrs) {
        if (ptrs.size() == d_expectedPacketsPerMessage)
            fullMessagesReceived++;
    }        
    return fullMessagesReceived == numWorkers;
}

void Request::registerBuffers(io_uring* ring, bool forceSubmit) {
    io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_provide_buffers(
        sqe, d_buffers, MaxBufferSize, NumBuffers, d_requestID, 0
    );
    if (forceSubmit)
        io_uring_submit(ring);
}

void Request::freeBuffers(io_uring* ring, bool forceSubmit) {
    io_uring_sqe* sqe = io_uring_get_sqe(ring);
    io_uring_prep_remove_buffers(sqe, NumBuffers, d_requestID);
    if (forceSubmit)
        io_uring_submit(ring);
}

} // close namespace sgbpf
