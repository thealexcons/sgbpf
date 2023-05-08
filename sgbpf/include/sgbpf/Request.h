#ifndef _SGBPF_REQUEST_H
#define _SGBPF_REQUEST_H

#include "Common.h"
#include "Worker.h"

#include <chrono>
#include <vector>
#include <unordered_map>
#include <liburing.h>

namespace sgbpf
{

enum class GatherCompletionPolicy 
{
    WaitAll = SG_MSG_F_WAIT_ALL,
    WaitAny = SG_MSG_F_WAIT_ANY,
    WaitN   = SG_MSG_F_WAIT_N
};

class ReqParams {
private:
    constexpr const static auto DEFAULT_TIMEOUT_US = std::chrono::microseconds{50 * 1000};
    constexpr const static auto DEFAULT_COMPLETION_POLICY = GatherCompletionPolicy::WaitAll;

public:
    unsigned int                numPksPerRespMsg = 1;
    unsigned int                numWorkersToWait = 0;
    std::chrono::microseconds   timeout          = DEFAULT_TIMEOUT_US;
    GatherCompletionPolicy      completionPolicy = DEFAULT_COMPLETION_POLICY;

    ReqParams() = default;
};

// Forward declaration of Service
class Service;

class Request
{
    // Manages the state and execution of a scatter gather request. Each invocation
    // of the scatter gather primitive creates an instance of this class.
public:
    constexpr static const auto NumBuffers    = 1024;
    constexpr static const auto MaxBufferSize = sizeof(sg_msg_t);

    enum class Status {
        Waiting,
        Ready,
        TimedOut,
        Error
    };

    friend Service;

private:
    // DATA MEMBERS
    int                     d_requestID;                    // The unique request ID
    std::vector<Worker>     d_workers;
    unsigned int            d_expectedPacketsPerMessage = 1;    // The number of expected packets per response message
    Status                  d_status;
    std::chrono::microseconds d_timeOut;
    GatherCompletionPolicy  d_completionPolicy;
    unsigned int            d_numWorkersToWait;
    
    std::chrono::time_point<std::chrono::steady_clock> d_startTime;

    // TODO num buffers should be the max number of packets for an entire request
    // = max num packets per response * max num workers
    char d_buffers[NumBuffers][MaxBufferSize] = {0};

    // todo make the key Worker type, instead of the fd
    std::unordered_map<int, std::vector<int>> d_workerBufferPtrs;

public:

    Request() = default;

    Request(int requestID, 
            std::vector<Worker> workers, 
            const ReqParams& params);


    int id() const { return d_requestID; }

    const std::vector<Worker>& workers() const { return d_workers; }

    const char* data(int packetIdx) const { return d_buffers[packetIdx]; }

    // TODO use Worker instance as key instead of FD
    const std::unordered_map<int, std::vector<int>>& bufferPointers() const { return d_workerBufferPtrs; };

    bool isReady() const { return d_status == Status::Ready; }

    bool isExpired() const { return d_status == Status::TimedOut; }

protected:
    bool hasTimedOut() const;

    void addBufferPtr(int workerFd, int ptr);

    void startTimer();

    bool receivedSufficientPackets() const;

    bool receivedWaitAny() const;

    bool receivedWaitN(uint32_t numWorkers) const;

    void registerBuffers(io_uring* ring, bool forceSubmit = false);

    void freeBuffers(io_uring* ring, bool forceSubmit = false);
};



} // close namespace sgbpf


#endif // !_SGBPF_REQUEST_H
