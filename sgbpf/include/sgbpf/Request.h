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
    WaitAll,
    WaitAny,
    WaitN,
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

// Forward declarations
class Service;

// These are defined here to avoid issues with circular dependencies
// and forward declaring enums
enum class PacketAction 
{
    Discard,
    Allow,
};

enum class CtrlSockMode
{
    UnixFD,         // use as a raw Unix file descriptor
    Native,        // use io_uring + buffer, blocks until ctrl sk is ready
    Notification    // use epoll notification-based polling
};


class Request
{
    // Manages the state and execution of a scatter gather request. Each invocation
    // of the scatter gather primitive creates an instance of this class.
public:
    // constexpr static const auto MaxNumPksPerResponse = 8;
    // constexpr static const auto MaxNumWorkers        = 4096;
    constexpr static const auto NumBuffers           = 1024; //MaxNumPksPerResponse * MaxNumWorkers;
    constexpr static const auto MaxBufferSize        = sizeof(sg_msg_t);

    enum class Status {
        Waiting,
        Ready,
        TimedOut,
        Error
    };

    friend Service;

private:
    // DATA MEMBERS
    bool                       d_isActive = false;
    int                        d_requestID;
    const std::vector<Worker>* d_workers;
    const std::vector<char*>*  d_packetBufferPool;
    unsigned int               d_expectedPacketsPerMessage = 1;
    Status                     d_status;
    std::chrono::microseconds  d_timeOut;
    GatherCompletionPolicy     d_completionPolicy;
    unsigned int               d_numWorkersToWait;
    // Fields only relevant if CtrlSockMode::Native is set
    CtrlSockMode               d_ctrlSockMode;
    bool                       d_ctrlSockReady;
    sg_msg_t                   d_ctrlSkBuf;

    std::chrono::time_point<std::chrono::steady_clock> d_startTime;

    // Points to the location of a packet buffer in the global packet memory buffer
    struct PacketBufferPointer {
        uint16_t bgid;  // Buffer Group ID (index into global buffer vector)
        uint16_t bid;   // Buffer ID (index into the buffer group)
    };

    // Map worker socket file descriptors to the received packets
    using WorkerBufferPointerMap = std::unordered_map<int, std::vector<PacketBufferPointer>>;

    WorkerBufferPointerMap d_workerBufferPtrs;

public:

    Request() = default;

    Request(int requestID, 
            const ReqParams& params,
            const std::vector<char*>* packetBufferPool,
            const std::vector<Worker>* workers,
            PacketAction packetAction,
            CtrlSockMode ctrlSockMode);


    inline int id() const { return d_requestID; }

    inline bool isActive() const { return d_isActive; }

    inline const std::vector<Worker>& workers() const { return *d_workers; }

    inline bool isReady(bool ctrlSockOnly = false) const { 
        if (d_ctrlSockMode == CtrlSockMode::Native)
            return ctrlSockOnly ? d_ctrlSockReady : d_ctrlSockReady && d_status == Status::Ready;
        
        return d_status == Status::Ready;
    }

    inline bool isExpired() const { return d_status == Status::TimedOut; }

    // Methods below are only relevant if PacketAction::Discard is set

    inline const WorkerBufferPointerMap& bufferPointers() const { return d_workerBufferPtrs; };

    inline const char* data(const PacketBufferPointer& packetPtr) const {
        return ((*d_packetBufferPool)[packetPtr.bgid] + packetPtr.bid * Request::MaxBufferSize);
    }

    // Methods below are only relevant if CtrlSockMode::Native is set

    inline const sg_msg_t* ctrlSockData() const { return &d_ctrlSkBuf; }

protected:
    bool hasTimedOut() const;

    void addBufferPtr(int workerFd, uint16_t bgid, uint16_t bid);

    void startTimer();

    bool receivedSufficientPackets() const;

    bool receivedWaitAny() const;

    bool receivedWaitN(uint32_t numWorkers) const;
};



} // close namespace sgbpf


#endif // !_SGBPF_REQUEST_H
