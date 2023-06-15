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

/**
 * @brief The completion policy for a scatter-gather request
 */
enum class GatherCompletionPolicy 
{
    WaitAll,
    WaitAny,
    WaitN,
};

/**
 * @brief The parameters for a scatter-gather request
 */
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

/**
 * @brief The packet action which determines the fate of the packet
 */
enum class PacketAction 
{
    Discard,
    Allow,
};

/**
 * @brief The data delivery API which determines how the aggregated data is consumed.
 */
enum class CtrlSockMode
{
    DefaultUnix,    // use as a raw Unix file descriptor
    Block,          // use io_uring + buffer, blocks until ctrl sk is ready
    BusyWait,       // use io_uring + buffer, user must busy wait on Request::isReady()
    Ringbuf         // use epoll notification-based polling on a ringbuf with callback
};


/**
 * @brief A handle to a scatter-gather request
 */
class Request
{
public:
    constexpr static const auto MaxBufferSize        = sizeof(sg_msg_t);

    // The status of a request
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
    // Fields only relevant if CtrlSockMode::Block is set
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

    /**
     * @brief Construct a new Request object
     * 
     * @param requestID the unique ID
     * @param params the parameters to configure the request
     * @param packetBufferPool a pointer to the global pool of buffers for packets
     * @param workers the list of workers involved in the request
     * @param packetAction the packet action
     * @param ctrlSockMode the data delivery mode
     */
    Request(int requestID, 
            const ReqParams& params,
            const std::vector<char*>* packetBufferPool,
            const std::vector<Worker>* workers,
            PacketAction packetAction,
            CtrlSockMode ctrlSockMode);

    /**
     * @brief Returns the request ID
     */
    inline int id() const { return d_requestID; }

    /**
     * @brief Checks whether the request is in-flight
     */
    inline bool isActive() const { return d_isActive; }

    /**
     * @brief Returns the list of workers involved in this request
     */
    inline const std::vector<Worker>& workers() const { return *d_workers; }

    /**
     * @brief Checks if a request is ready (completed). 
     * This method only makes sense if CtrlSockMode::{Block, BusyWait} are set 
     * or if PacketAction::Allow is set
     * 
     * @param waitForCtrlSockOnly specify whether to only wait for the control socket rather than all
     * the individual packets
     */
    inline bool isReady(bool waitForCtrlSockOnly = false) const { 
        if (d_ctrlSockMode == CtrlSockMode::Block || d_ctrlSockMode == CtrlSockMode::BusyWait)
            return waitForCtrlSockOnly ? d_ctrlSockReady : d_ctrlSockReady && d_status == Status::Ready;

        return d_status == Status::Ready;
    }

    /**
     * @brief Returns the final aggregated data available from the control socket
     * 
     * This method only makes sense if CtrlSockMode::{Block, BusyWait} are set 
     */
    inline const sg_msg_t* ctrlSockData() const { return &d_ctrlSkBuf; }

    /**
     * @brief Checks whether the request has timed out
     */
    inline bool hasExpired() const { return d_status == Status::TimedOut || hasTimedOut(); }


    /**
     * @brief Returns the pointers to the response packet buffers
     * This method is only relevant if PacketAction::Allow is set
     * 
     */
    inline const WorkerBufferPointerMap& bufferPointers() const { return d_workerBufferPtrs; };

    /**
     * @brief Returns a pointer to the packet data
     * This method is only relevant if PacketAction::Allow is set
     * 
     * @param packetPtr the pointer to the packet
     * @return const char* the packet data
     */
    inline const char* data(const PacketBufferPointer& packetPtr) const {
        return ((*d_packetBufferPool)[packetPtr.bgid] + packetPtr.bid * Request::MaxBufferSize);
    }


protected:
    // check if the request has timed out by comparing the elapsed time with the start time
    bool hasTimedOut() const;

    // add a new packet buffer pointer for a received packet
    void addBufferPtr(int workerFd, uint16_t bgid, uint16_t bid);

    // start the timer for the request
    void startTimer();

    // check whether enough individual packets have been received and the completion has satisfied
    bool receivedSufficientPackets() const;

    // check completion for wait any strategy for PacketAction::Allow
    bool receivedWaitAny() const;

    // check completion for wait n strategy for PacketAction::Allow
    bool receivedWaitN(uint32_t numWorkers) const;
};



} // close namespace sgbpf


#endif // !_SGBPF_REQUEST_H
