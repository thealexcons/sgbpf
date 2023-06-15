#ifndef _SGBPF_SERVICE_H
#define _SGBPF_SERVICE_H

#include "Request.h"
#include "Context.h"
#include "Common.h"

#include <iostream>
#include <functional>
#include <unordered_map>
#include <cassert>
#include <net/if.h>
#include <unistd.h>
#include <sys/mman.h>
#include <liburing.h>

namespace sgbpf 
{

/**
 * @brief Launches and manages scatter-gather requests
 */
class Service 
{
private:
    // DATA MEMBERS
    int                                 d_scatterSkFd;
    sockaddr_in                         d_scatterSkAddr;
    int                                 d_ctrlSkFd;
    Context&                            d_ctx;
    std::vector<Worker>                 d_workers;
    IOUringContext                      d_ioCtx;
    size_t                              d_numSkReads;
    std::vector<char*>                  d_packetBufferPool;
    Request*                            d_activeRequests;
    PacketAction                        d_packetAction;
    CtrlSockMode                        d_ctrlSockMode;
    ring_buffer*                        d_ringBuf;
    std::function<void(char*, int)>     d_notificationRingBufCallback;

    static uint32_t s_nextRequestID;

    constexpr static const uint16_t PORT = 9225;    // just generate and add to map
    constexpr static const int DEFAULT_REQUEST_ID = -1;
    constexpr static const int NUM_BUFFERS = std::numeric_limits<uint16_t>::max();

    friend int handleRingBufEpollEvent(void* ctx, void* data, size_t data_sz);

public:

    /**
     * @brief Construct a new Service object
     * 
     * @param ctx the context object
     * @param workers the list of workers that participate in the request
     * @param packetAction the packet action (should match the value in the aggregation program)
     * @param ctrlSockMode the data delivery mode
     * @param enableAllGatherBroadcast enable all-gather broadcast mode
     */
    Service(Context& ctx,
            const std::vector<Worker>& workers,
            PacketAction packetAction,
            CtrlSockMode ctrlSockMode = CtrlSockMode::DefaultUnix,
            bool enableAllGatherBroadcast = false);

    ~Service();

    /**
     * @brief Launch a new scatter operation
     * The behaviour of this method depends on the parameters specified to the Service constructor.
     * 
     * @param msg the data to be sent in the body of the scatter message
     * @param len the length of the data to be sent
     * @param params the optional request parameters
     * @return Request* a handle to the in-flight scatter-gather request
     */
    Request* scatter(const char* msg, size_t len, ReqParams params = {});

    /**
     * @brief Returns the Unix file descriptor associated with the control socket
     */
    int ctrlSkFd() const { return d_ctrlSkFd; }

    /**
     * @brief Process the completion events of scatter-gather requests and update their status if needed.
     * 
     * @param requestID the optional ID of the request to processs
     */
    void processEvents(int requestID = DEFAULT_REQUEST_ID);

    /**
     * @brief Free the resources associated with the scatter-gather request
     * 
     * @param req the pointer to the scatter-gather request
     * @param immediate perform the cleanup immediately (requires system call)
     */
    void freeRequest(Request* req, bool immediate = false);

    /**
     * @brief Set the callback function that executes whenever aggregated data is received on completion.
     * This method is only relevant if CtrlSockMode::Ringbuf is set
     * 
     * @param cb the callback function to execute on completion of a scatter-gather operation
     */
    inline void setRingbufCallback(const std::function<void(char*, int)>& cb) {
        assert(d_ctrlSockMode == CtrlSockMode::Ringbuf);
        d_notificationRingBufCallback = std::move(cb);
    }

    /**
     * @brief Poll the ring buffer for completed operations using epoll
     * 
     * @param timeout_ms the timeout parameter internally passed to epoll_wait
     * @return int the number of completion events returned
     */
    inline int epollRingbuf(int timeout_ms) {
        assert(d_ctrlSockMode == CtrlSockMode::Ringbuf);
        return ring_buffer__poll(d_ringBuf, timeout_ms);
    }

private:
    // process the completion events posted to the io_uring CQ
    void processPendingEvents(int requestID);

    // replenish the packet buffers
    uint16_t provideBuffers(bool immediate = false);
};

} // close namespace sgbpf


#endif // !_SGBPF_SERVICE_H
