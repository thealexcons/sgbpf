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

    Service(Context& ctx,
            const std::vector<Worker>& workers,
            PacketAction packetAction,
            CtrlSockMode ctrlSockMode = CtrlSockMode::DefaultUnix,
            bool enableAllGatherBroadcast = false);

    ~Service();

    Request* scatter(const char* msg, size_t len, ReqParams params = {});

    int ctrlSkFd() const { return d_ctrlSkFd; }

    void processEvents(int requestID = DEFAULT_REQUEST_ID);

    void freeRequest(Request* req, bool immediate = false);

    // The methods below are only relevant if CtrlSockMode::Ringbuf is set
    inline void setRingbufCallback(const std::function<void(char*, int)>& cb) {
        assert(d_ctrlSockMode == CtrlSockMode::Ringbuf);
        d_notificationRingBufCallback = std::move(cb);
    }

    inline int epollRingbuf(int timeout_ms) {
        assert(d_ctrlSockMode == CtrlSockMode::Ringbuf);
        return ring_buffer__poll(d_ringBuf, timeout_ms);
    }

private:

    void processPendingEvents(int requestID);

    uint16_t provideBuffers(bool immediate = false);
};

} // close namespace sgbpf


#endif // !_SGBPF_SERVICE_H
