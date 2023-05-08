#ifndef _SGBPF_SERVICE_H
#define _SGBPF_SERVICE_H

#include "Request.h"
#include "Context.h"
#include "Common.h"

#include <iostream>
#include <unordered_map>
#include <cassert>
#include <net/if.h>
#include <unistd.h>
#include <liburing.h>

namespace sgbpf 
{


class Service 
{
private:
    // DATA MEMBERS
    int                     d_scatterSkFd;  // Scatter socket
    sockaddr_in             d_scatterSkAddr;
    int                     d_ctrlSkFd;     // Gather control socket
    Context&                d_ctx;
    std::vector<Worker>     d_workers;

    const uint16_t PORT = 9225;    // just generate and add to map

    std::unordered_map<int, Request>   d_activeRequests;
    IOUringContext d_ioCtx;

    static uint32_t s_nextRequestID;

public:

    Service(Context& ctx,
            const std::vector<Worker>& workers);

    ~Service();

    Request* scatter(const char* msg, size_t len, ReqParams params = {});

    int ctrlSkFd() const { return d_ctrlSkFd; }

    void processEvents();

    void processRequestEvents(int requestID);

private:

    constexpr static const int DEFAULT_REQUEST_ID = -1;
    void processPendingEvents(int requestID = DEFAULT_REQUEST_ID);
};


} // close namespace sgbpf


#endif // !_SGBPF_SERVICE_H
