## Baseline applications using standard IO APIs

This directory contains alternative implementations of the scatter gather operation using standard IO APIs available on modern Linux systems. They demonstrate performance differences depending on the number of system calls, number of copies and context switches, all using the same dummy workload (vector of 4-byte integers which are summed up) and importantly, **performing data aggregation in user-space** over the individual worker responses (ie: no eBPF). In these examples, it assumes a "Wait All" completion policy (which represents the "worst case" in terms of the number of syscalls).

This functionality has been implemented using:

- Naive blocking IO (via standard `read`/`write` syscalls) - see `naive_sg.cpp`
- Event-based notification IO (via `epoll`) - see `event_sg.cpp`
- Asynchronous batched IO (via `io_uring`) - see `async_sg.cpp`

Note that the code for these three versions does not implement any type request handling from clients (which would be the case in a real-life application); they simply perform scatter-gather requests repeatedly. We are interested in the performance of the scatter-gather primitive, not in the design/implementation of a high-performance server. For this reason, these implementations are single-threaded, just like `sgbpf`.

Reminder: [epoll vs io_uring - io_uring is not an event system ](https://news.ycombinator.com/item?id=27540248)