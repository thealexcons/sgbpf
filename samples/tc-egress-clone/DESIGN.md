SCATTER:

- Create a single UDP socket for sending out
- Register all the destinations in an eBPF map of IPs
- The egress TC program should clone the packet and deliver it to all the desti>
    - If cannot iterate over map, use string parsing to get all the IPs


GATHER (no aggregation):

- Open N+1 receiving UDP sockets:
    - 1 control socket
    - 1 socket per worker
- Register the worker UDP sockets' ports in an eBPF map
- The XDP program should notify the control socket once it has received all soc>
    - XDP_PASS all packets, then clone a dummy END packet into the control sock>
