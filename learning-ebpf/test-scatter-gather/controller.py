'''
Accepts requests from clients and coordinates the distributed task over the workers
Usage: python3 controller.py <CONTROLLER_PORT> [<WORKER_HOSTS:WORKER_PORTS>]
'''

import socket
import sys
from typing import Tuple


def get_destination(worker_str) -> Tuple[str, int]:
    host, port = worker_str.split(':')
    return ((host, int(port)))


def start_distributed_task(conn, workers):
    """
    Start a distributed task for a client request.
    Invokes a scatter-gather primitive for the workers in the cluster.
    """
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Scatter the query to all the workers
    for worker in workers:
        query = "WORK"
        sk.sendto(query.encode(), get_destination(worker))

    # Wait and gather the results from all the workers
    results = []
    while len(results) < len(workers):
        data, _ = sk.recvfrom(1024)
        results.append(int(data.decode()))


    # Aggregate the results into a single response for the client
    results = list(map(int, results))
    s = sum(results, 0)
    resp = f"RES:{s}".encode()
    conn.sendall(resp)

    sk.close()


def handle_connection(conn, addr, workers):
    """
    Handle an incoming connection
    """
    print("Received connection from", addr)

    # Receive data from the client
    data = conn.recv(1024)

    if data.decode() == "REQ":
        start_distributed_task(conn, workers)

    # Close the connection
    conn.close()


if __name__ == '__main__':

    port = int(sys.argv[1])
    workers = sys.argv[2:]

    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", port))

    # Listen for incoming connections
    s.listen(5)
    print("Listening for incoming connections...")

    while True:
        # Accept a connection
        conn, addr = s.accept()

        # Handle the connection in a new thread
        handle_connection(conn, addr, workers)

    # Close the socket
    s.close()