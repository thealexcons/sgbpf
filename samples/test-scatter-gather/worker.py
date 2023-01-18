'''
Listens for requests from the controller and executes some local task
Usage: python3 worker.py <WORKER_PORT>
'''

import socket
import sys
import random
import time

def perform_task() -> int:
    """
    Performs a dummy task
    """
    time.sleep(random.random(0, 2))
    return random.randint(0, 1000)



if __name__ == '__main__':

    port = int(sys.argv[1])

    # Create a socket object
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", port))

    while True:
        data, addr = s.recvfrom(1024)
        if data.decode() == "WORK":
            result = perform_task()
            print("Produced value", result)
            s.sendto(str(result).encode(), addr)

    # Close the socket
    s.close()