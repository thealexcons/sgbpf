'''
Sends dummy requests to the controller node to initiate some distributed task.
Usage: python3 client.py <CONTROLLER_DEST:CONTROLLER_PORT>
'''
import socket
import sys


def send_request(host: str, port: int):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        message = "REQ"
        s.sendall(message.encode())
        data = s.recv(1024)
        print("Got result:", repr(data))


if __name__ == '__main__':
    host, port = sys.argv[1].split(':')

    while True:
        req = input("Enter to send request ")
        send_request(host, int(port))
