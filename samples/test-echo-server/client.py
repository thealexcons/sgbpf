import socket

HOST = '127.0.0.1'
PORT = 9922

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("Connected")
    while True:
        data = input("String to send: ")
        s.sendall(str.encode(data))
        data = s.recv(1024)
        print('Echoing: ', repr(data))
