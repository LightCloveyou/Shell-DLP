import socket

HOST = '11.111.11.111'
PORT = 8888
FILE_PATH = 'test.txt'

with socket.create_connection((HOST, PORT), timeout=10) as s:
    with open(FILE_PATH, 'rb') as f:
        while chunk := f.read(4096):
            s.sendall(chunk)

print('发送完成')