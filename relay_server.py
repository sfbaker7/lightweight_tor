import sys
import socket

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 5000))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        payload = clientsocket.recv(4096).decode('utf-8')


def deserialize_payload(payload):
    encrypted_message, AES_key = payload.split(b'###')
    print(encrypted_message)
