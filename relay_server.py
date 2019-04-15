#!/usr/bin/env python3

import sys
import socket
import json
import base64

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 5000))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        payload = clientsocket.recv(4096)
        res = deserialize_payload(payload)

        clientsocket.close()

    return

def get_pk(): #DELETE LATER, private key lookup from directory
    directory_socket = socket.socket()
    directory_socket.connect(('localhost', 3000))
    payload = directory_socket.recv(8192).decode('utf-8')  # payload is received as buffer, decode to get str type
    directory_socket.close()
    relay_nodes = json.loads(payload)
    print(relay_nodes['localhost'][1])
    return relay_nodes['localhost'][1]

PRIVATE_KEY = get_pk()

def deserialize_payload(payload):
    encrypted_key, encrypted_message = str(base64.b64decode(payload)).split('###')
    print(encrypted_key)
    print(encrypted_message)
    return encrypted_message

if __name__ == '__main__':
    main()
