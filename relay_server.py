#!/usr/bin/env python3 

import sys
import socket
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

def deserialize_payload(payload):
    encrypted_key, encrypted_message = str(base64.b64decode(payload)).split('###')
    print(encrypted_key)
    print(encrypted_message)
    return encrypted_message

if __name__ == '__main__':
    main()
