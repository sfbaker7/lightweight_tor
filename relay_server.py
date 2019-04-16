#!/usr/bin/env python3

import sys
import socket
import json
import base64
import crypt

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 5000))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        payload = clientsocket.recv(8192)
        res = deserialize_payload(payload)
        clientsocket.close()
        break

    return

def get_pk(): #DELETE LATER, private key lookup from directory
    directory_socket = socket.socket()
    directory_socket.connect(('localhost', 3000))
    payload = base64.b64decode(directory_socket.recv(8192)) # payload is received as buffer, decode to get str type
    directory_socket.close()
    relay_nodes = json.loads(payload)
    private_key = relay_nodes['localhost'][0]
    if (isinstance(private_key, unicode)):
      private_key = private_key.encode('UTF8')
    return private_key

PRIVATE_KEY = get_pk()

def deserialize_payload(payload):
    '''
    :param: bytestring payload: encrypted_aes_key, encrypted_payload
    '''
    encrypted_aes_key, encrypted_payload = base64.b64decode(payload).split('###')
    print('encrypted_aes_key, encrypted_payload', encrypted_aes_key, encrypted_payload)

    decrypted_aes_key = crypt.decrypt_rsa(PRIVATE_KEY, encrypted_aes_key)
    print('aes_key', decrypted_aes_key)
    print(type(encrypted_payload))
    ip, message = crypt.decrypt_payload(decrypted_aes_key, encrypted_payload) # decrypted_message = encypted_payload + next_ip
    print(ip, message)
    return

if __name__ == '__main__':
    main()
