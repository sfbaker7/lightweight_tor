#!/usr/bin/env python3

import sys
import socket
import json
import base64
import crypt
import requests

DIRECTORY_PORT = 3001

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 5000))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        payload = clientsocket.recv(8192)
        # print(payload)
        # print(type(payload))
        print('payload recieved from clientsocket', len(payload))

        clientsocket.close()
        next_ip, message = deserialize_payload(payload)
        forward_payload(next_ip, message)
        break

    return

def split_bytes(delimiter, bytestring):
    if not isinstance(delimiter, bytes):
        raise Exception('Delimiter used should be of byte format, not ' , type(delimiter))
    hash_index = bytestring.find(delimiter)
    encrypted_aes_key = bytestring[:hash_index]
    encrypted_message = bytestring[hash_index + len(delimiter):]

    return encrypted_aes_key, encrypted_message

def deserialize_payload(payload):
    '''
    :param: bytestring payload: encrypted_aes_key, encrypted_message
    '''
    decoded_payload = base64.b64decode(payload)
    encrypted_aes_key, encrypted_message = split_bytes(b'###', decoded_payload)
    decrypted_aes_key = crypt.decrypt_rsa(PRIVATE_KEY, encrypted_aes_key)
    ip, message = crypt.decrypt_payload(decrypted_aes_key, encrypted_message) # decrypted_message = encypted_payload + next_ip
    return ip, message

def forward_payload(next_ip, message):
    if is_valid_ip(next_ip):
        #request website
        req = requests.get(message)
        print(req.text)
    else:
        next_ip = 'foo'
        #connect to socket of next relay
    return

def is_valid_ip(ip_addr):
    return True

def get_pk(): #DELETE LATER, private key lookup from directory
    directory_socket = socket.socket()
    directory_socket.connect(('localhost', DIRECTORY_PORT))
    payload = directory_socket.recv(8192) # payload is received as bytes, decode to get as string
    directory_socket.close()
    relay_nodes = json.loads(payload)
    private_key = base64.b64decode(relay_nodes['localhost'][0])

    return private_key

PRIVATE_KEY = get_pk()


if __name__ == '__main__':
    main()
