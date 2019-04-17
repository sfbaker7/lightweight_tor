#!/usr/bin/env python3

import sys
import socket
import json
import base64
import crypt
import requests

DIRECTORY_PORT = 3001
RELAY_PORT = 5003
FORWARDING_PORT = 7003
HASH_DELIMITER = b'###'

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', RELAY_PORT))
    serversocket.listen(5)
    next_ip = None
    while True:
        print('RECIEVER PORT:' + str(RELAY_PORT) + ' SENDER IP:' + str(FORWARDING_PORT))
        clientsocket, address = serversocket.accept()
        payload = clientsocket.recv(8192000000)
        previous_ip = parse_address(address)
        print('FROM >>>> ', previous_ip)
        next_ip, message = deserialize_payload(payload)
        response = forward_payload(next_ip, message)
        if response is not None:
            '''
            Case: exit node
            '''
            #encrypt layer
            print('TO <<<<<<', previous_ip)

            encrypted_payload = serialize_payload(response)
            print(decrypted_aes_key)

            clientsocket.sendall(encrypted_payload)

        clientsocket.close()

    return

def deserialize_payload(payload):
    '''
    :param: bytestring payload: encrypted_aes_key, encrypted_message
    '''
    decoded_payload = base64.b64decode(payload)
    encrypted_aes_key, encrypted_message = split_bytes(HASH_DELIMITER, decoded_payload)
    global decrypted_aes_key
    decrypted_aes_key = crypt.decrypt_rsa(PRIVATE_KEY, encrypted_aes_key)
    next_ip, message = crypt.decrypt_payload(decrypted_aes_key, encrypted_message) # decrypted_message = encypted_payload + next_ip
    return next_ip, message

def serialize_payload(message):
    if not isinstance(message, bytes):
        raise Exception('Message should be of byte format, not ' , type(message))

    aes_encrypted_message = crypt.encrypt_aes(decrypted_aes_key, message)
    return base64.b64encode(aes_encrypted_message)

def forward_payload(next_ip, message):
    if is_exit_node(message):
        #request website
        req = requests.get(next_ip)
        #encrypt layer
        return req.text.encode()
    else:
        payload = message.encode()
        host, port = next_ip.split(':')

        relay_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        relay_socket.bind(('localhost', FORWARDING_PORT))
        print('>>>> TO localhost:', port)
        relay_socket.connect((host, int(port)))
        relay_socket.send(payload)
        response = relay_socket.recv(819200000)
        print('<<<<< FROM localhost:', port)
        # print('RESPONSE DATA:', response)
        relay_socket.close()
        return response

    return

def is_exit_node(message): #think of better way to check?
    return True if message is '' else False

def parse_address(addr):
    return addr[0] + ':' + str(addr[1])

def split_bytes(delimiter, bytestring):
    if not isinstance(delimiter, bytes):
        raise Exception('Delimiter used should be of byte format, not ' , type(delimiter))
    hash_index = bytestring.find(delimiter)
    encrypted_aes_key = bytestring[:hash_index]
    encrypted_message = bytestring[hash_index + len(delimiter):]

    return encrypted_aes_key, encrypted_message

def get_pk(): #DELETE LATER, private key lookup from directory
    directory_socket = socket.socket()
    directory_socket.connect(('localhost', DIRECTORY_PORT))
    payload = directory_socket.recv(8192) # payload is received as bytes, decode to get as string
    directory_socket.close()
    relay_nodes = json.loads(payload)
    private_key = base64.b64decode(relay_nodes['localhost:' + str(RELAY_PORT)][0])

    return private_key

PRIVATE_KEY = get_pk()


if __name__ == '__main__':
    main()
