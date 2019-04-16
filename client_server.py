#!/usr/bin/env python3

import sys
import socket
import json
import crypt
import base64
from random import shuffle

DIRECTORY_PORT = 3001
DIRECTORY_IP = 'localhost'
AES_KEY = crypt.gen_aes_key()

def main(message):
    relay_nodes = request_directory()
    circuit = generate_circuit(relay_nodes)
    encrypted_message = encrypt_payload(message, circuit, relay_nodes)
    send_request(encrypted_message)

def request_directory():
    """
    get list of relay nodes from directory
    """
    s = socket.socket()
    s.connect((DIRECTORY_IP, DIRECTORY_PORT))
    payload = s.recv(8192).decode()  # payload is received as buffer, decode to get str type
    print(payload)
    s.close()
    relay_nodes = json.loads(payload)
    return relay_nodes

def generate_circuit(nodes):
    """
    randomly select order of relay nodes
    """
    circuit = [str(ip) for ip in nodes.keys()]
    shuffle(circuit)
    return circuit

def serialize_payload(key, msg):
    return base64.b64encode(key + b'###' + msg)

def encrypt_payload(message, circuit, relay_nodes):
    """
    encrypt each layer of the request encrypt(encrypt(M + next_node) + next node)
    """
    node_stack = circuit
    next = message.encode()# final plaintext will be the original user request
    payload = b''
    while len(node_stack) != 0:
        curr_node_addr = node_stack.pop()
        public_key = base64.b64decode(relay_nodes[curr_node_addr][1]) #decode public key here
        print(public_key)
        print(type(public_key))
        if (isinstance(payload, tuple)):
          encrypted_aes_key, encrypted_payload = payload
          payload = serialize_payload(encrypted_aes_key, encrypted_payload)

        payload = encrypt(public_key, (payload + next))
        print('----')
        # break

        next = curr_node_addr

    return serialize_payload(payload[0], payload[1])


def decrypt_payload():
    """
    decrypt each layer of the request
    """
    return ''

def send_request(encrypted_message):
    """
    send request to first relay node
    """
    relay_socket = socket.socket()
    relay_socket.connect(('localhost', 5000))
    payload = encrypted_message
    relay_socket.send(payload)
    relay_socket.close()
    return

def encrypt(public_key, payload):
    print(type(payload))
    return crypt.encrypt(AES_KEY, public_key, payload)

def decrypt(private_key, payload):
    return crypto.decrypt(AES_KEY, private_key, payload)

if __name__ == '__main__':
    main("www.google.com")
