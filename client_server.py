#!/usr/bin/env python3

import sys
import socket
import json
import crypt
import base64
from random import shuffle

DIRECTORY_PORT = 3001
CLIENT_PORT = 4050
DIRECTORY_IP = 'localhost'
HASH_DELIMITER = b'###'
AES_KEY = crypt.gen_aes_key()

def main(message):
    relay_nodes = request_directory()
    circuit = generate_circuit(relay_nodes)
    entry_node = circuit[0][0]
    encrypted_message = encrypt_payload(message, circuit, relay_nodes)
    send_request(encrypted_message, entry_node)

def request_directory():
    """
    get list of relay nodes from directory
    """
    s = socket.socket()
    s.connect((DIRECTORY_IP, DIRECTORY_PORT))
    payload = s.recv(8192).decode()  # payload is received as bytes, decode to get str type
    # print(payload)
    s.close()
    relay_nodes = json.loads(payload)
    return relay_nodes

def generate_circuit(nodes):
    """
    randomly select order of relay nodes
    """
    circuit = [(str(ip), crypt.gen_aes_key()) for ip in nodes.keys()]
    shuffle(circuit)
    return circuit

def serialize_payload(aes_key, message):
    return base64.b64encode(aes_key + HASH_DELIMITER + message)

def encrypt_payload(message, circuit, relay_nodes):
    '''
    encrypt each layer of the request encrypt(encrypt(M + next_node) + next node)
    '''
    node_stack = circuit
    next = message # final plaintext will be the original user request
    payload = b''
    while len(node_stack) != 0:
        curr_node = node_stack.pop()
        curr_node_addr = curr_node[0]
        curr_aes_key_instance = curr_node[1]
        public_key = base64.b64decode(relay_nodes[curr_node_addr][1]) #decode public key here
        if (isinstance(payload, tuple)):
          encrypted_aes_key, encrypted_payload = payload
          payload = serialize_payload(encrypted_aes_key, encrypted_payload)

        # payload encrypt(public_key, (payload + next.encode())) #potential for encoding inconsistancy
        payload = crypt.encrypt(curr_aes_key_instance, public_key, (payload + next.encode()))
        next = curr_node_addr

    return serialize_payload(payload[0], payload[1])


def decrypt_payload():
    """
    decrypt each layer of the request
    """
    return ''

def send_request(encrypted_message, entry_node):
    """
    send request to first relay node
    """
    print(entry_node)
    host, port = entry_node.split(':')
    relay_socket = socket.socket()
    relay_socket.bind(('localhost', CLIENT_PORT))
    relay_socket.connect((host, int(port)))
    payload = encrypted_message
    relay_socket.send(payload)
    response = relay_socket.recv(8192)
    relay_socket.close()
    print(response)
    return

def encrypt(public_key, payload):
    print(type(payload))
    return crypt.encrypt(AES_KEY, public_key, payload)

def decrypt(private_key, payload):
    return crypt.decrypt(AES_KEY, private_key, payload)

if __name__ == '__main__':
    main("http://www.google.com")
