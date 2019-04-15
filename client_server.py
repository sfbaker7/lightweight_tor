#!/usr/bin/env python3

import sys
import socket
import json
import crypto
from random import shuffle

DIRECTORY_PORT = 3000
DIRECTORY_IP = 'localhost'

def main(message):
    relay_nodes = request_directory()
    circuit = generate_circuit(relay_nodes)
    print(circuit)
    encrypted_message = encrypt_payload(message, circuit, relay_nodes)
    send_request(encrypted_message)

def request_directory():
    """
    get list of relay nodes from directory
    """
    s = socket.socket()
    s.connect((DIRECTORY_IP, DIRECTORY_PORT))
    payload = s.recv(1024).decode()  # payload is received as buffer, decode to get str type
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

def encrypt_payload(message, circuit, relay_nodes):
    """
    encrypt each layer of the request encrypt(encrypt(M + next_node) + next node)
    """
    node_stack = circuit
    next = message # final plaintext will be the original user request
    payload = ''
    while len(node_stack) != 0:
        curr_node_addr = node_stack.pop()
        public_key = relay_nodes[curr_node_addr]
        payload = encrypt((payload + next), public_key)
        next = curr_node_addr

    return payload


def decrypt_payload():
    """
    decrypt each layer of the request
    """
    return ''

def send_request(encrypted_message):
    """
    send request to first relay node
    """

    return ''

def encrypt(public_key, payload):
    global AES_KEY = crypte.gen_aes_key() 
    return crypto.encrypt(AES_KEY, public_key, payload)

def decrypt(private_key, payload):
  return crypto.decrypt(AES_KEY, private_key, payload)

if __name__ == '__main__':
    main("www.google.com")
