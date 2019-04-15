#!/usr/bin/env python3

import sys
import socket
import json
import crypto
import base64
from random import shuffle

DIRECTORY_PORT = 3000
DIRECTORY_IP = 'localhost'
AES_KEY = crypto.gen_aes_key() 

def main(message):
    relay_nodes = request_directory()
    print(relay_nodes)
    circuit = generate_circuit(relay_nodes)
    print(circuit)
    encrypted_message = encrypt_payload(message, circuit, relay_nodes)
    print(encrypted_message)
    send_request(encrypted_message)

def request_directory():
    """
    get list of relay nodes from directory
    """
    s = socket.socket()
    s.connect((DIRECTORY_IP, DIRECTORY_PORT))
    payload = s.recv(4096).decode('utf-8')  # payload is received as buffer, decode to get str type

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
        print('public key', public_key)
        print('node', curr_node_addr)

        if (isinstance(payload, tuple)):
          encrypted_key, encrypted_message = payload
          print(len(encrypted_key), encrypted_key)

          padding = crypto.pad(encrypted_key.decode())
          # print('padding', padding, len(padding))
          key = base64.b64decode(encrypted_key + padding)
          # print('key', type(key), (key + ('=' * (-len(key) % 4).encode())).decode())
          msg = encrypted_message
          print('msg', type(msg), msg)
          payload = msg + b"###" + key
          # print(payload)
        payload = encrypt(public_key, (payload + next))
        next = curr_node_addr.encode('utf-8')

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
    return crypto.encrypt(AES_KEY, public_key, payload)

def decrypt(private_key, payload):
  return crypto.decrypt(AES_KEY, private_key, payload)

if __name__ == '__main__':
    main("www.google.com")
