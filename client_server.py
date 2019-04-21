#!/usr/bin/env python3

import sys
import socket
import json
import crypt
import base64
import struct
from random import shuffle
from cryptography.fernet import Fernet

DIRECTORY_PORT = 3001
CLIENT_PORT = 4050
DIRECTORY_IP = 'localhost'
HASH_DELIMITER = b'###'
AES_KEY = crypt.gen_aes_key()

def main(message):
    print('---- REQUEST RELAY NODES FROM DIRECTORY ----')  
    relay_nodes = request_directory()
    print('RELAY NODES: ', relay_nodes)
    print('\n')
    print('---- GENERATE CIRCUIT FOR ONION ROUTING ----')
    circuit = generate_circuit(relay_nodes)
    print('CIRCUIT IS: ', circuit)
    circuit_copy = list(circuit)
    entry_node = circuit[0][0]
    print('ENTRY NODE IS: ', entry_node)
    print('\n')
    print('---- BEGIN ENCRYPTION PROCESS TO WRAP ONION ----')
    encrypted_message = encrypt_payload(message, circuit, relay_nodes)
    print('---- END ENCRYPTION PROCESS TO WRAP ONION ----')
    print('ENCRYPTED MESSAGE: ', encrypted_message)
    print('\n')
    print('---- SEND REQUEST TO ENTRY NODE ----')
    response = send_request(encrypted_message, entry_node)
    print('...onion routing via relay nodes')
    print('...onion routing via relay nodes')
    print('...onion routing via relay nodes')
    print('\n')
    print('...received response from destination')
    byteStream = decrypt_payload(response, circuit_copy)
    result = byteStream.decode()
    print('---- DECODED RESPONSE FROM DESTINATION ----\n')
    print(result)
    # write result to html file
    print('---- BEGIN WRITE RESULT TO HTML FILE ----')
    f = open('response.html','w')
    f.write(result)
    f.close()
    print('---- END WRITE RESULT TO HTML FILE ----')
    print('---- OPEN ./response.html TO SEE RESPONSE ----')

def request_directory():
    """
    get list of relay nodes from directory
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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


def decrypt_payload(payload, circuit):
    """
    decrypt each layer of the request
    """
    message = payload
    for i in range(len(circuit)):
        # ip = circuit[i][0]
        aes_key = circuit[i][1]

        decoded_message = base64.b64decode(message)
        message = crypt.decrypt_aes(aes_key, decoded_message)

    return message

def send_request(encrypted_message, entry_node):
    """
    send request to first relay node
    """
    # print(entry_node)
    host, port = entry_node.split(':')
    relay_socket = socket.socket()
    relay_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    relay_socket.bind(('localhost', CLIENT_PORT))
    relay_socket.connect((host, int(port)))
    packet_size = struct.pack('>i', len(encrypted_message))
    payload = packet_size + encrypted_message
    relay_socket.sendall(payload)
    response = b""
    while True:
      incomingBuffer = relay_socket.recv(8192)
      print('buffer length', len(incomingBuffer), incomingBuffer)
      if not incomingBuffer: break
      response += incomingBuffer
    # response = relay_socket.recv(81920000)
    relay_socket.close()
    return response

if __name__ == '__main__':
  url = sys.argv[1]
  main(url)
