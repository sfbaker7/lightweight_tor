#!/usr/bin/env python3

import sys
import socket
import json
import crypt
import base64
import logger
from random import shuffle
from cryptography.fernet import Fernet

DIRECTORY_PORT = 3001
CLIENT_PORT = 4050
DIRECTORY_IP = 'localhost'
HASH_DELIMITER = b'###'
AES_KEY = crypt.gen_aes_key()

def main(message):
    logger.header('---- REQUEST RELAY NODES FROM DIRECTORY ----')
    relay_nodes = request_directory()
    logger.log('RELAY NODES: ', relay_nodes, True)
    logger.header('---- GENERATE CIRCUIT FOR ONION ROUTING ----')
    circuit = generate_circuit(relay_nodes)
    logger.log('CIRCUIT IS: ', circuit)
    circuit_copy = list(circuit)
    entry_node = circuit[0][0]
    logger.log('ENTRY NODE IS: ', entry_node, True)
    logger.header('---- BEGIN ENCRYPTION PROCESS TO WRAP ONION ----')
    encrypted_message = encrypt_payload(message, circuit, relay_nodes)
    logger.header('---- END ENCRYPTION PROCESS TO WRAP ONION ----')
    logger.log('ENCRYPTED MESSAGE: ', encrypted_message, True)
    logger.header('---- SEND REQUEST TO ENTRY NODE ----')
    response = send_request(encrypted_message, entry_node)
    logger.log('...onion routing via relay nodes', 3, True)
    logger.log('...received response from destination')
    logger.log('...received response from destination')
    byteStream = decrypt_payload(response, circuit_copy)
    result = byteStream.decode()
    logger.header('---- DECODED RESPONSE FROM DESTINATION ----\n')
    logger.log('', result)
    # write result to html file
    logger.header('---- BEGIN WRITE RESULT TO HTML FILE ----')
    f = open('response.html','w')
    f.write(result)
    f.close()
    logger.header('---- END WRITE RESULT TO HTML FILE ----')
    logger.header('---- OPEN ./response.html TO SEE RESPONSE ----')

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
    '''
    encode payload for transmission
    '''
    return base64.b64encode(aes_key + HASH_DELIMITER + message)

def encrypt_payload(message, circuit, relay_nodes):
    '''
    encrypt each layer of the request rsa_encrypt(AES_key) + aes_encrypt(M + next)
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

        payload = crypt.encrypt(curr_aes_key_instance, public_key, (payload + next.encode()))
        next = curr_node_addr

    return serialize_payload(payload[0], payload[1])


def decrypt_payload(payload, circuit):
    '''
    decrypt each layer of the request
    '''
    message = payload
    for i in range(len(circuit)):
        ip = circuit[i][0]
        aes_key = circuit[i][1]

        decoded_message = base64.b64decode(message)
        message = crypt.decrypt_aes(aes_key, decoded_message)

    return message

def send_request(encrypted_message, entry_node):
    '''
    send request to first relay node
    '''
    # print(entry_node)
    host, port = entry_node.split(':')
    relay_socket = socket.socket()
    relay_socket.bind(('localhost', CLIENT_PORT))
    relay_socket.connect((host, int(port)))
    payload = encrypted_message
    relay_socket.send(payload)
    response = relay_socket.recv(81920000)
    relay_socket.close()
    return response

if __name__ == '__main__':
  if len(sys.argv) < 2:
      raise Exception('No URL entered')
  url = sys.argv[1]
  main(url)
