import os
import sys
import requests
import socket
import json

DIRECTORY_PORT = 3000
DIRECTORY_IP = 'localhost'
RELAY_NODES = {}


def request_directory():
    """
    get list of relay nodes from directory
    """
    s = socket.socket()
    s.connect((DIRECTORY_IP, DIRECTORY_PORT))
    payload = s.recv(1024)
    s.close()
    RELAY_NODES = json.loads(payload)
    
    return

def generate_ciruit():
    """
    randomly select order of relay nodes
    """
    return ''

def encrypt_payload():
    """
    encrypt each layer of the request encrypt(encrypt(M + next_node) + next node)
    """

    return ''

def decrypt_payload():
    """
    decrypt each layer of the request
    """
    return ''

def send_request():
    """
    send request to first relay node
    """

    return ''

if __name__ == '__main__':
    request_directory()
