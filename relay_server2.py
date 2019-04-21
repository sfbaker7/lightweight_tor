#!/usr/bin/env python3

# python modules
import socket
import json
import base64
import requests
import traceback

# lightweight_tor modules
import crypt
import network

DIRECTORY_PORT = 3001
RELAY_PORT = 5003
FORWARDING_PORT = 7003
HASH_DELIMITER = b'###'
DECRYPTED_AES_KEY = ''
PRIVATE_KEY = ''

def main():
    # get RSA private key
    global PRIVATE_KEY
    PRIVATE_KEY = get_pk()
    # open socket connection
    listen()    

def listen():
  try:
    serversocket = network.start_server('localhost', RELAY_PORT)
    next_ip = None
    while True:
      print('CURRENT RELAY NODE: ' + str(RELAY_PORT))
      print('RECIEVING PORT:' + str(RELAY_PORT) + ' FORWARDING PORT:' + str(FORWARDING_PORT))

      # keep socket connection open and concatenate buffers
      clientsocket, address = serversocket.accept()
      payload = network.recv_by_size(clientsocket)

      # get previous ip address
      previous_ip = parse_address(address)
      print('received payload from: ', previous_ip)
      print('Payload (trunc): ', payload[:100])
      print('\n')
      
      # decrypt payload
      print('---- BEGIN DECRYPTION OF RECEIVED PAYLOAD ----')
      next_ip, message = deserialize_payload(payload)

      print('begin forwarding payload to next node...')
      response = forward_payload(next_ip, message)
      if response is not None:
        '''
        Case: send to previous_ip
        '''
        #encrypt layer
        print('Response returned from: ' + next_ip)
        print('\n')
        print('---- BEGIN ENCRYPTION OF RETURN PAYLOAD ----')
        print('Payload being encrypted (trunc):', response[:100])    
        print('aes_key used:', DECRYPTED_AES_KEY)
        encrypted_payload = network.prepend_length(serialize_payload(response))
        print('send payload to previous node: ', previous_ip)
        clientsocket.sendall(encrypted_payload)

      clientsocket.close()
  except Exception:
    print("Unable to connect to server")
    print(traceback.format_exc())         
    return

def deserialize_payload(payload):
    '''
    :param: bytestring payload: encrypted_aes_key, encrypted_message
    '''
    decoded_payload = base64.b64decode(payload)
    print('Decoded Payload (rsa_encrypt(aes_key) + aes_encrypt(payload)):', decoded_payload)
    print('\n')
    encrypted_aes_key, encrypted_message = split_bytes(HASH_DELIMITER, decoded_payload)
    global DECRYPTED_AES_KEY
    DECRYPTED_AES_KEY = crypt.decrypt_rsa(PRIVATE_KEY, encrypted_aes_key)
    next_ip, message = crypt.decrypt_payload(DECRYPTED_AES_KEY, encrypted_message) # decrypted_message = encypted_payload + next_ip
    print('Decrypted AES Key:', DECRYPTED_AES_KEY)
    print('Decrypted Payload:', next_ip, message)
    print('---- END DECRYPTION OF RECEIVED PAYLOD ----')
    print('\n')
    return next_ip, message

def serialize_payload(message):
    if not isinstance(message, bytes):
        raise Exception('Message should be of byte format, not ' , type(message))

    aes_encrypted_message = crypt.encrypt_aes(DECRYPTED_AES_KEY, message)
    return base64.b64encode(aes_encrypted_message)

def forward_payload(next_ip, message):
    if is_exit_node(message):
        print('EXIT NODE FOUND')
        print('begin request to destination')
        req = requests.get(next_ip)
        return req.text.encode()

    else:
        print('RELAY NODE FOUND')
        print('next relay node is: ' + next_ip)
        message = message.encode()
        host, port = next_ip.split(':')
        relay_socket = network.connect_server('localhost', FORWARDING_PORT, host, port)
        payload = network.prepend_length(message)
        relay_socket.sendall(payload)
        response = network.recv_by_size(relay_socket)

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

def get_pk(): # private key lookup from directory
    directory_socket = socket.socket()
    directory_socket.connect(('localhost', DIRECTORY_PORT))
    payload = directory_socket.recv(8192) # payload is received as bytes, decode to get as string
    directory_socket.close()
    relay_nodes = json.loads(payload)
    private_key = base64.b64decode(relay_nodes['localhost:' + str(RELAY_PORT)][0])

    return private_key

if __name__ == '__main__':
    main()
