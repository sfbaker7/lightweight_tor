#!/usr/bin/env python3
import base64
import socket
import json
import crypt

keypair1 = crypt.gen_rsa_keypair()
keypair2 = crypt.gen_rsa_keypair()
keypair3 = crypt.gen_rsa_keypair()

RELAY_NODES = {
    'localhost' : list(crypt.get_pem_format(keypair1[0], keypair1[1])),
    # '192.0.2.2' : list(crypt.get_pem_format(keypair2[0], keypair2[1])),
    # '192.0.2.3' : list(crypt.get_pem_format(keypair3[0], keypair3[1]))
}

RELAY_NODES['localhost'] = [base64.b64encode(RELAY_NODES['localhost'][0]).decode('ascii'), base64.b64encode(RELAY_NODES['localhost'][1]).decode('ascii')]

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 3001))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        # print(RELAY_NODES)
        payload = json.dumps(RELAY_NODES) # python3 doesn't allow sending of strings across UDP
        print (payload)
        # print('\n')
        clientsocket.send(payload.encode())
        clientsocket.close()
    return

def get_private_key(): #delete later
  return RELAY_NODES


if __name__ == '__main__':
    main()
