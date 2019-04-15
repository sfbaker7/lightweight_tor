#!/usr/bin/env python3

import socket
import json
import crypto

#stub values for now
RELAY_NODES = {
    '192.0.2.1' : crypto.gen_rsa_key()[0].decode(),
    '192.0.2.2' : crypto.gen_rsa_key()[0].decode(),
    '192.0.2.3' : crypto.gen_rsa_key()[0].decode()
}

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 3000))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        # base64.b64decode
        payload = json.dumps(RELAY_NODES).encode('utf-8') # python3 doesn't allow sending of strings across UDP
        print (payload)
        clientsocket.send(payload)
        clientsocket.close()
    return


if __name__ == '__main__':
    main()
