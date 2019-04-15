#!/usr/bin/env python3

import socket
import json

#stub values for now
RELAY_NODES = {
    '192.0.2.1' : 'priv-key1',
    '192.0.2.2' : 'priv-key2',
    '192.0.2.3' : 'priv-key3'
}

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 3000))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        print (clientsocket, address)
        payload = json.dumps(RELAY_NODES).encode() # python3 doesn't allow sending of strings across UDP
        print (payload)
        clientsocket.send(payload)
        clientsocket.close()
    return


if __name__ == '__main__':
    main()
