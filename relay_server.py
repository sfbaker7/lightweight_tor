import sys
import socket
import json

 #TODO: Change to read from config file later, OS.environ

def main():
    listen()

def listen():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind(('localhost', 5000))
    serversocket.listen(5)
    while True:
        clientsocket, address = serversocket.accept()
        payload = clientsocket.recv(4096).decode('utf-8')
        clientsocket.close()

    return

def get_pk(): #DELETE LATER, private key lookup from directory
    directory_socket = socket.socket()
    directory_socket.connect(('localhost', 3000))
    payload = directory_socket.recv(4096).decode('utf-8')  # payload is received as buffer, decode to get str type
    directory_socket.close()
    relay_nodes = json.loads(payload)
    print(relay_nodes)
    return relay_nodes['localhost'][1]

PRIVATE_KEY = get_pk()

if __name__ == '__main__':
    main()
