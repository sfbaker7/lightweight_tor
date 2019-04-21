import struct, socket, sys

def recv_by_size(socket_conn):
  # data length is packed into 4 bytes
  total_len = 0; payload = b''; size = sys.maxsize
  size_data = sock_data = b''; recv_size = 8192

  while (total_len < size):
    sock_data = socket_conn.recv(recv_size)

    if not payload:
      if len(sock_data)>4:
        size_data += sock_data
        size=struct.unpack('>i', size_data[:4])[0]
        recv_size=size

        if recv_size>524288: recv_size=524288
        payload += size_data[4:]
      else:
        size_data+=sock_data

    else:
      payload += sock_data
    total_len = len(payload)

  return payload

def start_server(host ,port):
  server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  server_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  server_socket.bind((host, port))
  server_socket.listen(5)

  return server_socket

def connect_server(forward_host, foward_port, connect_host, connect_port):
  connection_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  connection_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  connection_socket.bind((forward_host, foward_port))
  connection_socket.connect((connect_host, int(connect_port)))

  return connection_socket

def prepend_length(message):
  packet_size = struct.pack('>i', len(message))
  payload = packet_size + message

  return payload