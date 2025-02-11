import sys
import time
from os import path
import socket
import binascii

sys.path.insert(1, path.join(sys.path[0], '..', '..'))

from src.tls_server_session import TlsServerSession

server_name = "localhost"

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((server_name, 65432))
server_socket.listen(1)

print("Server is listening...\n")
conn, addr = server_socket.accept()
print(f"Connected by {addr}")

def on_data_to_send(data):
    print("Sending data to client: %s\n" % binascii.hexlify(data))
    conn.sendall(data)

certificate_path = path.join(path.dirname(__file__), "..", "..", "test", "data", "server_cert.der")
certificate_private_key_path = path.join(path.dirname(__file__), "..", "..", "test", "data", "server_key.pem")

def on_connected():
    print("TLS connection established with client\n")
    msg = session.build_application_message(b"Hello from server")
    print("Sending APPLICATION data to client: %s\n" % binascii.hexlify(msg))
    conn.sendall(msg)

    time.sleep(5)

    msg = session.build_application_message(b"Hello again from server")
    print("Sending APPLICATION data to client: %s\n" % binascii.hexlify(msg))
    conn.sendall(msg)

    session.end()

def on_application_data(data):
    data = data.decode('utf-8')
    print("Received application data from client: %s\n" % data)

if __name__ == "__main__":
    session = TlsServerSession(on_data_to_send,
                               certificate_path,
                               certificate_private_key_path,
                               on_connected,
                               on_application_data,
                               )
    session.start()

    while True:
        data = conn.recv(4096)
        if not data:
            break
        print("Received data from client: %s\n" % binascii.hexlify(data))
        session.on_record_received(data)