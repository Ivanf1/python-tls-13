import binascii
import sys
from os import path
import socket

sys.path.insert(1, path.join(sys.path[0], '..', '..'))

from src.tls_client_session import TlsClientSession

server_name = "localhost"

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((server_name, 65432))

def on_tls_connected():
    print("TLS connection established with server %s\n" % server_name)

trusted_root_certificate_path = path.join(path.dirname(__file__), "..", "..", "test", "data", "ca_cert.der")

def on_data_to_send(data):
    print("Sending data to server: %s\n" % binascii.hexlify(data))
    client_socket.sendall(data)

def on_application_data(data):
    data = data.decode('utf-8')
    print("Received application data from server: %s\n" % data)

if __name__ == "__main__":
    session = TlsClientSession(server_name,
                               on_tls_connected,
                               trusted_root_certificate_path,
                               on_data_to_send,
                               on_application_data,
                               )
    session.start()

    while True:
        data = client_socket.recv(4096)
        print("Received data from server: %s\n" % binascii.hexlify(data))
        session.on_record_received(data)