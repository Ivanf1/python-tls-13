from src.tls_crypto import get_32_random_bytes

class ClientHello:
    def __init__(self):
        self.CLIENT_VERSION = b'\x03\x03'
        self.client_random = get_32_random_bytes()