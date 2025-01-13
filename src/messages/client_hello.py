from src.tls_crypto import get_32_random_bytes

class ClientHello:
    def __init__(self):
        self.CLIENT_VERSION = b'\x03\x03'
        self.client_random = get_32_random_bytes()

    @staticmethod
    def get_supported_cipher_suites():
        """
        Only support TLS_AES_128_GCM_SHA256
        """
        TLS_AES_128_GCM_SHA256 = b'\x13\x01'
        return len(TLS_AES_128_GCM_SHA256).to_bytes(2) + TLS_AES_128_GCM_SHA256