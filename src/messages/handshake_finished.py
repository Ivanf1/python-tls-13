from src.tls_crypto import get_hmac_sha256


class HandshakeFinished:
    def __init__(self):
        self.HANDSHAKE_MESSAGE_TYPE_FINISHED = b'\x14'

    def get_verify_data(self, finished_key, finished_hash):
        return get_hmac_sha256(finished_hash, finished_key)