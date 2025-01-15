from src.tls_crypto import get_hmac_sha256


class HandshakeFinishedMessageBuilder:
    def __init__(self):
        self.HANDSHAKE_MESSAGE_TYPE_FINISHED = b'\x14'

    def get_verify_data(self, finished_key, finished_hash):
        return get_hmac_sha256(finished_hash, finished_key)

    def get_handshake_finished(self, finished_key, finished_hash):
        verify_data = self.get_verify_data(finished_key, finished_hash)
        verify_data_len = len(verify_data).to_bytes(3)

        return self.HANDSHAKE_MESSAGE_TYPE_FINISHED + verify_data_len + verify_data