from src.messages.handshake_finished_message import HandshakeFinishedMessage
from src.tls_crypto import get_hmac_sha256


class HandshakeFinishedMessageBuilder:
    def __init__(self):
        self.HANDSHAKE_MESSAGE_TYPE_FINISHED = b'\x14'

    def get_verify_data(self, finished_key, finished_hash):
        return get_hmac_sha256(finished_hash, finished_key)

    def get_handshake_finished(self, finished_key, finished_hash):
        verify_data = self.get_verify_data(finished_key, finished_hash)
        verify_data_len = len(verify_data).to_bytes(3)

        return HandshakeFinishedMessage(
            self.HANDSHAKE_MESSAGE_TYPE_FINISHED,
            verify_data_len,
            verify_data,
        )

    @staticmethod
    def build_from_bytes(message_bytes: bytes):
        handshake_message_type = message_bytes[0:1]
        bytes_of_handshake_data = message_bytes[1:4]
        verify_data = message_bytes[4:]

        return HandshakeFinishedMessage(
            handshake_message_type=handshake_message_type,
            bytes_of_handshake_data=bytes_of_handshake_data,
            verify_data=verify_data
        )
