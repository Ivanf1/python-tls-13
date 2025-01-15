from dataclasses import dataclass


@dataclass
class HandshakeFinishedMessage:
    handshake_message_type: bytes
    bytes_of_handshake_data: bytes
    verify_data: bytes

    def to_bytes(self):
        return self.handshake_message_type + \
            self.bytes_of_handshake_data + \
            self.verify_data