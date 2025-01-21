from dataclasses import dataclass


@dataclass
class EncryptedExtensionsMessage:
    handshake_message_type: bytes
    bytes_of_handshake_data: bytes
    bytes_of_extensions: bytes
    extensions: bytes

    def to_bytes(self):
        return self.handshake_message_type + \
            self.bytes_of_handshake_data + \
            self.bytes_of_extensions + \
            self.extensions
