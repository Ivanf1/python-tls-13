from dataclasses import dataclass


@dataclass
class CertificateVerifyMessage:
    handshake_message_type: bytes
    bytes_of_handshake_data: bytes
    signature_type: bytes
    bytes_of_signature_data: bytes
    signature: bytes

    def to_bytes(self):
        return self.handshake_message_type + \
            self.bytes_of_handshake_data + \
            self.signature_type + \
            self.bytes_of_signature_data + \
            self.signature
