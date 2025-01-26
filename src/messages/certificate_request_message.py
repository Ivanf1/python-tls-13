from dataclasses import dataclass


@dataclass
class CertificateRequestMessage:
    handshake_message_type: bytes
    bytes_of_handshake_data: bytes
    bytes_of_extensions: bytes
    signature_algorithms_extension: bytes

    def to_bytes(self):
        return self.handshake_message_type + \
            self.bytes_of_handshake_data + \
            self.bytes_of_extensions + \
            self.signature_algorithms_extension