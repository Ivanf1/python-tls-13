from dataclasses import dataclass


@dataclass
class CertificateMessage:
    handshake_message_type: bytes
    bytes_of_certificate_payload: bytes
    request_context: bytes
    certificates_length: bytes
    certificate_length: bytes
    certificate: bytes
    certificate_extensions: bytes

    def to_bytes(self):
        return self.handshake_message_type + \
            self.bytes_of_certificate_payload + \
            self.request_context + \
            self.certificates_length + \
            self.certificate_length + \
            self.certificate + \
            self.certificate_extensions