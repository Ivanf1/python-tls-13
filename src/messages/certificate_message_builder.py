from src.messages.certificate_message import CertificateMessage


class CertificateMessageBuilder:
    def __init__(self, certificate):
        self.HANDSHAKE_MESSAGE_TYPE_CERTIFICATE = b'\x0b'
        self.REQUEST_CONTEXT = b'\x00'
        self.certificate = certificate

    def get_certificate_payload(self):
        """
        The certificate payload includes:\n
        - Request Context \n
        - Certificates Length \n
        - Certificate Length \n
        - Certificate \n
        - Certificate Extensions \n

        :return: certificate payload
        """

        certificate_len = len(self.certificate).to_bytes(3)
        certificate_extensions = b'\x00\x00'

        certificates_len = (len(certificate_len) + len(self.certificate) + len(certificate_extensions)).to_bytes(3)

        return self.REQUEST_CONTEXT + \
            certificates_len + \
            certificate_len + \
            self.certificate + \
            certificate_extensions

    def get_certificate_message(self):
        certificate_length = len(self.certificate)
        certificate_extensions = b'\x00\x00'

        certificates_length = len(certificate_length.to_bytes(3)) + len(self.certificate) + len(certificate_extensions)
        payload_length = len(self.REQUEST_CONTEXT) + certificates_length + 3

        return CertificateMessage(
            self.HANDSHAKE_MESSAGE_TYPE_CERTIFICATE,
            payload_length.to_bytes(3),
            self.REQUEST_CONTEXT,
            certificates_length.to_bytes(3),
            certificate_length.to_bytes(3),
            self.certificate,
            certificate_extensions,
        )