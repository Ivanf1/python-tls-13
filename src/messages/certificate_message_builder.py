from src.messages.certificate_message import CertificateMessage
from src.utils import HandshakeMessageType


class CertificateMessageBuilder:
    def __init__(self, certificate):
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
            HandshakeMessageType.CERTIFICATE.value,
            payload_length.to_bytes(3),
            self.REQUEST_CONTEXT,
            certificates_length.to_bytes(3),
            certificate_length.to_bytes(3),
            self.certificate,
            certificate_extensions,
        )

    @staticmethod
    def build_from_bytes(message_bytes: bytes):
        """
        Builds a CertificateMessage object from a byte representation of a certificate message.

        :param message_bytes: The bytes of the message.
        :return: CertificateMessage
        """
        handshake_message_type = message_bytes[0:1]
        bytes_of_certificate_payload = message_bytes[1:4]
        request_context = message_bytes[4:5]
        certificates_length = message_bytes[5:8]
        certificate_length = message_bytes[8:11]
        certificate = message_bytes[11:-2]
        certificate_extensions = message_bytes[-2:]

        return CertificateMessage(
            handshake_message_type=handshake_message_type,
            bytes_of_certificate_payload=bytes_of_certificate_payload,
            request_context=request_context,
            certificates_length=certificates_length,
            certificate_length=certificate_length,
            certificate=certificate,
            certificate_extensions=certificate_extensions
        )
