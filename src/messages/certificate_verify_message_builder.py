from src.messages.certificate_verify_message import CertificateVerifyMessage
from src.tls_crypto import get_certificate_verify_signature
from src.utils import SignatureAlgorithms, HandshakeMessageType


class CertificateVerifyMessageBuilder:
    def __init__(self, private_key_path: str):
        self.private_key_path = private_key_path

    def get_certificate_verify_message(self, handshake_hash):
        signature = get_certificate_verify_signature(handshake_hash, self.private_key_path)
        signature_len = len(signature)

        payload_len = (signature_len + 2 + 2).to_bytes(3)

        return CertificateVerifyMessage(
            HandshakeMessageType.CERTIFICATE_VERIFY.value,
            payload_len,
            SignatureAlgorithms.RSA_PSS_RSAE_SHA256.value,
            signature_len.to_bytes(2),
            signature,
        )

    @staticmethod
    def build_from_bytes(message_bytes: bytes):
        """
        Builds a CertificateVerifyMessage object from a byte representation of a certificate message.

        :param message_bytes: The bytes of the message.
        :return: CertificateVerifyMessage
        """
        handshake_message_type = message_bytes[0:1]
        bytes_of_handshake_data = message_bytes[1:4]
        signature_type = message_bytes[4:6]
        bytes_of_signature_data = message_bytes[6:8]
        signature = message_bytes[8:]

        return CertificateVerifyMessage(
            handshake_message_type=handshake_message_type,
            bytes_of_handshake_data=bytes_of_handshake_data,
            signature_type=signature_type,
            bytes_of_signature_data=bytes_of_signature_data,
            signature=signature
        )
