from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from src.messages.certificate_verify_message import CertificateVerifyMessage
from src.utils import SignatureAlgorithms


class CertificateVerifyMessageBuilder:
    def __init__(self, private_key_path: str):
        self.HANDSHAKE_MESSAGE_TYPE_CERTIFICATE_VERIFY = b'\x0f'
        self.private_key_path = private_key_path

    def get_signature(self, handshake_hash):
        context_string = b'TLS 1.3, server CertificateVerify'

        # 64 bytes of 0x20 (space)
        prefix = b"\x20" * 64

        data_to_sign = prefix + context_string + b"\x00" + handshake_hash

        # Load the RSA private key from the PEM file
        with open(self.private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

            signature = private_key.sign(
                data_to_sign,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            return signature

    def get_certificate_verify_message(self, handshake_hash):
        signature = self.get_signature(handshake_hash)
        signature_len = len(signature)

        payload_len = (signature_len + 2 + 2).to_bytes(3)

        return CertificateVerifyMessage(
            self.HANDSHAKE_MESSAGE_TYPE_CERTIFICATE_VERIFY,
            payload_len,
            SignatureAlgorithms.RSA_PSS_RSAE_SHA256.value,
            signature_len.to_bytes(2),
            signature,
        )
