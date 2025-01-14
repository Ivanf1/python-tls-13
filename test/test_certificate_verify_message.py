import binascii
import unittest

from src.messages.certificate_verify_message import CertificateVerifyMessage


class TestCertificateVerifyMessage(unittest.TestCase):
    def test_should_return_signature(self):
        m = CertificateVerifyMessage(f"../test/data/private_key.pem")
        signature = m.get_signature(b'')
        self.assertIs(len(signature), 256)
