import unittest

from src.messages.certificate_verify_message import CertificateVerifyMessage


class TestCertificateVerifyMessage(unittest.TestCase):
    def test_should_return_signature(self):
        m = CertificateVerifyMessage(f"../test/data/private_key.pem")
        signature = m.get_signature(b'')
        self.assertIs(len(signature), 256)

    def test_should_return_certificate_verify_message(self):
        m = CertificateVerifyMessage(f"../test/data/private_key.pem")
        certificate_verify_message = m.get_certificate_verify_message(b'')
        certificate_verify_message_first_bytes = certificate_verify_message[:4]
        expected_certificate_verify_message_first_bytes = bytes.fromhex("""08 04 01 00""")
        self.assertEqual(certificate_verify_message_first_bytes, expected_certificate_verify_message_first_bytes)