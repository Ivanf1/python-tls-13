import unittest

from src.messages.certificate_verify_message_builder import CertificateVerifyMessageBuilder


class TestCertificateVerifyMessageBuilder(unittest.TestCase):
    def test_should_return_signature(self):
        m = CertificateVerifyMessageBuilder(f"../test/data/private_key.pem")
        signature = m.get_signature(b'')
        self.assertIs(len(signature), 256)

    def test_should_return_certificate_verify_message_new(self):
        m = CertificateVerifyMessageBuilder(f"../test/data/private_key.pem")
        certificate_verify_message = m.get_certificate_verify_message(b'').to_bytes()
        certificate_verify_message_first_bytes = certificate_verify_message[:8]
        expected_certificate_verify_message_first_bytes = bytes.fromhex("""0f 00 01 04 08 04 01 00""")
        self.assertEqual(certificate_verify_message_first_bytes, expected_certificate_verify_message_first_bytes)
