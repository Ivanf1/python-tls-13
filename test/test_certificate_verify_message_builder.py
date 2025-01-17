import unittest

from src.messages.certificate_verify_message_builder import CertificateVerifyMessageBuilder


class TestCertificateVerifyMessageBuilder(unittest.TestCase):
    def setUp(self):
        self.certificate_verify_message = bytes.fromhex("""0f 00 00 84 08 04 00 80 5a 74 7c
         5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
         b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
         86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
         be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
         5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
         3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3""")

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

    def test_should_build_certificate_verify_message_from_bytes_correct_handshake_message_type(self):
        message = CertificateVerifyMessageBuilder.build_from_bytes(self.certificate_verify_message)
        expected_handshake_message_type = bytes.fromhex("0f")
        self.assertEqual(message.handshake_message_type, expected_handshake_message_type)

    def test_should_build_certificate_verify_message_from_bytes_correct_bytes_of_handshake_data(self):
        message = CertificateVerifyMessageBuilder.build_from_bytes(self.certificate_verify_message)
        expected_bytes_of_handshake_data = bytes.fromhex("00 00 84")
        self.assertEqual(message.bytes_of_handshake_data, expected_bytes_of_handshake_data)

    def test_should_build_certificate_verify_message_from_bytes_correct_signature_type(self):
        message = CertificateVerifyMessageBuilder.build_from_bytes(self.certificate_verify_message)
        expected_signature_type = bytes.fromhex("08 04")
        self.assertEqual(message.signature_type, expected_signature_type)

    def test_should_build_certificate_verify_message_from_bytes_correct_bytes_of_signature_data(self):
        message = CertificateVerifyMessageBuilder.build_from_bytes(self.certificate_verify_message)
        expected_bytes_of_signature_data = bytes.fromhex("00 80")
        self.assertEqual(message.bytes_of_signature_data, expected_bytes_of_signature_data)

    def test_should_build_certificate_verify_message_from_bytes_correct_signature(self):
        message = CertificateVerifyMessageBuilder.build_from_bytes(self.certificate_verify_message)
        expected_signature = bytes.fromhex("""5a 74 7c
         5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
         b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
         86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
         be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
         5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
         3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3""")
        self.assertEqual(message.signature, expected_signature)
