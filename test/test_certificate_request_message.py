import unittest

from src.messages.certificate_request_message import CertificateRequestMessage


class TestCertificateRequestMessage(unittest.TestCase):
    def setUp(self):
        handshake_message_type = bytes.fromhex("0d")
        bytes_of_handshake_data = bytes.fromhex("00 00 27")
        bytes_of_extensions = bytes.fromhex("00 00 24")
        signature_algorithms_extension = bytes.fromhex("""00 0d 00 20
         00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06
         01 02 01 04 02 05 02 06 02 02 02""")

        self.certificate_request_message = CertificateRequestMessage(
            handshake_message_type,
            bytes_of_handshake_data,
            bytes_of_extensions,
            signature_algorithms_extension
        )

    def test_should_return_certificate_request_message_bytes(self):
        certificate_request_message = self.certificate_request_message.to_bytes()
        expected_certificate_request_message = bytes.fromhex("""
            0d 00 00 27 00 00 24 00 0d 00 20
            00 1e 04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06
            01 02 01 04 02 05 02 06 02 02 02""")
        self.assertEqual(certificate_request_message, expected_certificate_request_message)