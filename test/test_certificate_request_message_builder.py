import unittest

from src.messages.certificate_request_message_builder import CertificateRequestMessageBuilder


class TestCertificateRequestMessageBuilder(unittest.TestCase):
    def setUp(self):
        self.message_bytes = bytes.fromhex("0d 00 00 27 00 00 24 00 0d 00 02 08 09")

    def test_should_return_signature_algorithms_extension(self):
        extension = CertificateRequestMessageBuilder().get_signature_algorithms_extension()
        expected_extension = bytes.fromhex("00 0d 00 02 08 09")
        self.assertEqual(extension, expected_extension)

    def test_should_build_certificate_request_message(self):
        certificate_request_message = CertificateRequestMessageBuilder().get_certificate_request_message()
        expected_certificate_request_message = bytes.fromhex("""0d 00 00 09 00 00 06 00 0d 00 02 08 09""")
        self.assertEqual(certificate_request_message.to_bytes(), expected_certificate_request_message)

    def test_should_build_certificate_request_message_correct_handshake_type(self):
        certificate_request_message = CertificateRequestMessageBuilder.build_from_bytes(self.message_bytes)
        expected_handshake_type = bytes.fromhex("0d")
        self.assertEqual(certificate_request_message.handshake_message_type, expected_handshake_type)

    def test_should_build_certificate_request_message_correct_bytes_of_handshake_data(self):
        certificate_request_message = CertificateRequestMessageBuilder.build_from_bytes(self.message_bytes)
        expected_bytes_of_handshake_data = bytes.fromhex("00 00 27")
        self.assertEqual(certificate_request_message.bytes_of_handshake_data, expected_bytes_of_handshake_data)

    def test_should_build_certificate_request_message_correct_bytes_of_extensions(self):
        certificate_request_message = CertificateRequestMessageBuilder.build_from_bytes(self.message_bytes)
        expected_bytes_of_handshake_extensions = bytes.fromhex("00 00 24")
        self.assertEqual(certificate_request_message.bytes_of_extensions, expected_bytes_of_handshake_extensions)

    def test_should_build_certificate_request_message_correct_signature_algorithms_extension(self):
        certificate_request_message = CertificateRequestMessageBuilder.build_from_bytes(self.message_bytes)
        expected_signature_algorithms_extension = bytes.fromhex("00 0d 00 02 08 09")
        self.assertEqual(certificate_request_message.signature_algorithms_extension, expected_signature_algorithms_extension)
