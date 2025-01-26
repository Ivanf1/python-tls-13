import unittest

from src.messages.certificate_request_message_builder import CertificateRequestMessageBuilder


class TestCertificateRequestMessageBuilder(unittest.TestCase):
    def test_should_return_signature_algorithms_extension(self):
        extension = CertificateRequestMessageBuilder().get_signature_algorithms_extension()
        expected_extension = bytes.fromhex("00 0d 00 02 08 09")
        self.assertEqual(extension, expected_extension)