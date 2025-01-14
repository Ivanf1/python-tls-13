import unittest

from src.messages.certificate_message import CertificateMessage


class TestCertificateMessage(unittest.TestCase):
    def test_should_return_request_context(self):
        certificate_message = CertificateMessage()
        self.assertEqual(certificate_message.REQUEST_CONTEXT, b'\x00')
