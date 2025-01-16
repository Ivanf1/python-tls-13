import unittest

from src.tls_session import TlsSession


class TestTlsSession(unittest.TestCase):
    def setUp(self):
        self.tls_session = TlsSession("example.com")

    def test_should_return_client_hello_message_on_start(self):
        client_hello = self.tls_session.start()
        self.assertEqual(client_hello[5:6], b'\x01')