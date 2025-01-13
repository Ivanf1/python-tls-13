import unittest

from src.messages.client_hello import ClientHello

class TestClientHello(unittest.TestCase):
    def test_should_return_client_version_tls_12(self):
        c = ClientHello()
        expected_client_version = bytes.fromhex("""03 03""")
        self.assertEqual(c.CLIENT_VERSION, expected_client_version)