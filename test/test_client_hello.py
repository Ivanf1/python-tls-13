import unittest

from src.messages.client_hello import ClientHello

class TestClientHello(unittest.TestCase):
    def test_should_return_client_version_tls_12(self):
        c = ClientHello()
        expected_client_version = bytes.fromhex("""03 03""")
        self.assertEqual(c.CLIENT_VERSION, expected_client_version)

    def test_should_return_client_random(self):
        c = ClientHello()
        self.assertIs(len(c.client_random), 32)

    def test_should_return_supported_cipher_suites(self):
        c = ClientHello()
        supported_cipher_suites = c.get_supported_cipher_suites()
        expected_supported_cipher_suites = bytes.fromhex("""00 02 13 01""")
        self.assertEqual(supported_cipher_suites, expected_supported_cipher_suites)
