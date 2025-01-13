import unittest

from src.messages.client_hello import ClientHello

class TestClientHello(unittest.TestCase):
    def test_should_return_client_version_tls_12(self):
        c = ClientHello("")
        expected_client_version = bytes.fromhex("""03 03""")
        self.assertEqual(c.CLIENT_VERSION, expected_client_version)

    def test_should_return_client_random(self):
        c = ClientHello("")
        self.assertIs(len(c.client_random), 32)

    def test_should_return_supported_cipher_suites(self):
        c = ClientHello("")
        supported_cipher_suites = c.get_supported_cipher_suites()
        expected_supported_cipher_suites = bytes.fromhex("""00 02 13 01""")
        self.assertEqual(supported_cipher_suites, expected_supported_cipher_suites)

    def test_should_return_server_name_extension(self):
        c = ClientHello("example.ulfheim.net")
        server_name_extension = c.get_extension_server_name()
        expected_server_name_extension = bytes.fromhex("""00 00 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 
            68 65 69 6d 2e 6e 65 74""")
        self.assertEqual(server_name_extension, expected_server_name_extension)

