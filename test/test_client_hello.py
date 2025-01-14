import binascii
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.messages.client_hello import ClientHello


class TestClientHello(unittest.TestCase):
    def test_should_return_client_version_tls_12(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        expected_client_version = bytes.fromhex("""03 03""")
        self.assertEqual(c.CLIENT_VERSION, expected_client_version)

    def test_should_return_client_random(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        self.assertIs(len(c.client_random), 32)

    def test_should_return_supported_cipher_suites(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        supported_cipher_suites = c.get_supported_cipher_suites()
        expected_supported_cipher_suites = bytes.fromhex("""00 02 13 01""")
        self.assertEqual(supported_cipher_suites, expected_supported_cipher_suites)

    def test_should_return_server_name_extension(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("example.ulfheim.net", public_key)
        server_name_extension = c.get_extension_server_name_extension()
        expected_server_name_extension = bytes.fromhex("""00 00 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 
            68 65 69 6d 2e 6e 65 74""")
        self.assertEqual(server_name_extension, expected_server_name_extension)

    def test_should_return_supported_groups_extension(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        supported_groups_extension = c.get_supported_groups_extension()
        expected_supported_groups_extension = bytes.fromhex("""00 0a 00 02 00 1d""")
        self.assertEqual(supported_groups_extension, expected_supported_groups_extension)

    def test_should_return_signature_algorithms_extension(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        signature_algorithms_extension = c.get_signature_algorithms_extension()
        expected_signature_algorithms_extension = bytes.fromhex("""00 0d 00 02 04 03""")
        self.assertEqual(signature_algorithms_extension, expected_signature_algorithms_extension)

    def test_should_return_supported_versions_extension(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        supported_versions_extension = c.get_supported_versions_extension()
        expected_supported_versions_extension = bytes.fromhex("""00 2b 00 02 03 04""")
        self.assertEqual(supported_versions_extension, expected_supported_versions_extension)

    def test_should_build_key_share_extension(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        key_share_extension = c.get_key_share_extension()
        expected_key_share_extension = bytes.fromhex("""00 33 00 24 00 1d 00 20""") + c.public_key.public_bytes_raw()
        self.assertEqual(key_share_extension, expected_key_share_extension)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-4
    def test_should_return_client_hello_message_header(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("", public_key)
        data = bytes.fromhex("""03 03 cb 34 ec b1 e7 81 63 ba
         1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12 ec 18 a2 ef 62 83 02
         4d ec e7 00 00 06 13 01 13 03 13 02 01 00 00 91 00 00 00 0b 00
         09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00 14 00 12
         00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04 00 23 00
         00 00 33 00 26 00 24 00 1d 00 20 99 38 1d e5 60 e4 bd 43 d2 3d
         8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d 54 13 69 1e 52 9a af
         2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03 06 03 02
         03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05 02 06 02
         02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        client_hello_message_header = c.get_message_header(data)
        expected_client_hello_message_header = bytes.fromhex("""01 00 00 c0""")
        self.assertEqual(client_hello_message_header, expected_client_hello_message_header)

    def test_should_return_extensions_list(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHello("example.ulfheim.net", public_key)
        extensions_list = c.get_extensions_list()
        expected_extensions_list = bytes.fromhex("""00 54 00 00 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 
            68 65 69 6d 2e 6e 65 74 00 0a 00 02 00 1d 00 0d 00 02 04 03 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20""") \
            + c.public_key.public_bytes_raw()
        self.assertEqual(extensions_list, expected_extensions_list)
