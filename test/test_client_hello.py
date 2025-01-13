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