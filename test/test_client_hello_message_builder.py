import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.utils import TLSVersion


class TestClientHelloMessageBuilder(unittest.TestCase):
    def setUp(self):
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.client_hello = ClientHelloMessageBuilder("example.ulfheim.net", self.public_key)

    def test_should_return_client_version_tls_12(self):
        expected_client_version = bytes.fromhex("""03 03""")
        self.assertEqual(TLSVersion.V1_2.value, expected_client_version)

    def test_should_return_client_random(self):
        self.assertIs(len(self.client_hello.client_random), 32)

    def test_should_return_supported_cipher_suites(self):
        supported_cipher_suites = self.client_hello.get_supported_cipher_suites()
        expected_supported_cipher_suites = bytes.fromhex("""00 02 13 01""")
        self.assertEqual(supported_cipher_suites, expected_supported_cipher_suites)

    def test_should_return_server_name_extension(self):
        server_name_extension = self.client_hello.get_extension_server_name_extension()
        expected_server_name_extension = bytes.fromhex("""00 00 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 
            68 65 69 6d 2e 6e 65 74""")
        self.assertEqual(server_name_extension, expected_server_name_extension)

    def test_should_return_supported_groups_extension(self):
        supported_groups_extension = self.client_hello.get_supported_groups_extension()
        expected_supported_groups_extension = bytes.fromhex("""00 0a 00 02 00 1d""")
        self.assertEqual(supported_groups_extension, expected_supported_groups_extension)

    def test_should_return_signature_algorithms_extension(self):
        signature_algorithms_extension = self.client_hello.get_signature_algorithms_extension()
        expected_signature_algorithms_extension = bytes.fromhex("""00 0d 00 02 08 09""")
        self.assertEqual(signature_algorithms_extension, expected_signature_algorithms_extension)

    def test_should_return_supported_versions_extension(self):
        supported_versions_extension = self.client_hello.get_supported_versions_extension()
        expected_supported_versions_extension = bytes.fromhex("""00 2b 00 02 03 04""")
        self.assertEqual(supported_versions_extension, expected_supported_versions_extension)

    def test_should_build_key_share_extension(self):
        key_share_extension = self.client_hello.get_key_share_extension()
        expected_key_share_extension = bytes.fromhex("""00 33 00 24 00 1d 00 20""") + self.client_hello.public_key.public_bytes_raw()
        self.assertEqual(key_share_extension, expected_key_share_extension)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-4
    def test_should_return_client_hello_message_header(self):
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
        client_hello_message_header = self.client_hello.get_message_header(data)
        expected_client_hello_message_header = bytes.fromhex("""01 00 00 c0""")
        self.assertEqual(client_hello_message_header, expected_client_hello_message_header)

    def test_should_return_extensions_list(self):
        extensions_list = self.client_hello.get_extensions_list()
        expected_extensions_list = bytes.fromhex("""00 54 00 00 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 
            68 65 69 6d 2e 6e 65 74 00 0a 00 02 00 1d 00 0d 00 02 08 09 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20""") \
            + self.client_hello.public_key.public_bytes_raw()
        self.assertEqual(extensions_list, expected_extensions_list)

    @patch("secrets.token_bytes")
    def test_should_return_client_hello_message(self, mock_get_32_random_bytes):
        mock_random_bytes = b'\x00' * 32
        mock_get_32_random_bytes.return_value = mock_random_bytes

        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        c = ClientHelloMessageBuilder("example.ulfheim.net", public_key)

        client_hello_message = c.build_client_hello_message().to_bytes()
        expected_client_hello_message = bytes.fromhex(
            """0100007c03030000000000000000000000000000000000000000000000000000000000000000000213010054000000160000136578616d706c652e756c666865696d2e6e6574000a0002001d000d00020809002b0002030400330024001d0020"""
        ) + c.public_key.public_bytes_raw()
        self.assertEqual(client_hello_message, expected_client_hello_message)

    def test_should_build_client_hello_message_from_bytes_correct_handshake_message_type(self):
        data = bytes.fromhex("""01 00 00 c0 03 03 cb
         34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
         ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00
         00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
         00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
         01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
         e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d
         54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
         04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
         01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_handshake_message_type = bytes.fromhex("01")
        self.assertEqual(message.handshake_message_type, expected_handshake_message_type)

    def test_should_build_client_hello_message_from_bytes_correct_bytes_of_client_hello_data(self):
        data = bytes.fromhex("""01 00 00 c0 03 03 cb
         34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
         ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00
         00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
         00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
         01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
         e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d
         54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
         04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
         01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_bytes_of_client_hello_data = bytes.fromhex("00 00 c0")
        self.assertEqual(message.bytes_of_client_hello_data, expected_bytes_of_client_hello_data)

    def test_should_build_client_hello_message_from_bytes_correct_client_version(self):
        data = bytes.fromhex("""01 00 00 c0 03 03 cb
         34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
         ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00
         00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
         00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
         01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
         e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d
         54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
         04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
         01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_client_version = bytes.fromhex("03 03")
        self.assertEqual(message.client_version, expected_client_version)

    def test_should_build_client_hello_message_from_bytes_correct_client_random(self):
        data = bytes.fromhex("""01 00 00 c0 03 03 cb
         34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
         ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00
         00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
         00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
         01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
         e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d
         54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
         04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
         01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_client_random = bytes.fromhex("""cb
         34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
         ec 18 a2 ef 62 83 02 4d ec e7""")
        self.assertEqual(message.client_random, expected_client_random)

    def test_should_build_client_hello_message_from_bytes_correct_cipher_suites(self):
        data = bytes.fromhex("""01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_cipher_suites = bytes.fromhex("""00 08 13 01""")
        self.assertEqual(message.cipher_suites, expected_cipher_suites)

    def test_should_build_client_hello_message_from_bytes_correct_extensions_length(self):
        data = bytes.fromhex("""01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_extensions_length = bytes.fromhex("""00 a3""")
        self.assertEqual(message.extensions_length, expected_extensions_length)

    def test_should_build_client_hello_message_from_bytes_correct_extension_server_name(self):
        data = bytes.fromhex("""01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_server_name = bytes.fromhex("""00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74""")
        self.assertEqual(message.extension_server_name, expected_server_name)

    def test_should_build_client_hello_message_from_bytes_correct_extension_supported_groups(self):
        data = bytes.fromhex("""01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_supported_groups = bytes.fromhex("""00 0a 00 16 00 1d""")
        self.assertEqual(message.extension_supported_groups, expected_supported_groups)

    def test_should_build_client_hello_message_from_bytes_correct_extension_signature_algorithms(self):
        data = bytes.fromhex("""01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_signature_algorithms = bytes.fromhex("""00 0d 00 1e 04 03""")
        self.assertEqual(message.extension_signature_algorithms, expected_signature_algorithms)

    def test_should_build_client_hello_message_from_bytes_correct_extension_supported_versions(self):
        data = bytes.fromhex("""01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_supported_versions = bytes.fromhex("""00 2b 00 02 03 04""")
        self.assertEqual(message.extension_supported_versions, expected_supported_versions)

    def test_should_build_client_hello_message_from_bytes_correct_extension_key_share(self):
        data = bytes.fromhex("""01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        message = ClientHelloMessageBuilder.build_from_bytes(data)
        expected_key_share = bytes.fromhex("""00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")
        self.assertEqual(message.extension_key_share, expected_key_share)
