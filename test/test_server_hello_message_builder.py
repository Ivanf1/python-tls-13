import binascii
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.utils import TLSVersion

class TestServerHelloMessageBuilder(unittest.TestCase):
    def setUp(self):
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        self.server_hello = ServerHelloMessageBuilder(self.public_key)

    def test_should_return_server_version_tls_12(self):
        expected_server_version = bytes.fromhex("""03 03""")
        self.assertEqual(TLSVersion.V1_2.value, expected_server_version)

    def test_should_return_server_random(self):
        self.assertIs(len(self.server_hello.server_random), 32)

    def test_should_return_supported_cipher_suites(self):
        supported_cipher_suites = self.server_hello.get_supported_cipher_suites()
        expected_supported_cipher_suites = bytes.fromhex("""13 01""")
        self.assertEqual(supported_cipher_suites, expected_supported_cipher_suites)

    def test_should_build_key_share_extension(self):
        key_share_extension = self.server_hello.get_key_share_extension()
        expected_key_share_extension = bytes.fromhex(
            """00 33 00 24 00 1d 00 20""") + self.server_hello.public_key.public_bytes_raw()
        self.assertEqual(key_share_extension, expected_key_share_extension)

    def test_should_return_supported_versions_extension(self):
        supported_versions_extension = self.server_hello.get_supported_versions_extension()
        expected_supported_versions_extension = bytes.fromhex("""00 2b 00 02 03 04""")
        self.assertEqual(supported_versions_extension, expected_supported_versions_extension)

    def test_should_return_extensions_list(self):
        extensions_list = self.server_hello.get_extensions_list()
        expected_extensions_list = bytes.fromhex("""002e002b0002030400330024001d0020""") + self.public_key.public_bytes_raw()
        self.assertEqual(extensions_list, expected_extensions_list)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-5
    def test_should_return_server_hello_message_header(self):
        data = bytes.fromhex("""03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00 1d 00 20 c9 82 88
         76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 3b 83 3d f1
         dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04""")
        server_hello_message_header = self.server_hello.get_message_header(data)
        expected_server_hello_message_header = bytes.fromhex("""02 00 00 56""")
        self.assertEqual(server_hello_message_header, expected_server_hello_message_header)


    @patch("secrets.token_bytes")
    def test_should_return_server_hello_message(self, mock_get_32_random_bytes):
        mock_random_bytes = b'\x00' * 32
        mock_get_32_random_bytes.return_value = mock_random_bytes

        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        s = ServerHelloMessageBuilder(public_key)

        server_hello_message = s.build_server_hello_message().to_bytes()

        expected_server_hello_message = bytes.fromhex(
            """02000054030300000000000000000000000000000000000000000000000000000000000000001301002e002b0002030400330024001d0020"""
        ) + s.public_key.public_bytes_raw()
        self.assertEqual(server_hello_message, expected_server_hello_message)

    def test_should_build_server_hello_message_from_bytes_correct_handshake_message_type(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_handshake_message_type = bytes.fromhex("02")
        self.assertEqual(message.handshake_message_type, expected_handshake_message_type)

    def test_should_build_server_hello_message_from_bytes_correct_bytes_of_server_hello_data(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_bytes_of_server_hello_data = bytes.fromhex("00 00 56")
        self.assertEqual(message.bytes_of_server_hello_data, expected_bytes_of_server_hello_data)

    def test_should_build_server_hello_message_from_bytes_correct_server_version(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_server_version = bytes.fromhex("03 03")
        self.assertEqual(message.server_version, expected_server_version)

    def test_should_build_server_hello_message_from_bytes_correct_server_random(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_server_random = bytes.fromhex("a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e26928")
        self.assertEqual(message.server_random, expected_server_random)

    def test_should_build_server_hello_message_from_bytes_correct_cipher_suites(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_cipher_suites = bytes.fromhex("13 01")
        self.assertEqual(message.cipher_suite, expected_cipher_suites)

    def test_should_build_server_hello_message_from_bytes_correct_extensions_length(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_extensions_length = bytes.fromhex("00 2e")
        self.assertEqual(message.extensions_length, expected_extensions_length)

    def test_should_build_server_hello_message_from_bytes_correct_extension_supported_versions(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_extension_supported_versions = bytes.fromhex("002b00020304")
        self.assertEqual(message.extension_supported_versions, expected_extension_supported_versions)

    def test_should_build_server_hello_message_from_bytes_correct_extension_key_share(self):
        data = bytes.fromhex("""02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        message = ServerHelloMessageBuilder.build_from_bytes(data)
        expected_extension_key_share = bytes.fromhex("00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
        self.assertEqual(message.extension_key_share, expected_extension_key_share)
