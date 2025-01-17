import unittest

from src.messages.server_hello_message import ServerHelloMessage
from src.utils import TLSVersion, CipherSuites


class TestServerHelloMessage(unittest.TestCase):
    def setUp(self):
        handshake_message_type = bytes.fromhex("02")
        bytes_of_server_hello_data = bytes.fromhex("000054")
        server_version = bytes.fromhex("03 03")
        server_random = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        cipher_suites = bytes.fromhex("1301")
        extensions_length = bytes.fromhex("002e")
        extension_supported_versions = bytes.fromhex("002b 0002 0304")
        extension_key_share = bytes.fromhex("""00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f""")

        self.server_hello_message = ServerHelloMessage(
            handshake_message_type,
            bytes_of_server_hello_data,
            server_version,
            server_random,
            cipher_suites,
            extensions_length,
            extension_supported_versions,
            extension_key_share,
        )

    def test_should_return_server_hello_message_bytes(self):
        expected_server_hello_message = bytes.fromhex("""02 000054 0303 0000000000000000000000000000000000000000000000000000000000000000 1301 002e 002b 0002 0304 00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f""")
        self.assertEqual(self.server_hello_message.to_bytes(), expected_server_hello_message)

    def test_should_return_supported_versions(self):
        supported_versions = self.server_hello_message.get_supported_versions()
        expected_supported_versions = [TLSVersion.V1_3]
        self.assertEqual(supported_versions, expected_supported_versions)

    def test_should_return_public_key(self):
        public_key = self.server_hello_message.get_public_key()
        expected_public_key = bytes.fromhex("c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f")
        self.assertEqual(public_key, expected_public_key)

    def test_should_return_cipher_suite(self):
        self.assertEqual(CipherSuites.TLS_AES_128_GCM_SHA256, self.server_hello_message.get_cipher_suite())
