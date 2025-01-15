import unittest

from src.messages.client_hello_message import ClientHelloMessage
from src.utils import KeyExchangeGroups, SignatureAlgorithms, TLSVersion


class TestClientHelloMessage(unittest.TestCase):
    def setUp(self):
        handshake_message_type = bytes.fromhex("01")
        bytes_of_client_hello_data = bytes.fromhex("00007c")
        client_version = bytes.fromhex("03 03")
        client_random = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
        cipher_suites = bytes.fromhex("00021301")
        extensions_length = bytes.fromhex("0054")
        extension_server_name = bytes.fromhex("0000 0016 00 0013 6578616d706c652e756c666865696d2e6e6574")
        extension_supported_groups = bytes.fromhex("000a 0002 001d")
        extension_signature_algorithms = bytes.fromhex("000d 0002 0809")
        extension_supported_versions = bytes.fromhex("002b 0002 0304")
        extension_key_share = bytes.fromhex("""00330024001d00209a4407c27730168200ff65701c0f3f812b12a01df51b630351230280618a4067""")

        self.client_hello_message = ClientHelloMessage(
            handshake_message_type,
            bytes_of_client_hello_data,
            client_version,
            client_random,
            cipher_suites,
            extensions_length,
            extension_server_name,
            extension_supported_groups,
            extension_signature_algorithms,
            extension_supported_versions,
            extension_key_share,
        )

    def test_should_return_client_hello_message_bytes(self):
        expected_client_hello_message = bytes.fromhex("""01 00007c 0303 0000000000000000000000000000000000000000000000000000000000000000 00021301 0054 0000 0016 00 0013 6578616d706c652e756c666865696d2e6e6574 000a 0002 001d 000d 0002 0809 002b 0002 0304 00330024001d00209a4407c27730168200ff65701c0f3f812b12a01df51b630351230280618a4067""")
        self.assertEqual(self.client_hello_message.to_bytes(), expected_client_hello_message)

    def test_should_return_server_name(self):
        server_name = self.client_hello_message.get_server_name()
        expected_server_name = "example.ulfheim.net"
        self.assertEqual(server_name, expected_server_name)

    def test_should_return_supported_groups(self):
        supported_groups = self.client_hello_message.get_supported_groups()
        expected_supported_groups = [KeyExchangeGroups.x25519]
        self.assertSequenceEqual(supported_groups, expected_supported_groups)

    def test_should_return_signature_algorithms(self):
        signature_algorithms = self.client_hello_message.get_signature_algorithms()
        expected_signature_algorithms = [SignatureAlgorithms.RSA_PSS_PSS_SHA256]
        self.assertSequenceEqual(signature_algorithms, expected_signature_algorithms)

    def test_should_return_supported_versions(self):
        supported_versions = self.client_hello_message.get_supported_versions()
        expected_supported_versions = [TLSVersion.V1_3]
        self.assertEqual(supported_versions, expected_supported_versions)

    def test_should_return_public_key(self):
        public_key = self.client_hello_message.get_public_key()
        expected_public_key = bytes.fromhex("9a4407c27730168200ff65701c0f3f812b12a01df51b630351230280618a4067")
        self.assertEqual(public_key, expected_public_key)
