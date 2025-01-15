import unittest

from src.messages.client_hello_message import ClientHelloMessage


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
        extension_signature_algorithms = bytes.fromhex("000d 0002 0403")
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
        expected_client_hello_message = bytes.fromhex("""01 00007c 0303 0000000000000000000000000000000000000000000000000000000000000000 00021301 0054 0000 0016 00 0013 6578616d706c652e756c666865696d2e6e6574 000a 0002 001d 000d 0002 0403 002b 0002 0304 00330024001d00209a4407c27730168200ff65701c0f3f812b12a01df51b630351230280618a4067""")
        self.assertEqual(self.client_hello_message.to_bytes(), expected_client_hello_message)

    def test_should_return_server_name(self):
        server_name = self.client_hello_message.get_server_name()
        expected_server_name = "example.ulfheim.net"
        self.assertEqual(server_name, expected_server_name)
