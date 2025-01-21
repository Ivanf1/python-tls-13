import unittest

from src.messages.encrypted_extensions_message import EncryptedExtensionsMessage


class TestEncryptedExtensionsMessage(unittest.TestCase):
    def setUp(self):
        handshake_message_type = bytes.fromhex("08")
        bytes_of_handshake_data = bytes.fromhex("00 00 02")
        bytes_of_extensions = bytes.fromhex("00 00")
        extensions = bytes.fromhex("")

        self.encrypted_extensions_message = EncryptedExtensionsMessage(
            handshake_message_type=handshake_message_type,
            bytes_of_handshake_data=bytes_of_handshake_data,
            bytes_of_extensions=bytes_of_extensions,
            extensions=extensions
        )

    def test_should_return_encrypted_extensions_message_bytes(self):
        expected_encrypted_extensions_message = bytes.fromhex("""08 00 00 02 00 00""")
        self.assertEqual(self.encrypted_extensions_message.to_bytes(), expected_encrypted_extensions_message)
