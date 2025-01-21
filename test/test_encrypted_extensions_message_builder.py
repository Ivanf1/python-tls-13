import unittest

from src.messages.encrypted_extensions_message_builder import EncryptedExtensionsMessageBuilder


class TestEncryptedExtensionsMessageBuilder(unittest.TestCase):
    def setUp(self):
        self.data = bytes.fromhex("""08 00 00 02 00 00""")

    def test_should_build_encrypted_extensions_message_from_bytes_correct_handshake_message_type(self):
        message = EncryptedExtensionsMessageBuilder.build_from_bytes(self.data)
        expected_handshake_message_type = bytes.fromhex("08")
        self.assertEqual(message.handshake_message_type, expected_handshake_message_type)

    def test_should_build_encrypted_extensions_message_from_bytes_correct_bytes_of_handshake_data(self):
        message = EncryptedExtensionsMessageBuilder.build_from_bytes(self.data)
        expected_bytes_of_handshake_data = bytes.fromhex("00 00 02")
        self.assertEqual(message.bytes_of_handshake_data, expected_bytes_of_handshake_data)

    def test_should_build_encrypted_extensions_message_from_bytes_correct_bytes_of_extensions(self):
        message = EncryptedExtensionsMessageBuilder.build_from_bytes(self.data)
        expected_bytes_of_extensions = bytes.fromhex("00 00")
        self.assertEqual(message.bytes_of_extensions, expected_bytes_of_extensions)

    def test_should_build_encrypted_extensions_message_from_bytes_correct_extensions(self):
        message = EncryptedExtensionsMessageBuilder.build_from_bytes(self.data)
        expected_extensions = bytes.fromhex("")
        self.assertEqual(message.extensions, expected_extensions)
