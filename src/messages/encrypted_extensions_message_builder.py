from src.messages.encrypted_extensions_message import EncryptedExtensionsMessage


class EncryptedExtensionsMessageBuilder:
    def __init__(self):
        self.HANDSHAKE_MESSAGE_TYPE_ENCRYPTED_EXTENSIONS = b'\x08'

    @staticmethod
    def build_from_bytes(message_bytes: bytes):
        handshake_message_type = message_bytes[0:1]
        bytes_of_handshake_data = message_bytes[1:4]
        bytes_of_extensions = message_bytes[4:6]
        extensions = message_bytes[6:]

        return EncryptedExtensionsMessage(
            handshake_message_type=handshake_message_type,
            bytes_of_handshake_data=bytes_of_handshake_data,
            bytes_of_extensions=bytes_of_extensions,
            extensions=extensions
        )
