from src.messages.encrypted_extensions_message import EncryptedExtensionsMessage
from src.utils import HandshakeMessageType


class EncryptedExtensionsMessageBuilder:

    @staticmethod
    def get_encrypted_extensions_message():
        extensions = bytes.fromhex("")
        extensions_len = len(extensions).to_bytes(2)

        bytes_of_handshake_data = (len(extensions) + 2).to_bytes(3)

        return EncryptedExtensionsMessage(
            handshake_message_type=HandshakeMessageType.ENCRYPTED_EXTENSIONS.value,
            bytes_of_handshake_data=bytes_of_handshake_data,
            bytes_of_extensions=extensions_len,
            extensions=extensions
        )

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
