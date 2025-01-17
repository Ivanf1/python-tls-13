from src.messages.server_hello_message import ServerHelloMessage
from src.tls_crypto import get_32_random_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from src.utils import TLSVersion, CipherSuites, KeyExchangeGroups


class ServerHelloMessageBuilder:
    def __init__(self, public_key: X25519PublicKey):
        self.HANDSHAKE_MESSAGE_TYPE_SERVER_HELLO = b'\x02'
        self.server_random = get_32_random_bytes()
        self.public_key = public_key

    def get_message_header(self, data):
        # ServerHello message starts with a type and a length
        data_len = len(data)
        data_len_bytes = data_len.to_bytes(3, byteorder='big')
        return self.HANDSHAKE_MESSAGE_TYPE_SERVER_HELLO + data_len_bytes

    @staticmethod
    def get_supported_cipher_suites():
        """
        Only support TLS_AES_128_GCM_SHA256
        """
        return CipherSuites.TLS_AES_128_GCM_SHA256.value

    def get_key_share_extension(self):
        # 1 -- assigned value for extension "key share"
        key_share_flag = b'\x00\x33'

        return self.__build_key_share(key_share_flag)

    def get_supported_versions_extension(self):
        # assigned value for extension "supported versions"
        supported_versions_flag = b'\x00\x2b'
        return self.__build_extension(supported_versions_flag, TLSVersion.V1_3.value)

    def get_extensions_list(self):
        """
        Concatenates all the Extensions supported by this ServerHello and prefixes the result
        with 2 bytes representing its length.
        :return: the list of Extensions complete with the prefix of 2 bytes representing its length
        """

        extensions = self.get_supported_versions_extension() + \
                     self.get_key_share_extension()

        extensions_len = len(extensions)
        extensions_len_bytes = extensions_len.to_bytes(2)
        return extensions_len_bytes + extensions

    def build_server_hello_message(self):
        hello_data = (
            TLSVersion.V1_2.value,
            self.server_random,
            self.get_supported_cipher_suites(),
        )
        extensions = (
            self.get_supported_versions_extension(),
            self.get_key_share_extension(),
        )
        extensions_len = len(b''.join(extensions))
        # 2 is the number of bytes of extension_len
        payload_len = len(b''.join(hello_data)) + extensions_len + 2

        return ServerHelloMessage(
            self.HANDSHAKE_MESSAGE_TYPE_SERVER_HELLO,
            payload_len.to_bytes(3),
            *hello_data,
            extensions_len.to_bytes(2),
            *extensions
        )

    @staticmethod
    def build_from_bytes(message_bytes: bytes):
        """
        Builds a ServerHelloMessage object from a byte representation of a server hello message.

        :param message_bytes: The bytes of the message.
        :return: ServerHelloMessage
        """
        handshake_message_type = message_bytes[0:1]
        bytes_of_server_hello_data = message_bytes[1:4]
        server_version = message_bytes[4:6]
        server_random = message_bytes[6:38]
        cipher_suites = message_bytes[38:40]
        extensions_length = message_bytes[40:42]
        extension_supported_versions = message_bytes[42:48]
        extension_key_share = message_bytes[48:]

        return ServerHelloMessage(
            handshake_message_type=handshake_message_type,
            bytes_of_server_hello_data=bytes_of_server_hello_data,
            server_version=server_version,
            server_random=server_random,
            cipher_suites=cipher_suites,
            extensions_length=extensions_length,
            extension_supported_versions=extension_supported_versions,
            extension_key_share=extension_key_share
        )

    def __build_extension(self, flag, data):
        data_bytes = len(data).to_bytes(2)
        # Each extension starts with a flag indicating the type of extension which has a length of 2 bytes.
        # Then there are 2 bytes indicating how long is the data that follows.
        # Finally, there is the data.
        return flag + data_bytes + data

    def __build_key_share(self, flag):
        public_key_len_bytes = len(self.public_key.public_bytes_raw()).to_bytes(2)

        key_share_data_len_bytes = (len(self.public_key.public_bytes_raw()) + 2 + 2).to_bytes(2)

        return flag + \
            key_share_data_len_bytes + \
            KeyExchangeGroups.x25519.value + \
            public_key_len_bytes + \
            self.public_key.public_bytes_raw()
