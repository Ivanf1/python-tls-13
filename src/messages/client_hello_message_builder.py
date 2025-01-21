from src.messages.client_hello_message import ClientHelloMessage
from src.tls_crypto import get_32_random_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from src.utils import TLSVersion, SignatureAlgorithms, CipherSuites, KeyExchangeGroups, HandshakeMessageType


class ClientHelloMessageBuilder:
    def __init__(self, server_name, public_key: X25519PublicKey):
        self.client_random = get_32_random_bytes()
        self.server_name = server_name
        self.public_key = public_key

    def get_message_header(self, data):
        # ClientHello message starts with a type and a length
        data_len = len(data)
        data_len_bytes = data_len.to_bytes(3, byteorder='big')
        return HandshakeMessageType.CLIENT_HELLO.value + data_len_bytes

    @staticmethod
    def get_supported_cipher_suites():
        """
        Only support TLS_AES_128_GCM_SHA256
        """
        return len(CipherSuites.TLS_AES_128_GCM_SHA256.value).to_bytes(2) + CipherSuites.TLS_AES_128_GCM_SHA256.value

    def get_extension_server_name_extension(self):
        server_name_extension_flag = b'\x00\x00'
        return self.__build_extension(server_name_extension_flag, self.__build_server_name())

    def get_supported_groups_extension(self):
        supported_groups_extension_flag = b'\x00\x0a'
        return self.__build_extension(supported_groups_extension_flag, KeyExchangeGroups.x25519.value)

    def get_signature_algorithms_extension(self):
        # assigned value for extension "signature algorithms"
        supported_signature_algorithms_flag = b'\x00\x0d'
        return self.__build_extension(supported_signature_algorithms_flag, SignatureAlgorithms.RSA_PSS_PSS_SHA256.value)

    def get_supported_versions_extension(self):
        # assigned value for extension "supported versions"
        supported_versions_flag = b'\x00\x2b'
        return self.__build_extension(supported_versions_flag, TLSVersion.V1_3.value)

    def get_key_share_extension(self):
        # 1 -- assigned value for extension "key share"
        key_share_flag = b'\x00\x33'

        return self.__build_key_share(key_share_flag)

    def get_extensions_list(self):
        """
        Concatenates all the Extensions supported by this ClientHello and prefixes the result
        with 2 bytes representing its length.
        :return: the list of Extensions complete with the prefix of 2 bytes representing its length
        """

        extensions = self.get_extension_server_name_extension() + \
                     self.get_supported_groups_extension() + \
                     self.get_signature_algorithms_extension() + \
                     self.get_supported_versions_extension() + \
                     self.get_key_share_extension()

        extensions_len = len(extensions)
        extensions_len_bytes = extensions_len.to_bytes(2)
        return extensions_len_bytes + extensions

    def build_client_hello_message(self):
        hello_data = (
            TLSVersion.V1_2.value,
            self.client_random,
            self.get_supported_cipher_suites(),
        )
        extensions = (
            self.get_extension_server_name_extension(),
            self.get_supported_groups_extension(),
            self.get_signature_algorithms_extension(),
            self.get_supported_versions_extension(),
            self.get_key_share_extension(),
        )
        extensions_len = len(b''.join(extensions))
        # 2 is the number of bytes of extension_len
        payload_len = len(b''.join(hello_data)) + extensions_len + 2

        return ClientHelloMessage(
            HandshakeMessageType.CLIENT_HELLO.value,
            payload_len.to_bytes(3),
            *hello_data,
            extensions_len.to_bytes(2),
            *extensions
        )

    @staticmethod
    def build_from_bytes(message_bytes):
        handshake_message_type = message_bytes[0:1]
        bytes_of_client_hello_data = message_bytes[1:4]
        client_version = message_bytes[4:6]
        client_random = message_bytes[6:38]
        cipher_suites = message_bytes[38:42]
        extensions_length = message_bytes[42:44]

        bytes_of_server_name_data = int.from_bytes(message_bytes[46:48])
        i = 44 + 2 + 2 + bytes_of_server_name_data

        extension_server_name = message_bytes[44:i]
        extension_supported_groups = message_bytes[i: i + 6]
        i = i + 6
        extension_signature_algorithms = message_bytes[i: i + 6]
        i = i + 6
        extension_supported_versions = message_bytes[i: i + 6]
        i = i + 6
        extension_key_share = message_bytes[i:]

        return ClientHelloMessage(
            handshake_message_type=handshake_message_type,
            bytes_of_client_hello_data=bytes_of_client_hello_data,
            client_version=client_version,
            client_random=client_random,
            cipher_suites=cipher_suites,
            extensions_length=extensions_length,
            extension_server_name=extension_server_name,
            extension_supported_groups=extension_supported_groups,
            extension_signature_algorithms=extension_signature_algorithms,
            extension_supported_versions=extension_supported_versions,
            extension_key_share=extension_key_share
        )

    def __build_extension(self, flag, data):
        data_bytes = len(data).to_bytes(2)
        # Each extension starts with a flag indicating the type of extension which has a length of 2 bytes.
        # Then there are 2 bytes indicating how long is the data that follows.
        # Finally, there is the data.
        return flag + data_bytes + data

    def __build_server_name(self):
        encoded_server_hostname = self.server_name.encode('utf-8')

        # bytes of hostname follows
        encoded_server_hostname_len_bytes = (len(encoded_server_hostname)).to_bytes(2)

        # list entry is type 0x00 "DNS hostname"
        list_entry_type_dns_hostname = b'\x00'

        return list_entry_type_dns_hostname + encoded_server_hostname_len_bytes + encoded_server_hostname

    def __build_key_share(self, flag):
        public_key_len_bytes = len(self.public_key.public_bytes_raw()).to_bytes(2)

        key_share_data_len_bytes = (len(self.public_key.public_bytes_raw()) + 2 + 2).to_bytes(2)

        return flag + \
            key_share_data_len_bytes + \
            KeyExchangeGroups.x25519.value + \
            public_key_len_bytes + \
            self.public_key.public_bytes_raw()
