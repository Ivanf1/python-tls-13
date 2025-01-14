from src.tls_crypto import get_32_random_bytes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

class ServerHello:
    def __init__(self, public_key: X25519PublicKey):
        self.SERVER_VERSION = b'\x03\x03'
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
        TLS_AES_128_GCM_SHA256 = b'\x13\x01'
        return len(TLS_AES_128_GCM_SHA256).to_bytes(2) + TLS_AES_128_GCM_SHA256

    def get_key_share_extension(self):
        # 1 -- assigned value for extension "key share"
        key_share_flag = b'\x00\x33'

        return self.__build_key_share(key_share_flag)

    def get_supported_versions_extension(self):
        # assigned value for extension "supported versions"
        supported_versions_flag = b'\x00\x2b'
        tls_13 = b'\x03\x04'
        return self.__build_extension(supported_versions_flag, tls_13)

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

    def build_server_hello(self):
        m = self.SERVER_VERSION + \
            self.server_random + \
            self.get_supported_cipher_suites() + \
            self.get_extensions_list()

        return self.get_message_header(m) + m

    def __build_extension(self, flag, data):
        data_bytes = len(data).to_bytes(2)
        # Each extension starts with a flag indicating the type of extension which has a length of 2 bytes.
        # Then there are 2 bytes indicating how long is the data that follows.
        # Finally, there is the data.
        return flag + data_bytes + data

    def __build_key_share(self, flag):
        curve_25519_flag = b'\x00\x1d'

        public_key_len_bytes = len(self.public_key.public_bytes_raw()).to_bytes(2)

        key_share_data_len_bytes = (len(self.public_key.public_bytes_raw()) + 2 + 2).to_bytes(2)

        return flag + key_share_data_len_bytes + curve_25519_flag + public_key_len_bytes + self.public_key.public_bytes_raw()