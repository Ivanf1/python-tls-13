from src.tls_crypto import get_32_random_bytes

class ClientHello:
    def __init__(self, server_name):
        self.CLIENT_VERSION = b'\x03\x03'
        self.client_random = get_32_random_bytes()
        self.server_name = server_name

    @staticmethod
    def get_supported_cipher_suites():
        """
        Only support TLS_AES_128_GCM_SHA256
        """
        TLS_AES_128_GCM_SHA256 = b'\x13\x01'
        return len(TLS_AES_128_GCM_SHA256).to_bytes(2) + TLS_AES_128_GCM_SHA256

    def get_extension_server_name_extension(self):
        server_name_extension_flag = b'\x00\x00'
        return self.__build_extension(server_name_extension_flag, self.__build_server_name())

    def get_supported_groups_extension(self):
        supported_groups_extension_flag = b'\x00\x0a'
        group_x25519 = b'\x00\x1d'
        return self.__build_extension(supported_groups_extension_flag, group_x25519)

    def get_signature_algorithms_extension(self):
        # assigned value for extension "signature algorithms"
        supported_signature_algorithms_flag = b'\x00\x0d'
        algorithm_ECDSA_SECP256r1_SHA256 =  b'\x04\x03'
        return self.__build_extension(supported_signature_algorithms_flag, algorithm_ECDSA_SECP256r1_SHA256)

    def get_supported_versions_extension(self):
        # assigned value for extension "supported versions"
        supported_versions_flag = b'\x00\x2b'
        tls_13 = b'\x03\x04'
        return self.__build_extension(supported_versions_flag, tls_13)

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
