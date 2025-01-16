from dataclasses import dataclass

from src.utils import KeyExchangeGroups, SignatureAlgorithms, TLSVersion


@dataclass
class ClientHelloMessage:
    handshake_message_type: bytes
    bytes_of_client_hello_data: bytes
    client_version: bytes
    client_random: bytes
    cipher_suites: bytes
    extensions_length: bytes
    extension_server_name: bytes
    extension_supported_groups: bytes
    extension_signature_algorithms: bytes
    extension_supported_versions: bytes
    extension_key_share: bytes

    def to_bytes(self):
        return self.handshake_message_type + \
            self.bytes_of_client_hello_data + \
            self.client_version + \
            self.client_random + \
            self.cipher_suites + \
            self.extensions_length + \
            self.extension_server_name + \
            self.extension_supported_groups + \
            self.extension_signature_algorithms + \
            self.extension_supported_versions + \
            self.extension_key_share

    def get_server_name(self):
        return self.extension_server_name[7:].decode("utf-8")

    def get_supported_groups(self):
        return self.__get_extension_data(self.extension_supported_groups, KeyExchangeGroups)

    def get_signature_algorithms(self):
        return self.__get_extension_data(self.extension_signature_algorithms, SignatureAlgorithms)

    def get_supported_versions(self):
        return self.__get_extension_data(self.extension_supported_versions, TLSVersion)

    def get_public_key(self):
        return self.extension_key_share[8:]

    @staticmethod
    def __get_extension_data(extension, data_type):
        n_elements = int(int.from_bytes(extension[2:4]) / 2)
        data = []

        p_data = extension[4:]

        for i in range(n_elements):
            data.append(data_type(p_data[i*2:(i*2)+2]))

        return data