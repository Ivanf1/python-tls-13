from dataclasses import dataclass

from src.utils import TLSVersion, CipherSuites


@dataclass
class ServerHelloMessage:
    handshake_message_type: bytes
    bytes_of_server_hello_data: bytes
    server_version: bytes
    server_random: bytes
    cipher_suite: bytes
    extensions_length: bytes
    extension_supported_versions: bytes
    extension_key_share: bytes

    def to_bytes(self):
        return self.handshake_message_type + \
            self.bytes_of_server_hello_data + \
            self.server_version + \
            self.server_random + \
            self.cipher_suite + \
            self.extensions_length + \
            self.extension_supported_versions + \
            self.extension_key_share

    def get_supported_versions(self):
        return self.__get_extension_data(self.extension_supported_versions, TLSVersion)

    def get_public_key(self):
        return self.extension_key_share[8:]

    def get_cipher_suite(self):
        return CipherSuites(self.cipher_suite)

    @staticmethod
    def __get_extension_data(extension, data_type):
        n_elements = int(int.from_bytes(extension[2:4]) / 2)
        data = []

        p_data = extension[4:]

        for i in range(n_elements):
            data.append(data_type(p_data[i*2:(i*2)+2]))

        return data