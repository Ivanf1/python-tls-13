from dataclasses import dataclass

from src.utils import KeyExchangeGroups, SignatureAlgorithms


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
        number_of_supported_groups = int(int.from_bytes(self.extension_supported_groups[2:4]) / 2)
        groups = []

        groups_data = self.extension_supported_groups[4:]

        for i in range(number_of_supported_groups):
            groups.append(KeyExchangeGroups(groups_data[i*2:(i*2)+2]))

        return groups

    def get_signature_algorithms(self):
        number_of_signature_algorithms = int(int.from_bytes(self.extension_signature_algorithms[2:4]) / 2)
        algorithms = []

        algorithms_data = self.extension_signature_algorithms[4:]

        for i in range(number_of_signature_algorithms):
            algorithms.append(SignatureAlgorithms(algorithms_data[i*2:(i*2)+2]))

        return algorithms
