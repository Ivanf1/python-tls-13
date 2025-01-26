from src.utils import SignatureAlgorithms


class CertificateRequestMessageBuilder:
    def get_signature_algorithms_extension(self):
        # assigned value for extension "signature algorithms"
        supported_signature_algorithms_flag = b'\x00\x0d'
        return self.__build_extension(supported_signature_algorithms_flag, SignatureAlgorithms.RSA_PSS_PSS_SHA256.value)

    def __build_extension(self, flag, data):
        data_bytes = len(data).to_bytes(2)
        # Each extension starts with a flag indicating the type of extension which has a length of 2 bytes.
        # Then there are 2 bytes indicating how long is the data that follows.
        # Finally, there is the data.
        return flag + data_bytes + data
