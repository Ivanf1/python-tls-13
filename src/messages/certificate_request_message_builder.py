from src.messages.certificate_request_message import CertificateRequestMessage
from src.utils import SignatureAlgorithms, HandshakeMessageType


class CertificateRequestMessageBuilder:
    def get_certificate_request_message(self):
        signature_algorithms_extension = self.get_signature_algorithms_extension()
        bytes_of_extensions = len(signature_algorithms_extension).to_bytes(3)
        bytes_of_handshake_data = (len(signature_algorithms_extension) + 3).to_bytes(3)

        return CertificateRequestMessage(
            handshake_message_type=HandshakeMessageType.CERTIFICATE_REQUEST.value,
            bytes_of_handshake_data=bytes_of_handshake_data,
            bytes_of_extensions=bytes_of_extensions,
            signature_algorithms_extension=signature_algorithms_extension
        )

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
