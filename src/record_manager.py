from src.tls_crypto import encrypt
from src.utils import RecordHeaderType, TLSVersion


class RecordManager:

    @staticmethod
    def get_message_header(record_type: RecordHeaderType, message, tls_version: TLSVersion):
        message_len = len(message)

        # To the length of the message we need to add 16, that is the number of bytes of
        # the Auth Tag that will be appended to the message
        if record_type == RecordHeaderType.APPLICATION_DATA:
            message_len += 16

        return record_type.value + tls_version.value + message_len.to_bytes(2)
