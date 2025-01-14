from src.tls_crypto import encrypt
from src.utils import RecordHeaderType, record_header_type, TLS_VERSION_10


class RecordManager:

    @staticmethod
    def get_message_header(record_type: RecordHeaderType, message_type: RecordHeaderType, message):
        message_len = len(message)

        # To the length of the message we need to add 16, that is the number of bytes of
        # the Auth Tag that will be appended to the message
        if message_type == RecordHeaderType.APPLICATION_DATA:
            message_len += 16

        return record_header_type[record_type] + TLS_VERSION_10 + message_len.to_bytes(2)

