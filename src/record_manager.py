from enum import Enum


class RecordHeaderType(Enum):
    HANDSHAKE = 0

record_header_type = {
    RecordHeaderType.HANDSHAKE : b'\x16',
}

TLS_VERSION_10 = b'\x03\x01'

class RecordManager:

    @staticmethod
    def get_message_header(record_type: RecordHeaderType, message):
        message_len =  len(message).to_bytes(2)
        return record_header_type[record_type] + TLS_VERSION_10 + message_len
