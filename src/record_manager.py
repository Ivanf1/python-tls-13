from src.utils import RecordHeaderType, record_header_type, TLS_VERSION_10


class RecordManager:

    @staticmethod
    def get_message_header(record_type: RecordHeaderType, message):
        message_len =  len(message).to_bytes(2)
        return record_header_type[record_type] + TLS_VERSION_10 + message_len
