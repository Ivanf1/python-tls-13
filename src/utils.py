from enum import Enum


class RecordHeaderType(Enum):
    HANDSHAKE = 0
    APPLICATION_DATA = 1

record_header_type = {
    RecordHeaderType.HANDSHAKE : b'\x16',
    RecordHeaderType.APPLICATION_DATA: b'\x17',
}

TLS_VERSION_10 = b'\x03\x01'