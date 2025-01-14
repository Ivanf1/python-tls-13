from enum import Enum


class RecordHeaderType(Enum):
    HANDSHAKE = b'\x16'
    APPLICATION_DATA = b'\x17'

class TLSVersion(Enum):
    V1_0 = b'\x03\x01'
    V1_2 = b'\x03\x03'
