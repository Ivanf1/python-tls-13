from enum import Enum


class RecordHeaderType(Enum):
    HANDSHAKE = b'\x16'
    APPLICATION_DATA = b'\x17'

class HandshakeMessageType(Enum):
    CLIENT_HELLO = b'\x01'
    SERVER_HELLO = b'\x02'
    ENCRYPTED_EXTENSIONS = b'\x08'
    CERTIFICATE = b'\x0b'
    CERTIFICATE_REQUEST = b'\x0d'
    CERTIFICATE_VERIFY = b'\x0f'
    FINISHED = b'\x14'

class TLSVersion(Enum):
    V1_0 = b'\x03\x01'
    V1_2 = b'\x03\x03'
    V1_3 = b'\x03\x04'

class KeyExchangeGroups(Enum):
    x25519 = b'\x00\x1d'

class SignatureAlgorithms(Enum):
    RSA_PSS_PSS_SHA256 = b'\x08\x09'
    RSA_PSS_RSAE_SHA256 = b'\x08\x04'

class CipherSuites(Enum):
    TLS_AES_128_GCM_SHA256 = b'\x13\x01'
