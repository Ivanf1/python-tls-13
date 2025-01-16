from src.tls_crypto import encrypt, decrypt
from src.utils import RecordHeaderType, TLSVersion


class RecordManager:

    @staticmethod
    def build_record_header(record_type: RecordHeaderType, message, tls_version: TLSVersion):
        message_len = len(message)

        # To the length of the message we need to add 16, that is the number of bytes of
        # the Auth Tag that will be appended to the message
        if record_type == RecordHeaderType.APPLICATION_DATA:
            message_len += 16

        return record_type.value + tls_version.value + message_len.to_bytes(2)

    @staticmethod
    def build_unencrypted_record(tls_version: TLSVersion, record_type: RecordHeaderType, message):
        """
        Returns the record composed by the message itself and the header, with the payload in plaintext.

        :param tls_version: the TLS version to be specified in the record header
        :param record_type: the record type to be specified in the record header
        :param message: the message to encrypt
        :return: the encrypted record
        """
        header = RecordManager.build_record_header(record_type, message, tls_version)
        return header + message

    @staticmethod
    def build_encrypted_record(tls_version: TLSVersion, record_type: RecordHeaderType, message_type: RecordHeaderType, message, key, nonce):
        """
        Returns the record composed by the message and the header, with the payload encrypted.

        :param tls_version: the TLS version to be specified in the record header
        :param record_type: the record type to be specified in the record header
        :param message_type: the message type, which can be different from the record type if
        the message is being disguised as TLS 1.2 application message
        :param message: the message to encrypt
        :param key: the key to use for the encryption
        :param nonce: iv
        :return: the encrypted record
        """
        if message_type == RecordHeaderType.HANDSHAKE:
            message += message_type.value

        header = RecordManager.build_record_header(record_type, message, tls_version)
        return header + encrypt(key, nonce, message, header)

    @staticmethod
    def get_record_header(record):
        return record[0:5]

    @staticmethod
    def get_record_type(record):
        """
        Returns the type of the record. In TLS 1.3 the type of the record may be different from the type indicated
        in the record header if it is a handshake record being disguised as an application record.

        :param record: Decrypted record.
        :return: The type of the record. If the record is a handshake record being disguised as an application
        record, it will return type handshake.
        """
        if RecordHeaderType(record[0:1]) == RecordHeaderType.HANDSHAKE:
            return RecordHeaderType.HANDSHAKE
        else:
            return RecordHeaderType(record[:-1])

    @staticmethod
    def get_decrypted_record_payload(record, key, nonce):
        return decrypt(key, nonce, record[5:], record[:5])
