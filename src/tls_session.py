from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key
from src.utils import TLSVersion, RecordHeaderType


class TlsSession:
    def __init__(self, server_name):
        self.server_name = server_name
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)

        self.client_hello: ClientHelloMessage or None = None
        self.record_manager = RecordManager()

    def start(self) -> bytes:
        self.client_hello = ClientHelloMessageBuilder(
            self.server_name,
            self.public_key
        ).build_client_hello_message()

        return self.record_manager.get_unencrypted_record(
            tls_version=TLSVersion.V1_0,
            record_type=RecordHeaderType.HANDSHAKE,
            message=self.client_hello.to_bytes()
        )
