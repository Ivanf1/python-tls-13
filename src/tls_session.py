from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key, get_early_secret, get_derived_secret
from src.tls_fsm import TlsFsm, TlsFsmEvent
from src.utils import TLSVersion, RecordHeaderType


class TlsSession:
    def __init__(self, server_name):
        self.server_name = server_name
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)

        self.derived_secret = None

        self.client_hello: ClientHelloMessage or None = None
        self.server_hello: ServerHelloMessage or None = None

        self.tls_fsm = TlsFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_server_hello_received_cb=self._on_server_hello_received_fsm_transaction,
            on_certificate_received_cb=self._on_certificate_received_fsm_transaction,
            on_certificate_verify_received_cb=self._on_certificate_verify_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def start(self) -> bytes:
        self.client_hello = ClientHelloMessageBuilder(
            self.server_name,
            self.public_key
        ).build_client_hello_message()

        self.tls_fsm.transition(TlsFsmEvent.SESSION_BEGIN)

        return RecordManager.build_unencrypted_record(
            tls_version=TLSVersion.V1_0,
            record_type=RecordHeaderType.HANDSHAKE,
            message=self.client_hello.to_bytes()
        )

    def on_record_received(self, record):
        message_type = RecordManager.get_handshake_message_type(record)
        self.tls_fsm.transition(message_type, record)

    def _on_session_begin_fsm_transaction(self, _):
        early_secret = get_early_secret()
        self.derived_secret = get_derived_secret(early_secret)

    def _on_server_hello_received_fsm_transaction(self, ctx):
        pass

    def _on_certificate_received_fsm_transaction(self, ctx):
        pass

    def _on_certificate_verify_received_fsm_transaction(self, ctx):
        pass

    def _on_finished_received_fsm_transaction(self, ctx):
        pass