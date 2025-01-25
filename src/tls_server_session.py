from typing import Optional

from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key, get_early_secret, get_derived_secret
from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent
from src.utils import HandshakeMessageType


class TlsServerSession:
    def __init__(self, on_data_to_send, certificate_path, certificate_private_key_path, on_connected):
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)
        self.on_data_to_send = on_data_to_send
        self.certificate_path = certificate_path
        self.certificate_private_key_path = certificate_private_key_path
        self.on_connected = on_connected

        self.derived_secret: bytes = b''

        self.client_hello: Optional[ClientHelloMessage] = None
        self.server_hello: Optional[ServerHelloMessage] = None

        self.tls_fsm = TlsServerFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_client_hello_received_transaction_cb=self._on_client_hello_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def start(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)

    def on_record_received(self, record):
        self._on_handshake_message_received(record)

    def _on_handshake_message_received(self, record):
        message_type = RecordManager.get_handshake_message_type(record)

        match message_type:
            case HandshakeMessageType.CLIENT_HELLO:
                event = TlsServerFsmEvent.CLIENT_HELLO_RECEIVED
            case _:
                event = None

        self.tls_fsm.transition(event, record)

    def _on_session_begin_fsm_transaction(self, _):
        early_secret = get_early_secret()
        self.derived_secret = get_derived_secret(early_secret)
        return True

    def _on_client_hello_received_fsm_transaction(self, ctx):
        self.client_hello = ClientHelloMessageBuilder.build_from_bytes(ctx[5:])
        self.server_hello = ServerHelloMessageBuilder(self.public_key).build_server_hello_message()

        self.on_data_to_send(self.server_hello.to_bytes())
        return True

    def _on_finished_received_fsm_transaction(self, ctx):
        return True