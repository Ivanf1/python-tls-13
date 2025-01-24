from src.messages.client_hello_message import ClientHelloMessage
from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.messages.server_hello_message import ServerHelloMessage
from src.messages.server_hello_message_builder import ServerHelloMessageBuilder
from src.record_manager import RecordManager
from src.tls_crypto import get_X25519_private_key, get_X25519_public_key
from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent
from src.utils import HandshakeMessageType


class TlsServerSession:
    def __init__(self, on_data_to_send):
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)
        self.on_data_to_send = on_data_to_send

        self.client_hello: ClientHelloMessage or None = None
        self.server_hello: ServerHelloMessage or None = None

        self.tls_fsm = TlsServerFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_client_hello_received_transaction_cb=self._on_client_hello_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def on_record_received(self, record):
        message_type = RecordManager.get_handshake_message_type(record)

        match message_type:
            case HandshakeMessageType.CLIENT_HELLO:
                event = TlsServerFsmEvent.CLIENT_HELLO_RECEIVED
            case _:
                event = None

        self.tls_fsm.transition(event, record)

    def start(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)

    def _on_session_begin_fsm_transaction(self, ctx):
        return True

    def _on_client_hello_received_fsm_transaction(self, ctx):
        self.client_hello = ClientHelloMessageBuilder.build_from_bytes(ctx[5:])
        self.server_hello = self._build_server_hello()

        self.on_data_to_send(self.server_hello)
        
        return True

    def _on_finished_received_fsm_transaction(self, ctx):
        pass

    def _build_server_hello(self):
        return ServerHelloMessageBuilder(self.public_key).build_server_hello_message()