from src.tls_crypto import get_X25519_private_key, get_X25519_public_key
from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent


class TlsServerSession:
    def __init__(self, on_data_to_send, certificate_path, certificate_private_key_path, on_connected):
        self.private_key = get_X25519_private_key()
        self.public_key = get_X25519_public_key(self.private_key)
        self.on_data_to_send = on_data_to_send
        self.certificate_path = certificate_path
        self.certificate_private_key_path = certificate_private_key_path
        self.on_connected = on_connected

        self.tls_fsm = TlsServerFsm(
            on_session_begin_transaction_cb=self._on_session_begin_fsm_transaction,
            on_client_hello_received_transaction_cb=self._on_client_hello_received_fsm_transaction,
            on_finished_received_cb=self._on_finished_received_fsm_transaction
        )

    def start(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)

    def on_record_received(self, record):
        pass

    def _on_handshake_message_received(self, record):
        pass

    def _on_session_begin_fsm_transaction(self, ctx):
        return True

    def _on_client_hello_received_fsm_transaction(self, ctx):
        return True

    def _on_finished_received_fsm_transaction(self, ctx):
        return True