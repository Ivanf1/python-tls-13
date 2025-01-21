from enum import Enum

from src.fsm import FSM


class TlsFsmState(Enum):
    START = 0,
    WAIT_SERVER_HELLO = 1,
    WAIT_ENCRYPTED_EXTENSIONS = 2,
    WAIT_CERTIFICATE = 3,
    WAIT_CERTIFICATE_VERIFY = 4,
    WAIT_FINISHED = 5,
    CONNECTED = 6

class TlsFsmEvent(Enum):
    SESSION_BEGIN = 0,
    SERVER_HELLO_RECEIVED = 1,
    ENCRYPTED_EXTENSIONS_RECEIVED = 2,
    CERTIFICATE_RECEIVED = 3,
    CERTIFICATE_VERIFY_RECEIVED = 4,
    FINISHED_RECEIVED = 5


class TlsFsm(FSM):
    def __init__(
            self,
            on_session_begin_transaction_cb = None,
            on_server_hello_received_cb = None,
            on_encrypted_extensions_received_cb = None,
            on_certificate_received_cb = None,
            on_certificate_verify_received_cb = None,
            on_finished_received_cb = None
    ):
        tls_states = [state for state in TlsFsmState]
        self.events = [event for event in TlsFsmEvent]

        tls_table = {
            (TlsFsmState.START, TlsFsmEvent.SESSION_BEGIN): (TlsFsmState.WAIT_SERVER_HELLO, on_session_begin_transaction_cb),
            (TlsFsmState.WAIT_SERVER_HELLO, TlsFsmEvent.SERVER_HELLO_RECEIVED): (TlsFsmState.WAIT_ENCRYPTED_EXTENSIONS, on_server_hello_received_cb),
            (TlsFsmState.WAIT_ENCRYPTED_EXTENSIONS, TlsFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED): (TlsFsmState.WAIT_CERTIFICATE, on_encrypted_extensions_received_cb),
            (TlsFsmState.WAIT_CERTIFICATE, TlsFsmEvent.CERTIFICATE_RECEIVED): (TlsFsmState.WAIT_CERTIFICATE_VERIFY, on_certificate_received_cb),
            (TlsFsmState.WAIT_CERTIFICATE_VERIFY, TlsFsmEvent.CERTIFICATE_VERIFY_RECEIVED): (TlsFsmState.WAIT_FINISHED, on_certificate_verify_received_cb),
            (TlsFsmState.WAIT_FINISHED, TlsFsmEvent.FINISHED_RECEIVED): (TlsFsmState.CONNECTED, on_finished_received_cb),
        }

        super().__init__(
            states=tls_states,
            initial_state=tls_states[0],
            table=tls_table,
        )

    def get_states(self):
        return self.states

    def get_events(self):
        return self.events
