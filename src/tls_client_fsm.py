from enum import Enum

from src.fsm import FSM


class TlsClientFsmState(Enum):
    START = 0,
    WAIT_SERVER_HELLO = 1,
    WAIT_ENCRYPTED_EXTENSIONS = 3,
    WAIT_CERTIFICATE_OR_CERTIFICATE_REQUEST = 4,
    WAIT_CERTIFICATE = 5,
    WAIT_CERTIFICATE_VERIFY = 6,
    WAIT_FINISHED = 7,
    CONNECTED = 8

class TlsClientFsmEvent(Enum):
    SESSION_BEGIN = 0,
    SERVER_HELLO_RECEIVED = 1,
    ENCRYPTED_EXTENSIONS_RECEIVED = 2,
    CERTIFICATE_REQUEST_RECEIVED = 3,
    CERTIFICATE_RECEIVED = 4,
    CERTIFICATE_VERIFY_RECEIVED = 5,
    FINISHED_RECEIVED = 6


class TlsClientFsm(FSM):
    def __init__(
            self,
            on_session_begin_transaction_cb = None,
            on_server_hello_received_cb = None,
            on_encrypted_extensions_received_cb = None,
            on_certificate_request_received_cb = None,
            on_certificate_received_cb = None,
            on_certificate_verify_received_cb = None,
            on_finished_received_cb = None
    ):
        tls_states = [state for state in TlsClientFsmState]
        self.events = [event for event in TlsClientFsmEvent]

        tls_table = {
            (TlsClientFsmState.START, TlsClientFsmEvent.SESSION_BEGIN): (TlsClientFsmState.WAIT_SERVER_HELLO, on_session_begin_transaction_cb),
            (TlsClientFsmState.WAIT_SERVER_HELLO, TlsClientFsmEvent.SERVER_HELLO_RECEIVED): (TlsClientFsmState.WAIT_ENCRYPTED_EXTENSIONS, on_server_hello_received_cb),
            (TlsClientFsmState.WAIT_ENCRYPTED_EXTENSIONS, TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED): (TlsClientFsmState.WAIT_CERTIFICATE_OR_CERTIFICATE_REQUEST, on_encrypted_extensions_received_cb),
            (TlsClientFsmState.WAIT_CERTIFICATE_OR_CERTIFICATE_REQUEST, TlsClientFsmEvent.CERTIFICATE_RECEIVED): (TlsClientFsmState.WAIT_CERTIFICATE_VERIFY, on_certificate_received_cb),
            (TlsClientFsmState.WAIT_CERTIFICATE_OR_CERTIFICATE_REQUEST, TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED): (TlsClientFsmState.WAIT_CERTIFICATE, on_certificate_request_received_cb),
            (TlsClientFsmState.WAIT_CERTIFICATE, TlsClientFsmEvent.CERTIFICATE_RECEIVED): (TlsClientFsmState.WAIT_CERTIFICATE_VERIFY, on_certificate_received_cb),
            (TlsClientFsmState.WAIT_CERTIFICATE_VERIFY, TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED): (TlsClientFsmState.WAIT_FINISHED, on_certificate_verify_received_cb),
            (TlsClientFsmState.WAIT_FINISHED, TlsClientFsmEvent.FINISHED_RECEIVED): (TlsClientFsmState.CONNECTED, on_finished_received_cb),
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
