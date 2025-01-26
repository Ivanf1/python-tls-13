from enum import Enum

from src.fsm import FSM


class TlsServerFsmState(Enum):
    START = 0,
    WAIT_CLIENT_HELLO = 1,
    WAIT_CERTIFICATE = 2,
    WAIT_CERTIFICATE_VERIFY = 3,
    WAIT_FINISHED = 4,
    CONNECTED = 5

class TlsServerFsmEvent(Enum):
    SESSION_BEGIN = 0,
    CLIENT_HELLO_RECEIVED = 1,
    CERTIFICATE_RECEIVED = 2,
    CERTIFICATE_VERIFY_RECEIVED = 3,
    FINISHED_RECEIVED = 4


class TlsServerFsm(FSM):
    def __init__(
            self,
            client_authentication=False,
            on_session_begin_transaction_cb=None,
            on_client_hello_received_transaction_cb=None,
            on_client_certificate_received_transaction_cb=None,
            on_client_certificate_verify_received_transaction_cb=None,
            on_finished_received_cb=None
    ):
        tls_states = [state for state in TlsServerFsmState]
        self.events = [event for event in TlsServerFsmEvent]

        if client_authentication:
            self.tls_table = {
                (TlsServerFsmState.START, TlsServerFsmEvent.SESSION_BEGIN): (TlsServerFsmState.WAIT_CLIENT_HELLO, on_session_begin_transaction_cb),
                (TlsServerFsmState.WAIT_CLIENT_HELLO, TlsServerFsmEvent.CLIENT_HELLO_RECEIVED): (TlsServerFsmState.WAIT_CERTIFICATE, on_client_hello_received_transaction_cb),
                (TlsServerFsmState.WAIT_CERTIFICATE, TlsServerFsmEvent.CERTIFICATE_RECEIVED): (TlsServerFsmState.WAIT_CERTIFICATE_VERIFY, on_client_certificate_received_transaction_cb),
                (TlsServerFsmState.WAIT_CERTIFICATE_VERIFY, TlsServerFsmEvent.CERTIFICATE_VERIFY_RECEIVED): (TlsServerFsmState.WAIT_FINISHED, on_client_certificate_verify_received_transaction_cb),
                (TlsServerFsmState.WAIT_FINISHED, TlsServerFsmEvent.FINISHED_RECEIVED): (TlsServerFsmState.CONNECTED, on_finished_received_cb),
            }
        else:
            self.tls_table = {
                (TlsServerFsmState.START, TlsServerFsmEvent.SESSION_BEGIN): (TlsServerFsmState.WAIT_CLIENT_HELLO, on_session_begin_transaction_cb),
                (TlsServerFsmState.WAIT_CLIENT_HELLO, TlsServerFsmEvent.CLIENT_HELLO_RECEIVED): (TlsServerFsmState.WAIT_FINISHED, on_client_hello_received_transaction_cb),
                (TlsServerFsmState.WAIT_FINISHED, TlsServerFsmEvent.FINISHED_RECEIVED): (TlsServerFsmState.CONNECTED, on_finished_received_cb),
            }

        super().__init__(
            states=tls_states,
            initial_state=tls_states[0],
            table=self.tls_table,
        )

    def get_states(self):
        return self.states

    def get_events(self):
        return self.events