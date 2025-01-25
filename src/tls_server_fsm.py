from enum import Enum

from src.fsm import FSM


class TlsServerFsmState(Enum):
    START = 0,
    WAIT_FINISHED = 1,
    CONNECTED = 2

class TlsServerFsmEvent(Enum):
    SESSION_BEGIN = 0,
    FINISHED_RECEIVED = 1


class TlsServerFsm(FSM):
    def __init__(
            self,
            on_session_begin_transaction_cb = None,
            on_finished_received_cb = None
    ):
        tls_states = [state for state in TlsServerFsmState]
        self.events = [event for event in TlsServerFsmEvent]

        tls_table = {
            (TlsServerFsmState.START, TlsServerFsmEvent.SESSION_BEGIN): (TlsServerFsmState.WAIT_FINISHED, on_session_begin_transaction_cb),
            (TlsServerFsmState.WAIT_FINISHED, TlsServerFsmEvent.FINISHED_RECEIVED): (TlsServerFsmState.CONNECTED, on_finished_received_cb),
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