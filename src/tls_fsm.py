from enum import Enum

from src.fsm import FSM


class TlsFsmState(Enum):
    START = 0,
    WAIT_SERVER_HELLO = 1,
    WAIT_CERTIFICATE = 2,
    WAIT_CERTIFICATE_VERIFY = 3,
    WAIT_FINISHED = 4,
    CONNECTED = 5

class TlsFsmEvent(Enum):
    SESSION_BEGIN = 0,
    SERVER_HELLO_RECEIVED = 1,
    CERTIFICATE_RECEIVED = 2,
    CERTIFICATE_VERIFY_RECEIVED = 3,
    FINISHED_RECEIVED = 4


class TlsFsm(FSM):
    def __init__(self):
        tls_states = [state for state in TlsFsmState]
        self.events = [event for event in TlsFsmEvent]

        tls_table = {
            (TlsFsmState.START, TlsFsmEvent.SESSION_BEGIN): (TlsFsmState.WAIT_SERVER_HELLO, self._on_session_begin())
        }

        super().__init__(
            states=tls_states,
            initial_state=tls_states[0],
            table=tls_table,
        )

    def _on_session_begin(self):
        pass

    def get_states(self):
        return self.states

    def get_events(self):
        return self.events
