import unittest

from src.fsm import FSMInvalidEventForStateError
from src.tls_fsm import TlsFsm, TlsFsmState, TlsFsmEvent


class TestTlsFsm(unittest.TestCase):
    def setUp(self):
        self.tls_states = [state for state in TlsFsmState]
        self.tls_events = [event for event in TlsFsmEvent]
        self.tls_fsm = TlsFsm()

    def test_should_return_tls_states(self):
        self.assertSequenceEqual(self.tls_fsm.get_states(), self.tls_states)

    def test_should_return_tls_events(self):
        self.assertSequenceEqual(self.tls_fsm.get_events(), self.tls_events)

    def test_should_proceed_to_wait_server_hello_state(self):
        self.tls_fsm.transition(self.tls_events[0])
        self.assertEqual(self.tls_fsm.get_current_state(), self.tls_states[1])

    def test_should_not_proceed_to_next_state_if_event_invalid_for_current_state(self):
        self.assertRaises(FSMInvalidEventForStateError, self.tls_fsm.transition, self.tls_events[1])
