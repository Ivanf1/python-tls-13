import unittest
from unittest.mock import patch

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
        self.tls_fsm.transition(TlsFsmEvent.SESSION_BEGIN)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsFsmState.WAIT_SERVER_HELLO)

    def test_should_not_proceed_to_next_state_if_event_invalid_for_current_state(self):
        self.assertRaises(FSMInvalidEventForStateError, self.tls_fsm.transition, TlsFsmEvent.SERVER_HELLO_RECEIVED)

    def test_should_proceed_to_wait_certificate_state(self):
        with patch.object(TlsFsm, "_on_server_hello_received", return_value=True):
            fsm = TlsFsm()
            fsm.transition(TlsFsmEvent.SESSION_BEGIN)
            fsm.transition(TlsFsmEvent.SERVER_HELLO_RECEIVED)
            self.assertEqual(fsm.get_current_state(), TlsFsmState.WAIT_CERTIFICATE)

    def test_should_proceed_to_wait_certificate_verify_state(self):
        with patch.object(TlsFsm, "_on_server_hello_received", return_value=True), \
                patch.object(TlsFsm, "_on_certificate_received", return_value=True):
            fsm = TlsFsm()
            fsm.transition(TlsFsmEvent.SESSION_BEGIN)
            fsm.transition(TlsFsmEvent.SERVER_HELLO_RECEIVED)
            fsm.transition(TlsFsmEvent.CERTIFICATE_RECEIVED)
            self.assertEqual(fsm.get_current_state(), TlsFsmState.WAIT_CERTIFICATE_VERIFY)

    def test_should_proceed_to_wait_finished_state(self):
        with patch.object(TlsFsm, "_on_server_hello_received", return_value=True), \
                patch.object(TlsFsm, "_on_certificate_received", return_value=True), \
                patch.object(TlsFsm, "_on_certificate_verify_received", return_value=True):
            fsm = TlsFsm()
            fsm.transition(TlsFsmEvent.SESSION_BEGIN)
            fsm.transition(TlsFsmEvent.SERVER_HELLO_RECEIVED)
            fsm.transition(TlsFsmEvent.CERTIFICATE_RECEIVED)
            fsm.transition(TlsFsmEvent.CERTIFICATE_VERIFY_RECEIVED)
            self.assertEqual(fsm.get_current_state(), TlsFsmState.WAIT_FINISHED)
