import unittest
from unittest.mock import Mock

from src.fsm import FSMInvalidEventForStateError
from src.tls_server_fsm import TlsServerFsmEvent, TlsServerFsmState, TlsServerFsm


class TestTlsServerFsm(unittest.TestCase):
    def setUp(self):
        self.tls_states = [state for state in TlsServerFsmState]
        self.tls_events = [event for event in TlsServerFsmEvent]

        self.on_session_begin_transition_cb = Mock(return_value=True)
        self.on_client_hello_received_transition_cb = Mock(return_value=True)
        self.on_finished_received_cb = Mock(return_value=True)

        self.tls_fsm = TlsServerFsm(
            self.on_session_begin_transition_cb,
            self.on_client_hello_received_transition_cb,
            self.on_finished_received_cb
        )

    def test_should_return_tls_states(self):
        self.assertSequenceEqual(self.tls_fsm.get_states(), self.tls_states)

    def test_should_return_tls_events(self):
        self.assertSequenceEqual(self.tls_fsm.get_events(), self.tls_events)

    def test_should_proceed_to_wait_client_hello_state(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsServerFsmState.WAIT_CLIENT_HELLO)

    def test_should_call_on_session_begin_cb_with_context(self):
        ctx = "sb ctx"
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN, ctx)
        self.on_session_begin_transition_cb.assert_called_with(ctx)

    def test_should_not_proceed_to_next_state_if_event_invalid_for_current_state(self):
        self.assertRaises(FSMInvalidEventForStateError, self.tls_fsm.transition, TlsServerFsmEvent.FINISHED_RECEIVED)

    def test_should_proceed_to_wait_finished_state(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsServerFsmEvent.CLIENT_HELLO_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsServerFsmState.WAIT_FINISHED)

    def test_should_call_on_client_hello_received_with_context(self):
        ctx = "chr ctx"
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsServerFsmEvent.CLIENT_HELLO_RECEIVED, ctx)
        self.on_client_hello_received_transition_cb.assert_called_with(ctx)

    def test_should_proceed_to_connected_state(self):
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsServerFsmEvent.CLIENT_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsServerFsmEvent.FINISHED_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsServerFsmState.CONNECTED)

    def test_should_call_on_finished_received_with_context(self):
        ctx = "fr ctx"
        self.tls_fsm.transition(TlsServerFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsServerFsmEvent.CLIENT_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsServerFsmEvent.FINISHED_RECEIVED, ctx)
        self.on_finished_received_cb.assert_called_with(ctx)