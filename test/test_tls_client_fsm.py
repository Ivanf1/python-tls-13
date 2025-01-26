import unittest
from unittest.mock import Mock

from src.fsm import FSMInvalidEventForStateError
from src.tls_client_fsm import TlsClientFsm, TlsClientFsmState, TlsClientFsmEvent


class TestTlsClientFsm(unittest.TestCase):
    def setUp(self):
        self.tls_states = [state for state in TlsClientFsmState]
        self.tls_events = [event for event in TlsClientFsmEvent]

        self.on_session_begin_transaction_cb = Mock(return_value=True)
        self.on_server_hello_received_cb = Mock(return_value=True)
        self.on_encrypted_extensions_received_cb = Mock(return_value=True)
        self.on_certificate_request_received_cb = Mock(return_value=True)
        self.on_certificate_received_cb = Mock(return_value=True)
        self.on_certificate_verify_received_cb = Mock(return_value=True)
        self.on_finished_received_cb = Mock(return_value=True)

        self.tls_fsm = TlsClientFsm(
            on_session_begin_transaction_cb=self.on_session_begin_transaction_cb,
            on_server_hello_received_cb=self.on_server_hello_received_cb,
            on_encrypted_extensions_received_cb=self.on_encrypted_extensions_received_cb,
            on_certificate_request_received_cb=self.on_certificate_request_received_cb,
            on_certificate_received_cb=self.on_certificate_received_cb,
            on_certificate_verify_received_cb=self.on_certificate_verify_received_cb,
            on_finished_received_cb=self.on_finished_received_cb
        )

    def test_should_return_tls_states(self):
        self.assertSequenceEqual(self.tls_fsm.get_states(), self.tls_states)

    def test_should_return_tls_events(self):
        self.assertSequenceEqual(self.tls_fsm.get_events(), self.tls_events)

    def test_should_proceed_to_wait_server_hello_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_SERVER_HELLO)

    def test_should_call_on_session_begin_cb_with_context(self):
        ctx = "sb ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN, ctx)
        self.on_session_begin_transaction_cb.assert_called_with(ctx)

    def test_should_not_proceed_to_next_state_if_event_invalid_for_current_state(self):
        self.assertRaises(FSMInvalidEventForStateError, self.tls_fsm.transition, TlsClientFsmEvent.SERVER_HELLO_RECEIVED)

    def test_should_proceed_to_wait_encrypted_extensions_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_ENCRYPTED_EXTENSIONS)

    def test_should_call_on_server_hello_received_with_context(self):
        ctx = "shr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED, ctx)
        self.on_server_hello_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_wait_certificate_or_certificate_request_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_CERTIFICATE_OR_CERTIFICATE_REQUEST)

    def test_should_call_on_encrypted_extensions_received_with_context(self):
        ctx = "cr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED, ctx)
        self.on_encrypted_extensions_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_wait_certificate_verify_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_CERTIFICATE_VERIFY)

    def test_should_call_on_certificate_received_with_context(self):
        ctx = "cr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED, ctx)
        self.on_certificate_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_wait_finished_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_FINISHED)

    def test_should_call_on_certificate_verify_received_with_context(self):
        ctx = "cvr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED, ctx)
        self.on_certificate_verify_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_connected_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.FINISHED_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.CONNECTED)

    def test_should_call_on_finished_received_with_context(self):
        ctx = "fr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.FINISHED_RECEIVED, ctx)
        self.on_finished_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_wait_certificate_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_CERTIFICATE)

    def test_should_call_on_certificate_request_received_with_context(self):
        ctx = "crr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED, ctx)
        self.on_certificate_request_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_wait_certificate_verify_on_certificate_request_path_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_CERTIFICATE_VERIFY)

    def test_should_call_on_certificate_received_with_context_on_certificate_request_path(self):
        ctx = "cr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED, ctx)
        self.on_certificate_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_wait_finished_on_certificate_request_path_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.WAIT_FINISHED)

    def test_should_call_on_certificate_verify_received_with_context_on_certificate_request_path(self):
        ctx = "cvr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED, ctx)
        self.on_certificate_verify_received_cb.assert_called_with(ctx)

    def test_should_proceed_to_connected_on_certificate_request_path_state(self):
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.FINISHED_RECEIVED)
        self.assertEqual(self.tls_fsm.get_current_state(), TlsClientFsmState.CONNECTED)

    def test_should_call_on_finished_received_with_context_on_certificate_request_path(self):
        ctx = "fr ctx"
        self.tls_fsm.transition(TlsClientFsmEvent.SESSION_BEGIN)
        self.tls_fsm.transition(TlsClientFsmEvent.SERVER_HELLO_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.ENCRYPTED_EXTENSIONS_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_REQUEST_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.CERTIFICATE_VERIFY_RECEIVED)
        self.tls_fsm.transition(TlsClientFsmEvent.FINISHED_RECEIVED, ctx)
        self.on_finished_received_cb.assert_called_with(ctx)
