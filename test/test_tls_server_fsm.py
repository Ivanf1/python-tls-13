import unittest
from unittest.mock import Mock

from src.tls_server_fsm import TlsServerFsmEvent, TlsServerFsmState, TlsServerFsm


class TestTlsServerFsm(unittest.TestCase):
    def setUp(self):
        self.tls_states = [state for state in TlsServerFsmState]
        self.tls_events = [event for event in TlsServerFsmEvent]

        self.on_session_begin_transaction_cb = Mock(return_value=True)
        self.on_finished_received_cb = Mock(return_value=True)

        self.tls_fsm = TlsServerFsm(
            self.on_session_begin_transaction_cb,
            self.on_finished_received_cb
        )

    def test_should_return_tls_states(self):
        self.assertSequenceEqual(self.tls_fsm.get_states(), self.tls_states)

    def test_should_return_tls_events(self):
        self.assertSequenceEqual(self.tls_fsm.get_events(), self.tls_events)