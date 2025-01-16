import unittest

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