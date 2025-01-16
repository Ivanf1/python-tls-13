import unittest

from src.tls_fsm import TlsFsm, TlsFsmState


class TestTlsFsm(unittest.TestCase):
    def setUp(self):
        self.tls_fsm = TlsFsm()

    def test_should_return_tls_states(self):
        tls_states = [state for state in TlsFsmState]
        self.assertSequenceEqual(self.tls_fsm.get_states(), tls_states)
