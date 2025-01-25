import unittest
from os import path
from unittest.mock import patch, Mock

from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent
from src.tls_server_session import TlsServerSession


class TestTlsServerSession(unittest.TestCase):
    def setUp(self):
        self.certificate_path = path.join(path.dirname(path.abspath(__file__)), "data", "server_cert.der")
        self.certificate_private_key_path = path.join(path.dirname(path.abspath(__file__)), "data", "server_key.pem")

    def test_should_call_transition_on_session_begin(self):
        with patch.object(TlsServerFsm, "transition") as mock_transition:
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            mock_transition.assert_called_with(TlsServerFsmEvent.SESSION_BEGIN)