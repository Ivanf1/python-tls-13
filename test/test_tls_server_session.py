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

    def test_should_compute_derived_secret_on_session_begin(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        expected_derived_secret = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")
        self.assertEqual(session.derived_secret, expected_derived_secret)