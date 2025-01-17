import unittest
from unittest.mock import patch

from src.tls_fsm import TlsFsm, TlsFsmEvent
from src.tls_session import TlsSession


class TestTlsSession(unittest.TestCase):
    def setUp(self):
        self.tls_session = TlsSession("example.com")
        self.server_hello = bytes.fromhex("""16 03 03 00 5a 02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")

    def test_should_return_client_hello_message_on_start(self):
        client_hello = self.tls_session.start()
        self.assertEqual(client_hello[5:6], b'\x01')

    # https://datatracker.ietf.org/doc/html/rfc8448#page-7
    # section: {server}  send handshake record
    def test_should_call_transition_on_server_hello_message_received(self):
        with patch.object(TlsFsm, "transition") as mock_transition:
            session = TlsSession("example.com")
            session.on_record_received(self.server_hello)
            mock_transition.assert_called_with(TlsFsmEvent.SERVER_HELLO_RECEIVED, self.server_hello)

    def test_should_compute_derived_secret_on_session_begin(self):
        self.tls_session.start()
        expected_derived_secret = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")
        self.assertEqual(self.tls_session.derived_secret, expected_derived_secret)

    def test_should_compute_client_handshake_key_on_server_hello_received(self):
        self.tls_session.start()
        self.tls_session.on_record_received(self.server_hello)
        self.assertIs(len(self.tls_session.client_handshake_key), 16)

    def test_should_call_transition_on_certificate_message_received(self):
        with patch.object(TlsFsm, "transition") as mock_transition:
            session = TlsSession("example.com")
            session.on_record_received(self.server_hello)
            session.on_record_received(self.server_hello)
            mock_transition.assert_called_with(TlsFsmEvent.SERVER_HELLO_RECEIVED, self.server_hello)
