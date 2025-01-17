import unittest
from unittest.mock import patch

from src.tls_fsm import TlsFsm
from src.tls_session import TlsSession
from src.utils import HandshakeMessageType


class TestTlsSession(unittest.TestCase):
    def setUp(self):
        self.tls_session = TlsSession("example.com")

    def test_should_return_client_hello_message_on_start(self):
        client_hello = self.tls_session.start()
        self.assertEqual(client_hello[5:6], b'\x01')

    # https://datatracker.ietf.org/doc/html/rfc8448#page-7
    # section: {server}  send handshake record
    def test_should_call_transition_on_server_hello_message_received(self):
        record = bytes.fromhex("""16 03 03 00 5a 02 00 00 56 03 03 a6
         af 06 a4 12 18 60 dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14
         34 da c1 55 77 2e d3 e2 69 28 00 13 01 00 00 2e 00 33 00 24 00
         1d 00 20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6
         cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f 00 2b 00 02 03 04""")
        with patch.object(TlsFsm, "transition") as mock_transition:
            session = TlsSession("example.com")
            session.on_record_received(record)
            mock_transition.assert_called_with(HandshakeMessageType.SERVER_HELLO, record)
