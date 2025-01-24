import unittest
from os import path
from unittest.mock import patch, Mock

from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent
from src.tls_server_session import TlsServerSession
from src.utils import HandshakeMessageType


class TestTlsServerSession(unittest.TestCase):
    def setUp(self):
        self.certificate_path = path.join(path.dirname(path.abspath(__file__)), "data", "server_cert.der")

        self.client_hello = bytes.fromhex("""17 03 03 01 02 01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
        12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
        75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 03 04 00 33 00 24 00 1d 00 20 35 80 
        72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54""")

    def test_should_call_transition_on_session_begin(self):
        with patch.object(TlsServerFsm, "transition") as mock_transition:
            session = TlsServerSession(Mock(), self.certificate_path)
            session.start()
            mock_transition.assert_called_with(TlsServerFsmEvent.SESSION_BEGIN)

    def test_should_build_server_hello_on_client_hello_received(self):
        session = TlsServerSession(Mock(), self.certificate_path)
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(session.server_hello.to_bytes()[0:1], HandshakeMessageType.SERVER_HELLO.value)

    def test_should_call_on_data_to_send_on_client_hello_received(self):
        on_data_to_send = Mock()
        session = TlsServerSession(on_data_to_send, self.certificate_path)
        session.start()
        session.on_record_received(self.client_hello)
        on_data_to_send.assert_called()

    def test_should_build_certificate_message_on_client_hello_received(self):
        session = TlsServerSession(Mock(), self.certificate_path)
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(session.certificate_message.to_bytes()[0:1], HandshakeMessageType.CERTIFICATE.value)

    def test_should_call_on_data_to_send_on_client_hello_received_send_certificate(self):
        on_data_to_send = Mock()
        session = TlsServerSession(on_data_to_send, self.certificate_path)
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(on_data_to_send.call_count, 2)
