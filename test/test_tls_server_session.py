import unittest
from os import path
from unittest.mock import patch, Mock

from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent
from src.tls_server_session import TlsServerSession
from src.utils import HandshakeMessageType


class TestTlsServerSession(unittest.TestCase):
    def setUp(self):
        self.certificate_path = path.join(path.dirname(path.abspath(__file__)), "data", "server_cert.der")
        self.certificate_private_key_path = path.join(path.dirname(path.abspath(__file__)), "data", "server_key.pem")

        self.client_hello = bytes.fromhex("""16030320210100007c03030000000000000000000000000000000000000000000000000000000000000000000213010054000000160000136578616d706c652e756c666865696d2e6e6574000a0002001d000d00020809002b0002030400330024001d0020080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70675""")

    def test_should_call_transition_on_session_begin(self):
        with patch.object(TlsServerFsm, "transition") as mock_transition:
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            mock_transition.assert_called_with(TlsServerFsmEvent.SESSION_BEGIN)

    def test_should_build_server_hello_on_client_hello_received(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(session.server_hello.to_bytes()[0:1], HandshakeMessageType.SERVER_HELLO.value)

    def test_should_call_on_data_to_send_on_client_hello_received(self):
        on_data_to_send = Mock()
        session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        session.on_record_received(self.client_hello)
        on_data_to_send.assert_called()

    def test_should_build_certificate_message_on_client_hello_received(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(session.certificate_message.to_bytes()[0:1], HandshakeMessageType.CERTIFICATE.value)

    def test_should_call_on_data_to_send_on_client_hello_received_send_certificate(self):
        on_data_to_send = Mock()
        session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(on_data_to_send.call_count, 5)
