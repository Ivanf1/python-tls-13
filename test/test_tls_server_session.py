import binascii
import unittest
from os import path
from unittest.mock import patch, Mock, PropertyMock
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

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

    def test_should_compute_derived_secret_on_session_begin(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        expected_derived_secret = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")
        self.assertEqual(session.derived_secret, expected_derived_secret)

    def test_should_build_server_hello_on_client_hello_received(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(session.server_hello.to_bytes()[0:1], HandshakeMessageType.SERVER_HELLO.value)

    def test_should_call_on_data_to_send_with_server_hello(self):
        on_data_to_send = Mock()
        session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(on_data_to_send.call_args[0][0][0:1], HandshakeMessageType.SERVER_HELLO.value)

    def test_should_extract_client_public_key(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
        session.start()
        session.on_record_received(self.client_hello)
        expected_client_public_key = bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70675")
        self.assertEqual(session.client_public_key.public_bytes_raw(), expected_client_public_key)

    def test_should_compute_handshake_secret(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_handshake_secret = bytes.fromhex("50c9bf2ccf0bf2207aa98f64669ee533767f0259dfd0671cb65e35f6a981e5a9")
            self.assertEqual(session.handshake_secret, expected_handshake_secret)

    def test_should_compute_client_handshake_key(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
            patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_client_handshake_key = bytes.fromhex("7c0d79e865a4a5c74b87c11fa9aa15b4")
            self.assertEqual(session.client_handshake_key, expected_client_handshake_key)

    def test_should_compute_client_handshake_iv(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_client_handshake_iv = bytes.fromhex("a54bb96d5f0862b613740371")
            self.assertEqual(session.client_handshake_iv, expected_client_handshake_iv)

    def test_should_compute_server_handshake_key(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_server_handshake_key = bytes.fromhex("e5c074bdd75c24a6f028774d1dd6a7c8")
            self.assertEqual(session.server_handshake_key, expected_server_handshake_key)

    def test_should_compute_server_handshake_iv(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_server_handshake_iv = bytes.fromhex("decf18f51af9585d6f8ed346")
            self.assertEqual(session.server_handshake_iv, expected_server_handshake_iv)

    def test_should_build_encrypted_extensions_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_encrypted_extensions = bytes.fromhex("080000020000")
            self.assertEqual(session.encrypted_extensions.to_bytes(), expected_encrypted_extensions)
