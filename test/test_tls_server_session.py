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
        self.assertEqual(on_data_to_send.call_args_list[0][0][0][0:1], HandshakeMessageType.SERVER_HELLO.value)

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

    def test_should_send_encrypted_extensions_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_encrypted_extensions = bytes.fromhex("1703030017d74d67afb101c470f1c72077345866a3d49ada443dd4aa")
            self.assertEqual(on_data_to_send.call_args_list[1][0][0], expected_encrypted_extensions)

    def test_should_build_certificate_message(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_certificate = bytes.fromhex("0b0003ff000003fb0003f6308203f2308202daa0030201020214282641bd2d3a3bf80ba1a5dfd8d36edcf6d08b29300d06092a864886f70d01010b050030818e310b30090603550406130249543110300e06035504080c0753616c65726e6f3110300e06035504070c0753616c65726e6f31123010060355040a0c09556e6973615f696f7431123010060355040b0c09556e6973615f696f743112301006035504030c09556e6973615f696f74311f301d06092a864886f70d0109011610636140756e6973612d696f742e636f6d301e170d3235303132323132313431345a170d3236303132323132313431345a308192310b30090603550406130249543110300e06035504080c0753616c65726e6f3110300e06035504070c0753616c65726e6f31123010060355040a0c09556e6973615f696f7431123010060355040b0c09556e6973615f696f743112301006035504030c09556e6973615f696f743123302106092a864886f70d010901161473657276657240756e6973612d696f742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100bf8d0c6986901e7047c2fd0679d5b001ada290aa4625be47773933d6f01876fbd1c60b7ded9cd802ae212d02fd85ced0c87019531748caa1ff8a6f36de93cb395b52fd964c9938322325950f27afe52019b3e02d993b69fcba4b1515147c033a3e6534bae777fcf4e8260fe70b909dcdfa9101147f9b9cdaddb0979b818b738f00487eac30338406356d4d1c8562744e440c952b898f96d03915cff1fb6db35e6668a0053b09ccd58d70f295bbb4989dd31f0e35362b5939f82cd496fd299c18558e575371283ff04a154aa05efaf4fe1682f5c1d43b827d3eaa31775270ecbd1286e469dd862f1091975c126dcfcad223622944db9d83a536ba6170d21fe9f10203010001a3423040301d0603551d0e0416041443db40dd5f49018db2b811ea8e3852931ed0b0c9301f0603551d23041830168014bc750ec2a469bc813f0576eec5c2a21c08851b6a300d06092a864886f70d01010b05000382010100245fa578371b0dc4932f7c2e2627d347c1026ee22558d57302e5b3f0bc8d6f60de6d92c3c80e79cb9c81c7b91387b987f784af8293b22c2d89d6452d96e9bd8cdc38a991e9856f516b0d4940eacc22aad24886fc794290dc333f843c6da382d444ff788579038872bc27db1a4f6fe6809e38e00bf10be474eb480c619e111e2c0f8e2da9d8fc56ea740e0b21ee07869722c54500a94fc169fec1a4e5342494627746527e5576b53639db0e9ab58b210b598248fa519a591a8a7ae294240e96920e4e18f6b3ecfe02e69043e2ac871a144352a30223f67e992f0ae4f12564809143d0807c33efca58a9d8e50d0edda36e59b5869f04685eddd79a04c5b84e81740000")
            self.assertEqual(session.certificate_message.to_bytes(), expected_certificate)
