import binascii
import unittest
from os import path
from unittest.mock import patch, Mock, PropertyMock
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.tls_server_fsm import TlsServerFsm, TlsServerFsmEvent, TlsServerFsmState
from src.tls_server_session import TlsServerSession
from src.utils import HandshakeMessageType



class TestTlsServerSession(unittest.TestCase):
    def setUp(self):
        self.certificate_path = path.join(path.dirname(path.abspath(__file__)), "data", "server_cert.der")
        self.certificate_private_key_path = path.join(path.dirname(path.abspath(__file__)), "data", "server_key.pem")
        self.client_hello = bytes.fromhex("""16030320210100007c03030000000000000000000000000000000000000000000000000000000000000000000213010054000000160000136578616d706c652e756c666865696d2e6e6574000a0002001d000d00020809002b0002030400330024001d0020080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70675""")
        self.client_handshake_finished = bytes.fromhex("1703030035f46a88459776b4419aebdd7a5386280a0bf118d249959e3be9755b55bf16add32491edd1618af56be554847d13f71f9eb62912f73b")

    def test_should_call_transition_on_session_begin(self):
        with patch.object(TlsServerFsm, "transition") as mock_transition:
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            mock_transition.assert_called_with(TlsServerFsmEvent.SESSION_BEGIN)

    def test_should_compute_derived_secret_on_session_begin(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
        session.start()
        expected_derived_secret = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")
        self.assertEqual(session.derived_secret, expected_derived_secret)

    def test_should_build_server_hello_on_client_hello_received(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(session.server_hello.to_bytes()[0:1], HandshakeMessageType.SERVER_HELLO.value)

    def test_should_call_on_data_to_send_with_server_hello(self):
        on_data_to_send = Mock()
        session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
        session.start()
        session.on_record_received(self.client_hello)
        self.assertEqual(on_data_to_send.call_args_list[0][0][0][5:6], HandshakeMessageType.SERVER_HELLO.value)

    def test_should_extract_client_public_key(self):
        session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
        session.start()
        session.on_record_received(self.client_hello)
        expected_client_public_key = bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70675")
        self.assertEqual(session.client_public_key.public_bytes_raw(), expected_client_public_key)

    def test_should_compute_handshake_secret(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_handshake_secret = bytes.fromhex("50c9bf2ccf0bf2207aa98f64669ee533767f0259dfd0671cb65e35f6a981e5a9")
            self.assertEqual(session.handshake_secret, expected_handshake_secret)

    def test_should_compute_client_handshake_key(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
            patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_client_handshake_key = bytes.fromhex("7c0d79e865a4a5c74b87c11fa9aa15b4")
            self.assertEqual(session.client_handshake_key, expected_client_handshake_key)

    def test_should_compute_client_handshake_iv(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_client_handshake_iv = bytes.fromhex("a54bb96d5f0862b613740371")
            self.assertEqual(session.client_handshake_iv, expected_client_handshake_iv)

    def test_should_compute_server_handshake_key(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_server_handshake_key = bytes.fromhex("e5c074bdd75c24a6f028774d1dd6a7c8")
            self.assertEqual(session.server_handshake_key, expected_server_handshake_key)

    def test_should_compute_server_handshake_iv(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_server_handshake_iv = bytes.fromhex("decf18f51af9585d6f8ed346")
            self.assertEqual(session.server_handshake_iv, expected_server_handshake_iv)

    def test_should_build_encrypted_extensions_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
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
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_encrypted_extensions = bytes.fromhex("1703030017d74d67afb101c470f1c72077345866a3d49ada443dd4aa")
            self.assertEqual(on_data_to_send.call_args_list[1][0][0], expected_encrypted_extensions)

    def test_should_build_certificate_message(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_certificate = bytes.fromhex("0b0003ff000003fb0003f6308203f2308202daa0030201020214282641bd2d3a3bf80ba1a5dfd8d36edcf6d08b29300d06092a864886f70d01010b050030818e310b30090603550406130249543110300e06035504080c0753616c65726e6f3110300e06035504070c0753616c65726e6f31123010060355040a0c09556e6973615f696f7431123010060355040b0c09556e6973615f696f743112301006035504030c09556e6973615f696f74311f301d06092a864886f70d0109011610636140756e6973612d696f742e636f6d301e170d3235303132323132313431345a170d3236303132323132313431345a308192310b30090603550406130249543110300e06035504080c0753616c65726e6f3110300e06035504070c0753616c65726e6f31123010060355040a0c09556e6973615f696f7431123010060355040b0c09556e6973615f696f743112301006035504030c09556e6973615f696f743123302106092a864886f70d010901161473657276657240756e6973612d696f742e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100bf8d0c6986901e7047c2fd0679d5b001ada290aa4625be47773933d6f01876fbd1c60b7ded9cd802ae212d02fd85ced0c87019531748caa1ff8a6f36de93cb395b52fd964c9938322325950f27afe52019b3e02d993b69fcba4b1515147c033a3e6534bae777fcf4e8260fe70b909dcdfa9101147f9b9cdaddb0979b818b738f00487eac30338406356d4d1c8562744e440c952b898f96d03915cff1fb6db35e6668a0053b09ccd58d70f295bbb4989dd31f0e35362b5939f82cd496fd299c18558e575371283ff04a154aa05efaf4fe1682f5c1d43b827d3eaa31775270ecbd1286e469dd862f1091975c126dcfcad223622944db9d83a536ba6170d21fe9f10203010001a3423040301d0603551d0e0416041443db40dd5f49018db2b811ea8e3852931ed0b0c9301f0603551d23041830168014bc750ec2a469bc813f0576eec5c2a21c08851b6a300d06092a864886f70d01010b05000382010100245fa578371b0dc4932f7c2e2627d347c1026ee22558d57302e5b3f0bc8d6f60de6d92c3c80e79cb9c81c7b91387b987f784af8293b22c2d89d6452d96e9bd8cdc38a991e9856f516b0d4940eacc22aad24886fc794290dc333f843c6da382d444ff788579038872bc27db1a4f6fe6809e38e00bf10be474eb480c619e111e2c0f8e2da9d8fc56ea740e0b21ee07869722c54500a94fc169fec1a4e5342494627746527e5576b53639db0e9ab58b210b598248fa519a591a8a7ae294240e96920e4e18f6b3ecfe02e69043e2ac871a144352a30223f67e992f0ae4f12564809143d0807c33efca58a9d8e50d0edda36e59b5869f04685eddd79a04c5b84e81740000")
            self.assertEqual(session.certificate_message.to_bytes(), expected_certificate)

    def test_should_send_certificate_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_certificate = bytes.fromhex("170303041444b136b9a77f5fcbcf13169202c0528aec57611798c3c3f450844e5bb8f0bfbd57af1ac29037da8a5d0c1ad19599d5d22c451d37bb311f7358d0f8026f5108b39b107f6606a62736b68415c333453df2746a910a3e08167950a91887c8fef56c21a8c281d5e2ce9ecc538a588def18895c58073f67dfeb3fdbecf032d0ee3bd2d75360c6c496821ed1941b1d44ee10717c593314c79e5cbb62114a4225e4054987777e8efa7984d93ae36b50107a02d15bcdc4a5939915323943d23984327de21190506af843ea50115da49f2cd12e86a0cd06d49cb5dd3c65e17934344fc51075c6d22728c1504983ea76cb3440af3d3559a14a62d5887f5d23d63c0527c1af17076395ab71ca358a3871da170324a7428317d2ea883c668c20eb9cbe960469de35c4b15d3468159727c09659257b1647f6803ec9def19dbdc16b58b4b5f4ba2f3fabbd2c621e4d80fde7e9319018113e5fcb6ecec95d5e0c38bfc5879f99749b1f9de6d3504ad376038437edd2fcdd95ed050ad42e4bc38ecefb848466bfda6fa325c3ab4e16148b4078a5002152aedc5f9919b6a30deaf4e1ea51e1fd5660d7ee4ca16c1afc6801849b4c28be73fa93ecce940925096493c7cc7cabe4fefbdcb685ea4ca0e5083a85ad432a839612f35d7b21f2cf4423abd87c497bb2c785f322af113b5e9d0b9c287cf45bf9bb8db4ec4df64f2ac74b018aa2d825d6382c213c7b29fd00acb9ca33c5f63fa6e9e488f929de149f6842c7e2f35e6d386c19557e3c98fffb79598fd56f72d730811280cf3de7c4ae732eb811dac7f4ea0d9c47cbaf2fae334a3ccb896b20e93f9e4ce40d711402b736a7701f5de1deb897e155b2c6507071e2807278f51d1918215c3b5c60b907206f9e97c297c8dbc79318e099148ca348848b3f95218b206bf395e976e348b9d55e6bec511955e5ce93f09eb4c9ac7ed47cf7ce7142065ff1516e5dafa534cd229926c0ed3ab3ce863785f62156cc0972a382b61ef5870c3a38842414cc6f33612d2c00cd3e38efca4549757e2cfdd77def2f548efe1c13cde00659c6161d30357237fa86e08bd9c672b781a4298b0dd0b47a9da868931f27da4d026db74bcb9a70b880273c66d696ff3e1ba72d3eb83afb6c0b087a59de60fe82836938c78818b1183d9edc2746eefefcfab7194945d7b8750ac2142eebf79d9412fd992b16284eba6adef7f72d5506ad18d8df4fc2eeb2e34a22e8855858da32219d6f318fe122af847aceae9e25d82e748cdc75ded7108361c6f16263d2e28690823e3cdc5e9ce7d4eff61772dcdef20b84436531efe579b9d70eb67d25c6c559423619dfbc6e63e9e9baa618f60a089fdb2e99210d8d9e784c378d9bc1dc81157b8716a9a18fc095c05b87fb0dec37248769533e9cd2d562ccf4f858ee2d0417e017b4e7f0345b5bb4e4f2fb236c28fe23bf1909be29156e867bc61aa9f23aa39adedc")
            self.assertEqual(on_data_to_send.call_args_list[2][0][0], expected_certificate)

    def test_should_build_certificate_verify_message(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_certificate_verify_start = bytes.fromhex("0f")
            self.assertEqual(session.certificate_verify.to_bytes()[0:1], expected_certificate_verify_start)

    def test_should_send_certificate_verify_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_certificate_verify_header = bytes.fromhex("1703030119")
            self.assertEqual(on_data_to_send.call_args_list[3][0][0][0:5], expected_certificate_verify_header)

    def test_should_build_server_handshake_finished_message(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_handshake_finished_message = bytes.fromhex("14000020bb2d7d2a02263f1f66adcc6e0c58848807efcb4d4a4cf46fcad923967380928a")
            self.assertEqual(session.server_handshake_finished.to_bytes(), expected_handshake_finished_message)

    def test_should_send_server_handshake_finished_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            expected_server_handshake_finished = bytes.fromhex("1703030035778b9c5eac6e5a2c27e93cf28254780758ab642e292d444829ed29eebdf22143be3a729f98e8d9080e44681c848e7745578c211f37")
            self.assertEqual(on_data_to_send.call_args_list[4][0][0], expected_server_handshake_finished)

    def test_should_store_client_handshake_finished(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            session.on_record_received(self.client_handshake_finished)
            expected_client_handshake_finished = bytes.fromhex("1400002080f94998017147fb7b4b33bcfd637a0cf5f369a1e005ac51cda5565469d8de3e")
            self.assertEqual(session.client_handshake_finished.to_bytes(), expected_client_handshake_finished)

    def test_should_compute_client_application_key(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            session.on_record_received(self.client_handshake_finished)
            self.assertEqual(len(session.client_application_key), 16)

    def test_should_compute_client_application_iv(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            session.on_record_received(self.client_handshake_finished)
            self.assertEqual(len(session.client_application_iv), 12)

    def test_should_compute_server_application_key(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            session.on_record_received(self.client_handshake_finished)
            self.assertEqual(len(session.server_application_key), 16)

    def test_should_compute_server_application_iv(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.client_hello)
            session.on_record_received(self.client_handshake_finished)
            self.assertEqual(len(session.server_application_iv), 12)

    def test_should_call_on_application_data_on_application_data_received(self):
        with patch.object(TlsServerSession, "client_application_key", new_callable=PropertyMock) as mock_application_key, \
                patch("src.tls_server_session.compute_new_nonce") as mock_application_iv, \
                patch.object(TlsServerFsm, "get_current_state") as mock_tlsfsm:
            mock_application_key.return_value = bytes.fromhex("""01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27""")
            mock_application_iv.return_value = bytes.fromhex("""196a750b0c5049c0cc51a540""")

            mock_tlsfsm.return_value = TlsServerFsmState.CONNECTED

            on_application_message_callback = Mock()

            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), on_application_message_callback)
            session.start()
            session.on_record_received(bytes.fromhex("""17 03 03 00 ea 38 ad fb 1d 01 fd 95 a6 03 85 e8 bb f1 fd 8d cb 46 70 98 97 e7 d6 74 
                c2 f7 37 0e c1 1d 8e 33 eb 4f 4f e7 f5 4b f4 dc 0b 92 fa e7 42 1c 33 c6 45 3c eb c0 73 15 96 10 a0 97 40 ab 2d 
                05 6f 8d 51 cf a2 62 00 7d 40 12 36 da fc 2f 72 92 ff 0c c8 86 a4 ef 38 9f 2c ed 12 26 c6 b4 dc f6 9d 99 4f f9 
                14 8e f9 69 bc 77 d9 43 3a b1 d3 a9 32 54 21 82 82 9f 88 9a d9 5f 04 c7 52 f9 4a ce 57 14 6a 5d 84 b0 42 bf b3 
                48 5a 64 e7 e9 57 b0 89 80 cd 08 ba f9 69 8b 89 29 98 6d 11 74 d4 aa 6d d7 a7 e8 c0 86 05 2c 3c 76 d8 19 34 bd 
                f5 9b 96 6e 39 20 31 f3 47 1a de bd dd db e8 4f cf 1f f4 08 84 6a e9 b2 8c a4 a9 e7 28 84 4a 49 3d 80 45 5d 6e 
                af f2 05 b4 0a 1e f1 85 74 ef c0 b9 6a d3 83 af bd 8d fc 86 f8 08 7c 1f 7d c8"""))
            expected_application_message = bytes.fromhex("""04 00 00 d5 00 00 1c 20 00 00 00 00 08 00 00 
                00 00 00 00 00 01 00 c0 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 00 49 56 44 41 54 41 49 56 44 41 54 41 
                00 41 45 53 cb 11 9d 4d bd 2a 21 ec c2 26 a6 09 0e e8 ca 58 df 09 03 9b 35 96 f4 de 79 98 0e a3 25 d5 14 62 
                5c 0c 21 c5 0f 03 26 1d c4 2c e7 c5 97 0c 4c 01 16 06 fb 99 8a 86 c3 fa 30 e5 5e ea 91 f1 ff f3 18 fc 7b d5 
                88 31 bf 49 c8 8d 7b 59 05 91 a6 5c 7d e8 cf c6 77 46 8a 54 fd be c0 d8 53 be 20 21 c8 bb fc db e5 1f 5d 9a 
                0c 70 85 84 1a 01 e4 95 85 f6 8b 4a fe e1 d7 07 e2 cb b1 a0 b4 23 aa 7e 32 d5 60 7b d9 9d d4 db 3c 9a aa ed 
                43 d3 5d 26 b4 b1 c6 84 71 71 ea a0 7a 9b c8 cb f7 58 49 9a 00 00""")
            on_application_message_callback.assert_called_with(expected_application_message)

    def test_should_call_on_connected_on_handshake_finished(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_connected = Mock()
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, on_connected, Mock())
            session.start()
            session.on_record_received(self.client_hello)
            session.on_record_received(self.client_handshake_finished)
            on_connected.assert_called_once()

    def test_should_build_certificate_request_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            session = TlsServerSession(Mock(), self.certificate_path, self.certificate_private_key_path, Mock(), Mock(), client_authentication=True)
            session.start()
            session.on_record_received(self.client_hello)
            expected_certificate_request = bytes.fromhex("0d000009000006000d00020809")
            self.assertEqual(session.certificate_request.to_bytes(), expected_certificate_request)

    def test_should_certificate_request_record(self):
        with patch("src.tls_server_session.get_X25519_private_key") as mock_server_private_key, \
                patch("src.messages.server_hello_message_builder.get_32_random_bytes") as mock_server_random:
            mock_server_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("080d0f5fc5c556684df38ae7bbce90a1e1fae852ad65e46a78d7e81402b70677"))
            mock_server_random.return_value = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
            on_data_to_send = Mock()
            session = TlsServerSession(on_data_to_send, self.certificate_path, self.certificate_private_key_path, Mock(), Mock(), client_authentication=True)
            session.start()
            session.on_record_received(self.client_hello)
            expected_certificate_request = bytes.fromhex("170303001e42b1354fa77f5a30c210e2aa89d50e1922b56ef1cc81ca46f388590c2500")
            self.assertEqual(on_data_to_send.call_args_list[2][0][0], expected_certificate_request)
