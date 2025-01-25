import unittest
from os import path
from unittest.mock import patch, PropertyMock, Mock

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.messages.client_hello_message_builder import ClientHelloMessageBuilder
from src.tls_fsm import TlsFsm, TlsFsmEvent, TlsFsmState
from src.tls_session import TlsSession


class TestTlsSession(unittest.TestCase):
    def setUp(self):
        self.on_connected = Mock()
        self.root_certificate_path = path.join(path.dirname(path.abspath(__file__)), "data", "ca_cert.der")
        self.tls_session = TlsSession("example.com", self.on_connected, self.root_certificate_path, Mock(), Mock())
        self.server_hello = bytes.fromhex("""16 03 03 00 5a 02 00 00 56 03 03 a6 af 06 a4 12 18 60
         dc 5e 6e 60 24 9c d3 4c 95 93 0c 8a c5 cb 14 34 da c1 55 77 2e
         d3 e2 69 28 13 01 00 2e 00 2b 00 02 03 04 00 33 00 24 00 1d 00 
         20 c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6 72 e1 56 d6 cc 25 
         3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f""")
        self.encrypted_extensions = bytes.fromhex("17 03 03 00 17 6b e0 2f 9d a7 c2 dc 9d de f5 6f 24 68 b9 0a df a2 51 01 ab 03 44 ae")
        self.server_certificate = bytes.fromhex("""17 03 03 03 43 ba f0 0a 9b e5 0f 3f 23 07 e7 26 ed cb da cb e4 b1 86 16 44 9d 46 c6 20 7a f6 e9 95 3e e5 d2 41 1b a6 5d 31 fe af 4f 78 76 4f 2d 69 39 87 18 6c c0 13 29 c1 87 a5 e4 60 8e 8d 27 b3 18 e9 8d d9 47 69 f7 73 9c e6 76 83 92 ca ca 8d cc 59 7d 77 ec 0d 12 72 23 37 85 f6 e6 9d 6f 43 ef fa 8e 79 05 ed fd c4 03 7e ee 59 33 e9 90 a7 97 2f 20 69 13 a3 1e 8d 04 93 13 66 d3 d8 bc d6 a4 a4 d6 47 dd 4b d8 0b 0f f8 63 ce 35 54 83 3d 74 4c f0 e0 b9 c0 7c ae 72 6d d2 3f 99 53 df 1f 1c e3 ac eb 3b 72 30 87 1e 92 31 0c fb 2b 09 84 86 f4 35 38 f8 e8 2d 84 04 e5 c6 c2 5f 66 a6 2e be 3c 5f 26 23 26 40 e2 0a 76 91 75 ef 83 48 3c d8 1e 6c b1 6e 78 df ad 4c 1b 71 4b 04 b4 5f 6a c8 d1 06 5a d1 8c 13 45 1c 90 55 c4 7d a3 00 f9 35 36 ea 56 f5 31 98 6d 64 92 77 53 93 c4 cc b0 95 46 70 92 a0 ec 0b 43 ed 7a 06 87 cb 47 0c e3 50 91 7b 0a c3 0c 6e 5c 24 72 5a 78 c4 5f 9f 5f 29 b6 62 68 67 f6 f7 9c e0 54 27 35 47 b3 6d f0 30 bd 24 af 10 d6 32 db a5 4f c4 e8 90 bd 05 86 92 8c 02 06 ca 2e 28 e4 4e 22 7a 2d 50 63 19 59 35 df 38 da 89 36 09 2e ef 01 e8 4c ad 2e 49 d6 2e 47 0a 6c 77 45 f6 25 ec 39 e4 fc 23 32 9c 79 d1 17 28 76 80 7c 36 d7 36 ba 42 bb 69 b0 04 ff 55 f9 38 50 dc 33 c1 f9 8a bb 92 85 83 24 c7 6f f1 eb 08 5d b3 c1 fc 50 f7 4e c0 44 42 e6 22 97 3e a7 07 43 41 87 94 c3 88 14 0b b4 92 d6 29 4a 05 40 e5 a5 9c fa e6 0b a0 f1 48 99 fc a7 13 33 31 5e a0 83 a6 8e 1d 7c 1e 4c dc 2f 56 bc d6 11 96 81 a4 ad bc 1b bf 42 af d8 06 c3 cb d4 2a 07 6f 54 5d ee 4e 11 8d 0b 39 67 54 be 2b 04 2a 68 5d d4 72 7e 89 c0 38 6a 94 d3 cd 6e cb 98 20 e9 d4 9a fe ed 66 c4 7e 6f c2 43 ea be bb cb 0b 02 45 38 77 f5 ac 5d bf bd f8 db 10 52 a3 c9 94 b2 24 cd 9a aa f5 6b 02 6b b9 ef a2 e0 13 02 b3 64 01 ab 64 94 e7 01 8d 6e 5b 57 3b d3 8b ce f0 23 b1 fc 92 94 6b bc a0 20 9c a5 fa 92 6b 49 70 b1 00 91 03 64 5c b1 fc fe 55 23 11 ff 73 05 58 98 43 70 03 8f d2 cc e2 a9 1f c7 4d 6f 3e 3e a9 f8 43 ee d3 56 f6 f8 2d 35 d0 3b c2 4b 81 b5 8c eb 1a 43 ec 94 37 e6 f1 e5 0e b6 f5 55 e3 21 fd 67 c8 33 2e b1 b8 32 aa 8d 79 5a 27 d4 79 c6 e2 7d 5a 61 03 46 83 89 19 03 f6 64 21 d0 94 e1 b0 0a 9a 13 8d 86 1e 6f 78 a2 0a d3 e1 58 00 54 d2 e3 05 25 3c 71 3a 02 fe 1e 28 de ee 73 36 24 6f 6a e3 43 31 80 6b 46 b4 7b 83 3c 39 b9 d3 1c d3 00 c2 a6 ed 83 13 99 77 6d 07 f5 70 ea f0 05 9a 2c 68 a5 f3 ae 16 b6 17 40 4a f7 b7 23 1a 4d 94 27 58 fc 02 0b 3f 23 ee 8c 15 e3 60 44 cf d6 7c d6 40 99 3b 16 20 75 97 fb f3 85 ea 7a 4d 99 e8 d4 56 ff 83 d4 1f 7b 8b 4f 06 9b 02 8a 2a 63 a9 19 a7 0e 3a 10 e3 08 41 58 fa a5 ba fa 30 18 6c 6b 2f 23 8e b5 30 c7 3e""")
        self.server_certificate_verify = bytes.fromhex("""17 03 03 01 19 73 71 9f ce 07 ec 2f 6d 3b ba 02 92 a0 d4 0b 27 70 c0 6a 27 17 99 a5 33 14 f6 f7 7f c9 5c 5f e7 b9 a4 32 9f d9 54 8c 67 0e be ea 2f 2d 5c 35 1d d9 35 6e f2 dc d5 2e b1 37 bd 3a 67 65 22 f8 cd 0f b7 56 07 89 ad 7b 0e 3c ab a2 e3 7e 6b 41 99 c6 79 3b 33 46 ed 46 cf 74 0a 9f a1 fe c4 14 dc 71 5c 41 5c 60 e5 75 70 3c e6 a3 4b 70 b5 19 1a a6 a6 1a 18 fa ff 21 6c 68 7a d8 d1 7e 12 a7 e9 99 15 a6 11 bf c1 a2 be fc 15 e6 e9 4d 78 46 42 e6 82 fd 17 38 2a 34 8c 30 10 56 b9 40 c9 84 72 00 40 8b ec 56 c8 1e a3 d7 21 7a b8 e8 5a 88 71 53 95 89 9c 90 58 7f 72 e8 dd d7 4b 26 d8 ed c1 c7 c8 37 d9 f2 eb bc 26 09 62 21 90 38 b0 56 54 a6 3a 0b 12 99 9b 4a 83 06 a3 dd cc 0e 17 c5 3b a8 f9 c8 03 63 f7 84 13 54 d2 91 b4 ac e0 c0 f3 30 c0 fc d5 aa 9d ee f9 69 ae 8a b2 d9 8d a8 8e bb 6e a8 0a 3a 11 f0 0e a2 96 a3 23 23 67 ff 07 5e 1c 66 dd 9c be dc 47 13""")
        self.handshake_finished = bytes.fromhex("""17 03 03 00 45 10 61 de 27 e5 1c 2c 9f 34 29 11 80 6f 28 2b 71 0c 10 63 2c a5 00 67 55 88 0d bf 70 06 00 2d 0e 84 fe d9 ad f2 7a 43 b5 19 23 03 e4 df 5c 28 5d 58 e3 c7 62 24 07 84 40 c0 74 23 74 74 4a ec f2 8c f3 18 2f d0""")

    def test_should_return_client_hello_message_on_start(self):
        client_hello = self.tls_session.start()
        self.assertEqual(client_hello[5:6], b'\x01')

    # https://datatracker.ietf.org/doc/html/rfc8448#page-7
    # section: {server}  send handshake record
    def test_should_call_transition_on_server_hello_message_received(self):
        with patch.object(TlsFsm, "transition") as mock_transition:
            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
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

    def test_should_store_encrypted_extensions_message_on_encrypted_extensions_message_received(self):
        with patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv:
            mock_handshake_key.return_value = bytes.fromhex("""9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.return_value = bytes.fromhex("""9563bc8b590f671f488d2da3""")

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            expected_encrypted_extensions = bytes.fromhex("""08 00 00 02 00 00 16""")
            self.assertEqual(session.encrypted_extensions.to_bytes(), expected_encrypted_extensions)

    def test_should_store_certificate_message_on_certificate_message_received(self):
        with patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv:
            mock_handshake_key.return_value = bytes.fromhex("""9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
            ]

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            expected_certificate_record = bytes.fromhex("""0b 00 03 2e 00 00 03 2a 00 03 25 30 82 03 21 
            30 82 02 09 a0 03 02 01 02 02 08 15 5a 92 ad c2 04 8f 90 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 30 
            22 31 0b 30 09 06 03 55 04 06 13 02 55 53 31 13 30 11 06 03 55 04 0a 13 0a 45 78 61 6d 70 6c 65 20 43 41 
            30 1e 17 0d 31 38 31 30 30 35 30 31 33 38 31 37 5a 17 0d 31 39 31 30 30 35 30 31 33 38 31 37 5a 30 2b 31 
            0b 30 09 06 03 55 04 06 13 02 55 53 31 1c 30 1a 06 03 55 04 03 13 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 
            65 69 6d 2e 6e 65 74 30 82 01 22 30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82 01 0f 00 30 82 01 0a 
            02 82 01 01 00 c4 80 36 06 ba e7 47 6b 08 94 04 ec a7 b6 91 04 3f f7 92 bc 19 ee fb 7d 74 d7 a8 0d 00 1e 
            7b 4b 3a 4a e6 0f e8 c0 71 fc 73 e7 02 4c 0d bc f4 bd d1 1d 39 6b ba 70 46 4a 13 e9 4a f8 3d f3 e1 09 59 
            54 7b c9 55 fb 41 2d a3 76 52 11 e1 f3 dc 77 6c aa 53 37 6e ca 3a ec be c3 aa b7 3b 31 d5 6c b6 52 9c 80 
            98 bc c9 e0 28 18 e2 0b f7 f8 a0 3a fd 17 04 50 9e ce 79 bd 9f 39 f1 ea 69 ec 47 97 2e 83 0f b5 ca 95 de 
            95 a1 e6 04 22 d5 ee be 52 79 54 a1 e7 bf 8a 86 f6 46 6d 0d 9f 16 95 1a 4c f7 a0 46 92 59 5c 13 52 f2 54 
            9e 5a fb 4e bf d7 7a 37 95 01 44 e4 c0 26 87 4c 65 3e 40 7d 7d 23 07 44 01 f4 84 ff d0 8f 7a 1f a0 52 10 
            d1 f4 f0 d5 ce 79 70 29 32 e2 ca be 70 1f df ad 6b 4b b7 11 01 f4 4b ad 66 6a 11 13 0f e2 ee 82 9e 4d 02 
            9d c9 1c dd 67 16 db b9 06 18 86 ed c1 ba 94 21 02 03 01 00 01 a3 52 30 50 30 0e 06 03 55 1d 0f 01 01 ff 
            04 04 03 02 05 a0 30 1d 06 03 55 1d 25 04 16 30 14 06 08 2b 06 01 05 05 07 03 02 06 08 2b 06 01 05 05 07 
            03 01 30 1f 06 03 55 1d 23 04 18 30 16 80 14 89 4f de 5b cc 69 e2 52 cf 3e a3 00 df b1 97 b8 1d e1 c1 46 
            30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00 03 82 01 01 00 59 16 45 a6 9a 2e 37 79 e4 f6 dd 27 1a ba 1c 
            0b fd 6c d7 55 99 b5 e7 c3 6e 53 3e ff 36 59 08 43 24 c9 e7 a5 04 07 9d 39 e0 d4 29 87 ff e3 eb dd 09 c1 
            cf 1d 91 44 55 87 0b 57 1d d1 9b df 1d 24 f8 bb 9a 11 fe 80 fd 59 2b a0 39 8c de 11 e2 65 1e 61 8c e5 98 
            fa 96 e5 37 2e ef 3d 24 8a fd e1 74 63 eb bf ab b8 e4 d1 ab 50 2a 54 ec 00 64 e9 2f 78 19 66 0d 3f 27 cf 
            20 9e 66 7f ce 5a e2 e4 ac 99 c7 c9 38 18 f8 b2 51 07 22 df ed 97 f3 2e 3e 93 49 d4 c6 6c 9e a6 39 6d 74 
            44 62 a0 6b 42 c6 d5 ba 68 8e ac 3a 01 7b dd fc 8e 2c fc ad 27 cb 69 d3 cc dc a2 80 41 44 65 d3 ae 34 8c 
            e0 f3 4a b2 fb 9c 61 83 71 31 2b 19 10 41 64 1c 23 7f 11 a5 d6 5c 84 4f 04 04 84 99 38 71 2b 95 9e d6 85 
            bc 5c 5d d6 45 ed 19 90 94 73 40 29 26 dc b4 0e 34 69 a1 59 41 e8 e2 cc a8 4b b6 08 46 36 a0 00 00 16""")
            self.assertEqual(session.certificate_message.to_bytes(), expected_certificate_record)

    def test_should_store_certificate_verify_message_on_certificate_verify_message_received(self):
        with patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
                patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex("""9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
            ]
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            expected_certificate_verify_record = bytes.fromhex("""0f 00 01 04 08 04 01 00 5c bb 24 c0 40 93 32 da a9 20 bb ab bd b9 bd 50 17 0b e4 9c fb e0 a4 10 7f ca 6f fb 10 68 e6 5f 96 9e 6d e7 d4 f9 e5 60 38 d6 7c 69 c0 31 40 3a 7a 7c 0b cc 86 83 e6 57 21 a0 c7 2c c6 63 40 19 ad 1d 3a d2 65 a8 12 61 5b a3 63 80 37 20 84 f5 da ec 7e 63 d3 f4 93 3f 27 22 74 19 a6 11 03 46 44 dc db c7 be 3e 74 ff ac 47 3f aa ad de 8c 2f c6 5f 32 65 77 3e 7e 62 de 33 86 1f a7 05 d1 9c 50 6e 89 6c 8d 82 f5 bc f3 5f ec e2 59 b7 15 38 11 5e 9c 8c fb a6 2e 49 bb 84 74 f5 85 87 b1 1b 8a e3 17 c6 33 e9 c7 6c 79 1d 46 62 84 ad 9c 4f f7 35 a6 d2 e9 63 b5 9b bc a4 40 a3 07 09 1a 1b 4e 46 bc c7 a2 f9 fb 2f 1c 89 8e cb 19 91 8b e4 12 1d 7e 8e d0 4c d5 0c 9a 59 e9 87 98 01 07 bb bf 29 9c 23 2e 7f db e1 0a 4c fd ae 5c 89 1c 96 af df f9 4b 54 cc d2 bc 19 d3 cd aa 66 44 85 9c 16""")
            self.assertEqual(session.certificate_verify_message.to_bytes(), expected_certificate_verify_record)

    def test_should_store_handshake_finished_message_on_handshake_finished_message_received(self):
        with patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
                patch("src.tls_session.validate_certificate_verify_signature") as mock_validate_signature, \
                patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex("""9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
                bytes.fromhex("""9563bc8b590f671f488d2da0"""),
                bytes.fromhex("""9563bc8b590f671f488d2da8"""),
            ]
            mock_validate_signature.return_value = True
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            session.on_record_received(self.handshake_finished)
            expected_handshake_finished_message = bytes.fromhex("""14 00 00 30 7e 30 ee cc b6 b2 3b e6 c6 ca 36 39 92 e8 42 da 87 7e e6 47 15 ae 7f c0 cf 87 f9 e5 03 21 82 b5 bb 48 d1 e3 3f 99 79 05 5a 16 0c 8d bb b1 56 9c 16""")
            self.assertEqual(session.server_finished_message.to_bytes(), expected_handshake_finished_message)

    def test_should_call_on_connected_on_handshake_finished_message_received(self):
        with patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
                patch("src.tls_session.validate_certificate_verify_signature") as mock_validate_signature, \
                patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex("""9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
                bytes.fromhex("""9563bc8b590f671f488d2da0"""),
                bytes.fromhex("""9563bc8b590f671f488d2da8"""),
            ]
            mock_validate_signature.return_value = True
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True

            on_connected = Mock()

            session = TlsSession("example.com", on_connected, self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            session.on_record_received(self.handshake_finished)
            on_connected.assert_called_once()

    def test_should_compute_client_application_key_on_handshake_finished(self):
        with patch("src.tls_session.get_X25519_private_key") as mock_private_key, \
            patch("src.tls_session.get_X25519_public_key") as mock_public_key, \
            patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
            patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
            patch.object(TlsSession,"client_hello", new_callable=PropertyMock) as client_hello, \
            patch("src.tls_session.validate_certificate_verify_signature") as mock_validate_signature, \
            patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex(
                """9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
                bytes.fromhex("""9563bc8b590f671f488d2da0"""),
                bytes.fromhex("""9563bc8b590f671f488d2da8"""),
            ]
            mock_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
            mock_public_key.return_value = X25519PublicKey.from_public_bytes(bytes.fromhex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"))
            mock_validate_signature.return_value = True
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True
            client_hello.return_value = ClientHelloMessageBuilder.build_from_bytes(bytes.fromhex("""
                01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
                12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
                75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 35 80 
                72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54"""))

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            session.on_record_received(self.handshake_finished)
            expected_client_application_key = bytes.fromhex("55d5118ace9a005db8b6822330ba1cd4")
            self.assertEqual(session.client_application_key, expected_client_application_key)

    def test_should_compute_client_application_iv_on_handshake_finished(self):
        with patch("src.tls_session.get_X25519_private_key") as mock_private_key, \
                patch("src.tls_session.get_X25519_public_key") as mock_public_key, \
                patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
                patch.object(TlsSession,"client_hello", new_callable=PropertyMock) as client_hello, \
                patch("src.tls_session.validate_certificate_verify_signature") as mock_validate_signature, \
                patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex(
                """9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
                bytes.fromhex("""9563bc8b590f671f488d2da0"""),
                bytes.fromhex("""9563bc8b590f671f488d2da8"""),
            ]
            mock_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
            mock_public_key.return_value = X25519PublicKey.from_public_bytes(bytes.fromhex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"))
            mock_validate_signature.return_value = True
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True
            client_hello.return_value = ClientHelloMessageBuilder.build_from_bytes(bytes.fromhex("""
                01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
                12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
                75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 35 80 
                72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54"""))

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            session.on_record_received(self.handshake_finished)
            expected_client_application_iv = bytes.fromhex("82c7f29670b59d5a096db894")
            self.assertEqual(session.client_application_iv, expected_client_application_iv)

    def test_should_compute_server_application_key_on_handshake_finished(self):
        with patch("src.tls_session.get_X25519_private_key") as mock_private_key, \
                patch("src.tls_session.get_X25519_public_key") as mock_public_key, \
                patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
                patch.object(TlsSession,"client_hello", new_callable=PropertyMock) as client_hello, \
                patch("src.tls_session.validate_certificate_verify_signature") as mock_validate_signature, \
                patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex(
                """9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
                bytes.fromhex("""9563bc8b590f671f488d2da0"""),
                bytes.fromhex("""9563bc8b590f671f488d2da8"""),
            ]
            mock_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
            mock_public_key.return_value = X25519PublicKey.from_public_bytes(bytes.fromhex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"))
            mock_validate_signature.return_value = True
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True
            client_hello.return_value = ClientHelloMessageBuilder.build_from_bytes(bytes.fromhex("""
                01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
                12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
                75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 35 80 
                72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54"""))

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            session.on_record_received(self.handshake_finished)
            expected_server_application_key = bytes.fromhex("c228c7bee3f5ff301f7486fa42602cc3")
            self.assertEqual(session.server_application_key, expected_server_application_key)

    def test_should_compute_server_application_iv_on_handshake_finished(self):
        with patch("src.tls_session.get_X25519_private_key") as mock_private_key, \
                patch("src.tls_session.get_X25519_public_key") as mock_public_key, \
                patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
                patch.object(TlsSession,"client_hello", new_callable=PropertyMock) as client_hello, \
                patch("src.tls_session.validate_certificate_verify_signature") as mock_validate_signature, \
            patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex(
                """9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
                bytes.fromhex("""9563bc8b590f671f488d2da0"""),
                bytes.fromhex("""9563bc8b590f671f488d2da8"""),
            ]
            mock_private_key.return_value = X25519PrivateKey.from_private_bytes(bytes.fromhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"))
            mock_public_key.return_value = X25519PublicKey.from_public_bytes(bytes.fromhex("358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"))
            mock_validate_signature.return_value = True
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True
            client_hello.return_value = ClientHelloMessageBuilder.build_from_bytes(bytes.fromhex("""
                01 00 00 f4 03 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 
                12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 00 08 13 01 00 a3 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 
                75 6c 66 68 65 69 6d 2e 6e 65 74 00 0a 00 16 00 1d 00 0d 00 1e 04 03 00 2b 00 02 03 04 00 33 00 24 00 1d 00 20 35 80 
                72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54"""))

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            session.on_record_received(self.handshake_finished)
            expected_server_application_iv = bytes.fromhex("9b72fb0c52d090669090da80")
            self.assertEqual(session.server_application_iv, expected_server_application_iv)

    def test_should_decrypt_application_record(self):
        with patch.object(TlsSession, "server_application_key", new_callable=PropertyMock) as mock_application_key, \
                patch("src.tls_session.compute_new_nonce") as mock_application_iv, \
                patch.object(TlsFsm, "get_current_state") as mock_tlsfsm:
            mock_application_key.return_value = bytes.fromhex("""01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27""")
            mock_application_iv.return_value = bytes.fromhex("""196a750b0c5049c0cc51a540""")

            mock_tlsfsm.return_value = TlsFsmState.CONNECTED

            on_application_message_callback = Mock()

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), on_application_message_callback)
            session.start()
            session.on_record_received(bytes.fromhex("""17 03 03 00 ea 38 ad fb 1d 01 fd 95 a6 03 85 e8 bb f1 fd 8d cb 46 70 98 97 e7 d6 74 
                c2 f7 37 0e c1 1d 8e 33 eb 4f 4f e7 f5 4b f4 dc 0b 92 fa e7 42 1c 33 c6 45 3c eb c0 73 15 96 10 a0 97 40 ab 2d 
                05 6f 8d 51 cf a2 62 00 7d 40 12 36 da fc 2f 72 92 ff 0c c8 86 a4 ef 38 9f 2c ed 12 26 c6 b4 dc f6 9d 99 4f f9 
                14 8e f9 69 bc 77 d9 43 3a b1 d3 a9 32 54 21 82 82 9f 88 9a d9 5f 04 c7 52 f9 4a ce 57 14 6a 5d 84 b0 42 bf b3 
                48 5a 64 e7 e9 57 b0 89 80 cd 08 ba f9 69 8b 89 29 98 6d 11 74 d4 aa 6d d7 a7 e8 c0 86 05 2c 3c 76 d8 19 34 bd 
                f5 9b 96 6e 39 20 31 f3 47 1a de bd dd db e8 4f cf 1f f4 08 84 6a e9 b2 8c a4 a9 e7 28 84 4a 49 3d 80 45 5d 6e 
                af f2 05 b4 0a 1e f1 85 74 ef c0 b9 6a d3 83 af bd 8d fc 86 f8 08 7c 1f 7d c8"""))
            expected_application_message = bytes.fromhex("""17 03 03 00 ea 04 00 00 d5 00 00 1c 20 00 00 00 00 08 00 00 
                00 00 00 00 00 01 00 c0 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 00 49 56 44 41 54 41 49 56 44 41 54 41 
                00 41 45 53 cb 11 9d 4d bd 2a 21 ec c2 26 a6 09 0e e8 ca 58 df 09 03 9b 35 96 f4 de 79 98 0e a3 25 d5 14 62 
                5c 0c 21 c5 0f 03 26 1d c4 2c e7 c5 97 0c 4c 01 16 06 fb 99 8a 86 c3 fa 30 e5 5e ea 91 f1 ff f3 18 fc 7b d5 
                88 31 bf 49 c8 8d 7b 59 05 91 a6 5c 7d e8 cf c6 77 46 8a 54 fd be c0 d8 53 be 20 21 c8 bb fc db e5 1f 5d 9a 
                0c 70 85 84 1a 01 e4 95 85 f6 8b 4a fe e1 d7 07 e2 cb b1 a0 b4 23 aa 7e 32 d5 60 7b d9 9d d4 db 3c 9a aa ed 
                43 d3 5d 26 b4 b1 c6 84 71 71 ea a0 7a 9b c8 cb f7 58 49 9a 00 00 16""")
            on_application_message_callback.assert_called_with(expected_application_message)

    def test_should_decrypt_application_record_ping(self):
        with patch.object(TlsSession, "server_application_key", new_callable=PropertyMock) as mock_application_key, \
                patch("src.tls_session.compute_new_nonce") as mock_application_iv, \
                patch.object(TlsFsm, "get_current_state") as mock_tlsfsm:
            mock_application_key.return_value = bytes.fromhex("""01f78623f17e3edcc09e944027ba3218d57c8e0db93cd3ac419309274700ac27""")
            mock_application_iv.return_value = bytes.fromhex("""196a750b0c5049c0cc51a543""")

            mock_tlsfsm.return_value = TlsFsmState.CONNECTED

            on_application_message_callback = Mock()

            session = TlsSession("example.com", Mock(), self.root_certificate_path, Mock(), on_application_message_callback)
            session.start()
            session.on_record_received(bytes.fromhex("""17 03 03 00 15 0c da 85 f1 44 7a e2 3f a6 6d 56 f4 c5 40 84 82 
                b1 b1 d4 c9 98"""))
            expected_application_message = bytes.fromhex("""17 03 03 00 15 70 6f 6e 67 17""")
            on_application_message_callback.assert_called_with(expected_application_message)

    def test_should_call_on_data_to_send_on_handshake_finished_message_received(self):
        with patch.object(TlsSession, "server_handshake_key", new_callable=PropertyMock) as mock_handshake_key, \
                patch("src.tls_session.compute_new_nonce") as mock_handshake_iv, \
                patch("src.tls_session.validate_certificate_verify_signature") as mock_validate_signature, \
                patch.object(TlsSession, "server_certificate", new_callable=PropertyMock) as mock_validate_certificate_issued_by:
            mock_handshake_key.return_value = bytes.fromhex("""9f13575ce3f8cfc1df64a77ceaffe89700b492ad31b4fab01c4792be1b266b7f""")
            mock_handshake_iv.side_effect = [
                bytes.fromhex("""9563bc8b590f671f488d2da3"""),
                bytes.fromhex("""9563bc8b590f671f488d2da2"""),
                bytes.fromhex("""9563bc8b590f671f488d2da1"""),
                bytes.fromhex("""9563bc8b590f671f488d2da0"""),
                bytes.fromhex("""9563bc8b590f671f488d2da8"""),
            ]
            mock_validate_signature.return_value = True
            mock_validate_certificate_issued_by.verify_directly_issued_by.return_value = True

            on_data_to_send = Mock()

            session = TlsSession("example.com", Mock(), self.root_certificate_path, on_data_to_send, Mock())
            session.start()
            session.on_record_received(self.server_hello)
            session.on_record_received(self.encrypted_extensions)
            session.on_record_received(self.server_certificate)
            session.on_record_received(self.server_certificate_verify)
            session.on_record_received(self.handshake_finished)
            on_data_to_send.assert_called_once()
