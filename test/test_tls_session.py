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
        self.server_certificate = bytes.fromhex("""17 03 03 03 43 0b 00 01 b9 00 00 01 b5 00 01 b0 30 82
         01 ac 30 82 01 15 a0 03 02 01 02 02 01 02 30 0d 06 09 2a 86 48
         86 f7 0d 01 01 0b 05 00 30 0e 31 0c 30 0a 06 03 55 04 03 13 03
         72 73 61 30 1e 17 0d 31 36 30 37 33 30 30 31 32 33 35 39 5a 17
         0d 32 36 30 37 33 30 30 31 32 33 35 39 5a 30 0e 31 0c 30 0a 06
         03 55 04 03 13 03 72 73 61 30 81 9f 30 0d 06 09 2a 86 48 86 f7
         0d 01 01 01 05 00 03 81 8d 00 30 81 89 02 81 81 00 b4 bb 49 8f
         82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26
         d3 90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c
         1a f1 9e aa 6a f9 8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52
         4b 1b 01 8c 3e 0b 63 26 4d 44 9a 6d 38 e2 2a 5f da 43 08 46 74
         80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1 d0 3e 2b d1 93
         ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f 02 03
         01 00 01 a3 1a 30 18 30 09 06 03 55 1d 13 04 02 30 00 30 0b 06
         03 55 1d 0f 04 04 03 02 05 a0 30 0d 06 09 2a 86 48 86 f7 0d 01
         01 0b 05 00 03 81 81 00 85 aa d2 a0 e5 b9 27 6b 90 8c 65 f7 3a
         72 67 17 06 18 a5 4c 5f 8a 7b 33 7d 2d f7 a5 94 36 54 17 f2 ea
         e8 f8 a5 8c 8f 81 72 f9 31 9c f3 6b 7f d6 c5 5b 80 f2 1a 03 01
         51 56 72 60 96 fd 33 5e 5e 67 f2 db f1 02 70 2e 60 8c ca e6 be
         c1 fc 63 a4 2a 99 be 5c 3e b7 10 7c 3c 54 e9 b9 eb 2b d5 20 3b
         1c 3b 84 e0 a8 b2 f7 59 40 9b a3 ea c9 d9 1d 40 2d cc 0c c8 f8
         96 12 29 ac 91 87 b4 2b 4d e1 00 00""")
        self.server_certificate_verify = bytes.fromhex("""17 03 03 01 19 0f 00 00 84 08 04 00 80 5a 74 7c
         5d 88 fa 9b d2 e5 5a b0 85 a6 10 15 b7 21 1f 82 4c d4 84 14 5a
         b3 ff 52 f1 fd a8 47 7b 0b 7a bc 90 db 78 e2 d3 3a 5c 14 1a 07
         86 53 fa 6b ef 78 0c 5e a2 48 ee aa a7 85 c4 f3 94 ca b6 d3 0b
         be 8d 48 59 ee 51 1f 60 29 57 b1 54 11 ac 02 76 71 45 9e 46 44
         5c 9e a5 8c 18 1e 81 8e 95 b8 c3 fb 0b f3 27 84 09 d3 be 15 2a
         3d a5 04 3e 06 3d da 65 cd f5 ae a2 0d 53 df ac d4 2f 74 f3""")

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
            session.on_record_received(self.server_certificate)
            mock_transition.assert_called_with(TlsFsmEvent.CERTIFICATE_RECEIVED, self.server_certificate)

    def test_should_store_certificate_verify_message_on_certificate_verify_message_received(self):
        self.tls_session.start()
        self.tls_session.on_record_received(self.server_hello)
        self.tls_session.on_record_received(self.server_certificate)
        self.tls_session.on_record_received(self.server_certificate_verify)
        self.assertEqual(self.tls_session.certificate_verify_message.to_bytes(), self.server_certificate_verify)

