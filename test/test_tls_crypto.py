import binascii
import unittest

from src.tls_crypto import get_X25519_private_key, get_32_random_bytes, get_32_zero_bytes, hkdf_extract, \
    get_early_secret, get_empty_hash_256, hkdf_expand_label, get_derived_secret, get_handshake_secret, \
    get_shared_secret, get_client_secret_handshake, get_server_secret_handshake, get_client_handshake_key, \
    get_server_handshake_key, \
    get_client_handshake_iv, get_server_handshake_iv, get_master_secret, get_client_secret_application, \
    get_server_secret_application, get_client_application_key, get_server_application_key
from src.tls_crypto import get_X25519_public_key

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

class TestTLSCrypto(unittest.TestCase):
    def test_should_return_x25519_private_key(self):
        private_key = get_X25519_private_key()
        self.assertTrue(isinstance(private_key, X25519PrivateKey))

    def test_should_return_x25519_public_key(self):
        private_key = get_X25519_private_key()
        public_key = get_X25519_public_key(private_key)
        self.assertTrue(isinstance(public_key, X25519PublicKey))

    def test_should_return_32_random_bytes(self):
        random_bytes = get_32_random_bytes()
        self.assertIs(len(random_bytes), 32)

    def test_should_return_32_zero_bytes(self):
        zero_bytes = get_32_zero_bytes()
        expected_zero_bytes = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        self.assertEqual(zero_bytes, expected_zero_bytes)

    def test_should_perform_hkdf_extract(self):
        ikm = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        salt = bytes.fromhex("00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00")
        hkdf_extract_result = hkdf_extract(ikm, salt)
        expected_hkdf_extract_result = bytes.fromhex("""33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
         e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a""")
        self.assertEqual(hkdf_extract_result, expected_hkdf_extract_result)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-4
    # section: {server}  extract secret "early"
    def test_should_return_early_secret(self):
        early_secret = get_early_secret()
        expected_early_secret = bytes.fromhex("""33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
         e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a""")
        self.assertEqual(early_secret, expected_early_secret)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-5
    # section: {server}  derive secret for handshake "tls13 derived"
    def test_should_return_empty_hash(self):
        empty_hash = get_empty_hash_256()
        expected_empty_hash = bytes.fromhex("""e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
         27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55""")
        self.assertEqual(empty_hash, expected_empty_hash)

    def test_should_perform_hkdf_expand_label(self):
        secret = bytes.fromhex("""33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
         e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a""")
        label = b'derived'
        context = bytes.fromhex("""e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24
         27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55""")

        expanded_label = hkdf_expand_label(secret, label, context, 32)
        expected_expanded_label = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")

        self.assertEqual(expanded_label, expected_expanded_label)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-5
    # section: {server}  derive secret for handshake "tls13 derived"
    def test_should_return_derived_secret(self):
        early_secret = bytes.fromhex("""33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c
         e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a""")
        derived_secret = get_derived_secret(early_secret)
        expected_derived_secret = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")
        self.assertEqual(derived_secret, expected_derived_secret)

    # https://datatracker.ietf.org/doc/html/rfc8448#page-5
    # section: {server}  extract secret "handshake"
    def test_should_return_handshake_secret(self):
        derived_secret = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")
        shared_secret = bytes.fromhex("""8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d""")
        handshake_secret = get_handshake_secret(shared_secret, derived_secret)
        expected_handshake_secret = bytes.fromhex("""1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
         01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac""")
        self.assertEqual(handshake_secret, expected_handshake_secret)

    def test_should_return_handshake_secret_using_defined_keys(self):
        shared_secret = bytes.fromhex("""8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d""")
        derived_secret = bytes.fromhex("""6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba
         b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba""")
        handshake_secret = get_handshake_secret(shared_secret, derived_secret)
        expected_handshake_secret = bytes.fromhex("""1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
         01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac""")
        self.assertEqual(handshake_secret, expected_handshake_secret)

    def test_should_return_shared_secret(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-3
        # section: {client}  create an ephemeral x25519 key pair
        private_key = X25519PrivateKey.from_private_bytes(bytes.fromhex("""49 af 42 ba 7f 79 94 85 2d 71 3e f2 78
         4b cb ca a7 91 1d e2 6a dc 56 42 cb 63 45 40 e7 ea 50 05"""))

        # https://datatracker.ietf.org/doc/html/rfc8448#page-5
        # section: {server}  create an ephemeral x25519 key pair
        public_key = X25519PublicKey.from_public_bytes(bytes.fromhex("""c9 82 88 76 11 20 95 fe 66 76 2b db f7 c6
         72 e1 56 d6 cc 25 3b 83 3d f1 dd 69 b1 b0 4e 75 1f 0f"""))

        # https://datatracker.ietf.org/doc/html/rfc8448#page-5
        # section: {server}  extract secret "handshake"
        shared_secret = get_shared_secret(private_key, public_key)
        expected_shared_secret = bytes.fromhex("""8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d
         35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d""")
        self.assertEqual(shared_secret, expected_shared_secret)

    def test_should_return_client_secret(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-5
        # section: {server}  derive secret "tls13 c hs traffic"
        handshake_secret = bytes.fromhex("""1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
         01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac""")
        hello_hash = bytes.fromhex("""86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
         d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8""")
        client_secret = get_client_secret_handshake(handshake_secret, hello_hash)
        expected_client_secret = bytes.fromhex("""b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
         2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21""")
        self.assertEqual(client_secret, expected_client_secret)

    def test_should_return_server_secret(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-6
        # section: {server}  derive secret "tls13 s hs traffic"
        handshake_secret = bytes.fromhex("""1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
         01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac""")
        hello_hash = bytes.fromhex("""86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed
         d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8""")
        server_secret = get_server_secret_handshake(handshake_secret, hello_hash)
        expected_server_secret = bytes.fromhex("""b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
         37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38""")
        self.assertEqual(server_secret, expected_server_secret)

    def test_should_return_client_handshake_key(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-11
        # section: {server}  derive read traffic keys for handshake data
        client_secret = bytes.fromhex("""b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
         2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21""")
        client_handshake_key = get_client_handshake_key(client_secret)
        expected_client_handshake_key = bytes.fromhex("""db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50
         25 8d 01""")
        self.assertEqual(client_handshake_key, expected_client_handshake_key)

    def test_should_return_server_handshake_key(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-7
        # section: {server}  derive write traffic keys for handshake data
        server_secret = bytes.fromhex("""b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
         37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38""")
        server_handshake_key = get_server_handshake_key(server_secret)
        expected_server_handshake_key = bytes.fromhex("""3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e
         e4 03 bc""")
        self.assertEqual(server_handshake_key, expected_server_handshake_key)

    def test_should_return_client_handshake_iv(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-11
        # section: {server}  derive read traffic keys for handshake data
        client_secret = bytes.fromhex("""b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e
         2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21""")
        client_handshake_iv = get_client_handshake_iv(client_secret)
        expected_client_handshake_iv = bytes.fromhex("""5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f""")
        self.assertEqual(client_handshake_iv, expected_client_handshake_iv)

    def test_should_return_server_handshake_iv(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-7
        # section: {server}  derive write traffic keys for handshake data
        server_secret = bytes.fromhex("""b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d
         37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38""")
        server_handshake_iv = get_server_handshake_iv(server_secret)
        expected_server_handshake_iv = bytes.fromhex("""5d 31 3e b2 67 12 76 ee 13 00 0b 30""")
        self.assertEqual(server_handshake_iv, expected_server_handshake_iv)

    def test_should_return_derived_secret_from_handshake_secret(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-7
        # section: {server}  extract secret "master"
        handshake_secret = bytes.fromhex("""1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b
         01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac""")
        derived_secret = get_derived_secret(handshake_secret)
        expected_derived_secret = bytes.fromhex("""43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5
         31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4""")
        self.assertEqual(derived_secret, expected_derived_secret)

    def test_should_return_master_secret(self):
        derived_secret = bytes.fromhex("""43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5
         31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4""")
        master_secret = get_master_secret(derived_secret)
        expected_master_secret = bytes.fromhex("""18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
         47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19""")
        self.assertEqual(master_secret, expected_master_secret)

    def test_should_return_client_secret_application(self):
        master_secret = bytes.fromhex("""18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
         47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19""")
        handshake_hash = bytes.fromhex("""96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
         00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13""")
        client_secret_application = get_client_secret_application(master_secret, handshake_hash)
        expected_client_secret_application = bytes.fromhex("""9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce
         65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5""")
        self.assertEqual(client_secret_application, expected_client_secret_application)

    def test_should_return_server_secret_application(self):
        master_secret = bytes.fromhex("""18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a
         47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19""")
        handshake_hash = bytes.fromhex("""96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a
         00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13""")
        server_secret_application = get_server_secret_application(master_secret, handshake_hash)
        expected_server_secret_application = bytes.fromhex("""a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9
         50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43""")
        self.assertEqual(server_secret_application, expected_server_secret_application)

    def test_should_return_client_application_key(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-13
        # section: {client}  derive write traffic keys for application data
        client_secret = bytes.fromhex("""9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce
         65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5""")
        client_application_key = get_client_application_key(client_secret)
        expected_client_application_key = bytes.fromhex("""17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6
         3f 50 51""")
        self.assertEqual(client_application_key, expected_client_application_key)

    def test_should_return_server_application_key(self):
        # https://datatracker.ietf.org/doc/html/rfc8448#page-11
        # section: {server}  derive write traffic keys for application data
        server_secret = bytes.fromhex("""a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9
         50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43""")
        server_application_key = get_server_application_key(server_secret)
        expected_server_application_key = bytes.fromhex("""9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac
         92 e3 56""")
        self.assertEqual(server_application_key, expected_server_application_key)

