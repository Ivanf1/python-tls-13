import unittest

from src.tls_crypto import get_X25519_private_key, get_32_random_bytes, get_32_zero_bytes, hkdf_extract, \
    get_early_secret, get_empty_hash_256, hkdf_expand_label
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