import unittest

from src.tls_crypto import get_X25519_private_key
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

class TestTLSCrypto(unittest.TestCase):
    def test_should_return_x25519_private_key(self):
        private_key = get_X25519_private_key()
        self.assertTrue(isinstance(private_key, X25519PrivateKey))