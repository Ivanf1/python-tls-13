import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def get_X25519_private_key():
    return X25519PrivateKey.generate()

def get_X25519_public_key(private_key: X25519PrivateKey):
    return private_key.public_key()

def get_32_random_bytes():
    return secrets.token_bytes(32)