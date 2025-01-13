import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def get_X25519_private_key():
    return X25519PrivateKey.generate()

def get_X25519_public_key(private_key: X25519PrivateKey):
    return private_key.public_key()

def get_32_random_bytes():
    return secrets.token_bytes(32)

def get_32_zero_bytes():
    return b"\x00" * 32

def hkdf_extract(input_keying_material, salt):
    """
    Perform HKDF-Extract.

    :param input_keying_material: Input keying material (bytes)
    :param salt: Optional salt (bytes). If not provided, a string of zeroes the same length as the hash output will be used.
    :return: A pseudorandom key (PRK).
    """

    hash_alg = hashlib.sha256
    return hmac.new(salt, input_keying_material, hash_alg).digest()

def get_early_secret():
    """
    Calculates the early secret performing HKDF-Extract.
    early_secret = HKDF-Extract(salt: 00, key: 00...)

    :return: early_secret
    """
    ikm = get_32_zero_bytes()
    salt = get_32_zero_bytes()
    return hkdf_extract(ikm, salt)