import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes

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

def get_empty_hash_256():
    return hashlib.sha256().digest()

def hkdf_expand_label(secret, label, context, length):
    """
    Perform HKDF-Expand-Label as defined in TLS 1.3.

    https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
    """

    # Construct the HkdfLabel structure
    label_prefix = b"tls13 "
    full_label = label_prefix + label
    hkdf_label = (
            length.to_bytes(2, "big") +  # Length of output (2 bytes)
            len(full_label).to_bytes(1, "big") +  # Length of the label (1 byte)
            full_label +  # Label
            len(context).to_bytes(1, "big") +  # Length of Context (1 byte)
            context  # Context
    )

    # Perform HKDF-Expand
    hkdf_expand = HKDFExpand(algorithm=hashes.SHA256(), length=length, info=hkdf_label)

    return hkdf_expand.derive(secret)