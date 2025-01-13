import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
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

def get_empty_hash_256():
    return hashlib.sha256().digest()

def hkdf_extract(input_keying_material, salt):
    """
    Perform HKDF-Extract.

    :param input_keying_material: Input keying material (bytes)
    :param salt: Optional salt (bytes). If not provided, a string of zeroes the same length as the hash output will be used.
    :return: A pseudorandom key (PRK).
    """

    hash_alg = hashlib.sha256
    return hmac.new(salt, input_keying_material, hash_alg).digest()

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

def get_early_secret():
    """
    Calculates the early secret performing HKDF-Extract.
    early_secret = HKDF-Extract(salt: 00, key: 00...)

    :return: early_secret
    """
    ikm = get_32_zero_bytes()
    salt = get_32_zero_bytes()
    return hkdf_extract(ikm, salt)

def get_derived_secret():
    label = b'derived'
    return hkdf_expand_label(get_early_secret(), label, get_empty_hash_256(), 32)

def get_handshake_secret(shared_secret):
    """
    Calculates the handshake secret performing HKDF-Extract.

    :param shared_secret: calculated by performing key exchange from private key of the client with public key of the
     server (or vice versa)
    :return: handshake_secret
    """
    return hkdf_extract(shared_secret, get_derived_secret())

def get_shared_secret(private_key: X25519PrivateKey, public_key: X25519PublicKey):
    return private_key.exchange(public_key)

def get_client_secret(handshake_secret, hello_hash):
    label = b'c hs traffic'
    return hkdf_expand_label(handshake_secret, label, hello_hash, 32)

def get_server_secret(handshake_secret, hello_hash):
    label = b's hs traffic'
    return hkdf_expand_label(handshake_secret, label, hello_hash, 32)

def get_client_handshake_key(client_secret):
    label = b'key'
    ctx = b''
    return hkdf_expand_label(client_secret, label, ctx, 16)

def get_server_handshake_key(server_secret):
    label = b'key'
    ctx = b''
    return hkdf_expand_label(server_secret, label, ctx, 16)
