import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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

def get_hash_sha256(data):
    return hashlib.sha256(data).digest()

def get_records_hash_sha256(*records):
    data = b''.join([record for record in records])
    return get_hash_sha256(data)

def get_hmac_sha256(message, secret_key):
    return hmac.new(secret_key, message, hashlib.sha256).digest()

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

def get_derived_secret(key):
    """
    Calculates the derived secret by performing HKDF-Expand-Label

    :param key: either the early secret or the handshake secret
    :return: derived_secret
    """
    label = b'derived'
    return hkdf_expand_label(key, label, get_empty_hash_256(), 32)

def get_handshake_secret(shared_secret, derived_secret):
    """
    Calculates the handshake secret performing HKDF-Extract.

    :param shared_secret: calculated by performing key exchange from private key of the client with public key of the
     server (or vice versa)
    :param derived_secret: derived secret obtained from the early secret
    :return: handshake_secret
    """
    return hkdf_extract(shared_secret, derived_secret)

def get_shared_secret(private_key: X25519PrivateKey, public_key: X25519PublicKey):
    return private_key.exchange(public_key)

def get_client_secret_handshake(handshake_secret, hello_hash):
    label = b'c hs traffic'
    return hkdf_expand_label(handshake_secret, label, hello_hash, 32)

def get_server_secret_handshake(handshake_secret, hello_hash):
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

def get_client_handshake_iv(client_secret):
    label = b'iv'
    ctx = b''
    return hkdf_expand_label(client_secret, label, ctx, 12)

def get_server_handshake_iv(server_secret):
    label = b'iv'
    ctx = b''
    return hkdf_expand_label(server_secret, label, ctx, 12)

def get_finished_secret(secret):
    """
    Returns the finished secret (finished key)

    :param secret: server_secret or client_secret
    :return: the finished secret (finished key)
    """
    label = b'finished'
    ctx = b''
    return hkdf_expand_label(secret, label, ctx, 32)

def get_master_secret(derived_secret):
    """
    Calculates the master secret by performing HKDF-Extract

    :param derived_secret: derived secret obtained from the handshake secret
    :return: master_secret
    """
    return hkdf_extract(get_32_zero_bytes(), derived_secret)

def get_client_secret_application(master_secret, handshake_hash):
    label = b'c ap traffic'
    return hkdf_expand_label(master_secret, label, handshake_hash, 32)

def get_server_secret_application(master_secret, handshake_hash):
    label = b's ap traffic'
    return hkdf_expand_label(master_secret, label, handshake_hash, 32)

def get_client_application_key(client_secret):
    """

    :param client_secret: the client secret (application) obtained from the master secret
    :return: client_application_key
    """
    label = b'key'
    ctx = b''
    return hkdf_expand_label(client_secret, label, ctx, 16)

def get_server_application_key(server_secret):
    """

    :param server_secret: the server secret (application) obtained from the master secret
    :return: server_application_key
    """
    label = b'key'
    ctx = b''
    return hkdf_expand_label(server_secret, label, ctx, 16)

def get_client_application_iv(client_secret):
    """

    :param client_secret: the client secret (application) obtained from the master secret
    :return: client_application_iv
    """
    label = b'iv'
    ctx = b''
    return hkdf_expand_label(client_secret, label, ctx, 12)

def get_server_application_iv(server_secret):
    """

    :param server_secret: the server secret (application) obtained from the master secret
    :return: server_application_iv
    """
    label = b'iv'
    ctx = b''
    return hkdf_expand_label(server_secret, label, ctx, 12)

def encrypt(key, nonce, data, aad):
    """
    Encrypts the data.

    :param key: handshake or application key
    :param nonce: handshake iv or application iv
    :param data: data to encrypt
    :param aad: Additional Authenticated Data.
    AAD = ContentType || Version || Length.
    These values are referred to the record header for the message to encrypt.
    NOTE: to the **Length** of the message you need to add 16, that is the number of bytes of
    the Auth Tag that will be appended to the message
    :return: encrypted data with the Auth Tag
    """

    return AESGCM(key).encrypt(nonce, data, aad)

def decrypt(key, nonce, data, aad):
    """
    Decrypts the data.

    :param key: handshake or application key
    :param nonce: handshake iv or application iv
    :param data: data to decrypt
    :param aad: first 5 bytes of the message (record header)
    :return: decrypted data
    """
    return AESGCM(key).decrypt(nonce, data, aad)

def compute_new_nonce(iv, seq):
    """
    Modifies the `iv` by XORing it with the `seq` value.

    :param iv: A bytearray representing the IV (Initialization Vector).
    :param seq: A 64-bit integer sequence value.
    """
    gcm_ivlen = 12
    iv_array = bytearray(iv)
    for i in range(8):
        iv_array[gcm_ivlen - 1 - i] ^= (seq >> (i * 8)) & 0xFF

    return bytes(iv_array)

def get_certificate_verify_signature(handshake_hash, private_key_path):
    context_string = b'TLS 1.3, server CertificateVerify'

    # 64 bytes of 0x20 (space)
    prefix = b"\x20" * 64

    data_to_sign = prefix + context_string + b"\x00" + handshake_hash

    # Load the RSA private key from the PEM file
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

        signature = private_key.sign(
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        return signature

def validate_certificate_verify_signature(handshake_hash, public_key, signature):
    context_string = b'TLS 1.3, server CertificateVerify'

    # 64 bytes of 0x20 (space)
    prefix = b"\x20" * 64

    data_to_sign = prefix + context_string + b"\x00" + handshake_hash

    try:
        public_key.verify(
            signature,
            data_to_sign,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except:
        return False
