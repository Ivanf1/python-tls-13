from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

def get_X25519_private_key():
    return X25519PrivateKey.generate()