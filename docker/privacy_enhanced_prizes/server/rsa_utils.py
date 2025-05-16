from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_rsa_keys(key_size=2048):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, message: bytes):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(private_key, ciphertext: bytes):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_encrypt_raw(public_key, message: bytes):
    # Raw RSA encryption: c = m^e mod n
    numbers = public_key.public_numbers()
    n = numbers.n
    e = numbers.e
    m = int.from_bytes(message, byteorder='big')
    c = pow(m, e, n)
    k = (n.bit_length() + 7) // 8
    return c.to_bytes(k, byteorder='big')
