# server/utils.py
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import base64

def generate_dh_keys():
    dh_parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = dh_parameters.generate_private_key()
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_b64 = base64.b64encode(public_key_bytes).decode()
    return dh_parameters, private_key, public_key, pub_b64

def derive_shared_key(private_key, client_public_key):
    shared_key = private_key.exchange(client_public_key)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)
    return derived_key

# Remove RSA methods from here; now in rsa_utils.py