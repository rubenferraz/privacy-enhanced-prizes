from fastapi import APIRouter
import server.config as g
from cryptography.hazmat.primitives import serialization

router = APIRouter()

@router.get("/rsa/public")
def get_rsa_public_key():
    """Return the server's RSA public key in PEM format."""
    public_key = g.rsa_public_key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return {"rsa_public_key": pem}
