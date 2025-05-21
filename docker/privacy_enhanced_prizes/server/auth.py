from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import jwt
import time
import base64
import logging
import os
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

from server.utils import derive_shared_key
import server.config as g

router = APIRouter()
SECRET_KEY = "superseguro"

users = {}        # username -> password
sessions = {}     # username -> JWT
dh_sessions = {}  # username -> derived key

# --- Models ---
class RegisterEncryptedData(BaseModel):
    username: str
    encrypted_password: str
    nonce: str

class LoginData(BaseModel):
    username: str
    password: str

class DHExchange(BaseModel):
    username: str
    client_pub_key: str  # public key as string

# --- JWT ---
def create_jwt(username: str):
    payload = {
        "sub": username,
        "exp": time.time() + 3600
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Standard DH implementation
# NIST parameters (1024 bits)
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2

# --- DH Handshake (Standard DH version) ---
@router.get("/dh/params")
def dh_params():
    """Return the standard DH parameters"""
    return {
        "p": base64.b64encode(P.to_bytes((P.bit_length() + 7) // 8, byteorder="big")).decode('utf-8'),
        "g": G
    }

@router.get("/dh/start")
def dh_start():
    """Start DH key exchange by generating server DH private key"""
    # Generate a random private key
    server_private_key = secrets.randbelow(P-2) + 2  # Range [2, P-1]
    
    # Calculate public key: g^private_key mod p
    server_public_key = pow(G, server_private_key, P)
    
    # Store for later use
    g.server_private_key = server_private_key
    g.server_public_key = server_public_key
    
    # Convert public key to base64 string for transmission
    server_public_key_bytes = server_public_key.to_bytes((server_public_key.bit_length() + 7) // 8, byteorder="big")
    server_public_key_b64 = base64.b64encode(server_public_key_bytes).decode('utf-8')
    
    # Format like PEM for compatibility with the client expectation
    server_public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{server_public_key_b64}\n-----END PUBLIC KEY-----"
    
    return {
        "server_pub_key": server_public_key_pem,
    }

@router.post("/dh/finish")
def dh_finish(data: DHExchange):
    logging.debug(f"[DH] Received DH finish data for username: {data.username}")
    try:
        # Extract the client's public key value from PEM format
        client_pub_key_pem = data.client_pub_key
        client_pub_key_b64 = client_pub_key_pem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
        client_pub_key_bytes = base64.b64decode(client_pub_key_b64)
        client_public_key = int.from_bytes(client_pub_key_bytes, byteorder="big")
        
        # Get server's private key
        server_private_key = g.server_private_key
        
        # Compute the shared secret: (client_pub_key^server_private_key) mod p
        shared_secret = pow(client_public_key, server_private_key, P)
        
        # Convert to bytes for key derivation
        shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
        
        # Use the shared secret as the AES key (we're taking first 32 bytes if longer)
        derived_key = hashlib.sha256(shared_secret_bytes).digest()
        
        # Store the derived key for this username
        dh_sessions[data.username] = derived_key
        
        logging.debug(f"[DH] Established secure key for {data.username}")
        return {"message": "DH key established"}
    except Exception as e:
        logging.error(f"[DH] Exchange failed for {data.username}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"DH error: {str(e)}")

# --- Registo ---
@router.post("/register")
def register(data: RegisterEncryptedData):
    logging.debug(f"Attempting to register user: {data.username}")

    if not data.username or not data.encrypted_password or not data.nonce:
        raise HTTPException(status_code=400, detail="Missing fields")

    if data.username in users:
        raise HTTPException(status_code=400, detail="User already exists")

    derived_key = dh_sessions.get(data.username)
    if not derived_key:
        raise HTTPException(status_code=400, detail="Missing DH session")

    try:
        logging.debug(f"Attempting to decrypt password for user: {data.username}")

        aesgcm = AESGCM(derived_key)
        nonce_bytes = base64.b64decode(data.nonce)
        encrypted_bytes = base64.b64decode(data.encrypted_password)
        decrypted_password = aesgcm.decrypt(nonce_bytes, encrypted_bytes, None).decode()

        # Log the decrypted password (in real-world applications, avoid logging sensitive information)
        logging.debug(f"Decrypted password for {data.username}: {decrypted_password}")

        # Hash the password with a salt
        import os, hashlib
        salt = os.urandom(16)
        hashed_password = hashlib.pbkdf2_hmac('sha256', decrypted_password.encode(), salt, 100_000)
        users[data.username] = (hashed_password, salt)
        logging.debug(f"Stored hashed password and salt for {data.username}")

    except Exception as e:
        logging.error(f"Decryption failed for {data.username}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    logging.debug(f"User {data.username} successfully registered")
    return {"message": "User registered successfully"}

# --- Login ---
@router.post("/login")
def login(data: LoginData):
    logging.debug(f"Attempting to login with username: {data.username}")

    # Get stored hash and salt
    user_entry = users.get(data.username)
    logging.debug(f"User entry for {data.username}: {user_entry}")
    if not user_entry:
        logging.error(f"User {data.username} not found")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    hashed_password, salt = user_entry
    logging.debug(f"Stored hashed password for {data.username}: {hashed_password}")

    # For login, we simply hash the provided password with the stored salt
    import hashlib
    hashed_attempt = hashlib.pbkdf2_hmac('sha256', data.password.encode(), salt, 100_000)
    
    if hashed_attempt == hashed_password:
        token = create_jwt(data.username)
        sessions[data.username] = token
        logging.debug(f"Login successful for {data.username}")
        return {"token": token}

    logging.error(f"Invalid credentials for {data.username}")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.get("/active_sessions")
def active_sessions():
    active_count = len(sessions)
    logging.debug(f"Currently active sessions: {active_count}")
    return {"active_sessions": active_count}

@router.get("/logout")
def logout(token: str = None, request: Request = None):
    # Try to get token from query or Authorization header
    logging.debug(f"Attempting to logout with token: {token}")
    if not token and request:
        auth = request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth[7:]
    if not token:
        logging.error("No token provided for logout")
        raise HTTPException(status_code=401, detail="No token provided")
    for username, user_token in list(sessions.items()):
        if user_token == token:
            del sessions[username]
            logging.debug(f"User {username} logged out successfully")
            return {"message": "Logged out successfully"}
    logging.error("Invalid token")
    raise HTTPException(status_code=401, detail="Invalid token")

@router.get("/get-users")
def get_users():
    users_dict = {
        username: {
            "hashed_password": base64.b64encode(hashed_password).decode(),
            "salt": base64.b64encode(salt).decode()
        }
        for username, (hashed_password, salt) in users.items()
    }
    logging.debug(f"Current users-passwords: {users_dict}")
    return {"users": users_dict}
