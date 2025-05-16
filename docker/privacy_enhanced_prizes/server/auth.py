from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import jwt
import time
import base64
import logging

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
    client_pub_key: str  # base64 PEM format
    
# --- JWT ---
def create_jwt(username: str):
    payload = {
        "sub": username,
        "exp": time.time() + 3600
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Toy DH parameters (small, insecure, for demo only)
DH_P = 23  # prime
DH_G = 5   # generator

toy_dh_private_keys = {}  # username -> private key (int)
toy_dh_public_keys = {}   # username -> public key (int)

def toy_generate_private_key():
    import random
    return random.randint(2, DH_P-2)

def toy_generate_public_key(private_key):
    return pow(DH_G, private_key, DH_P)

def toy_derive_shared_key(private_key, other_public):
    return pow(other_public, private_key, DH_P)

# --- DH Handshake (Toy version) ---
@router.get("/dh/start")
def dh_start():
    # Generate a new private/public key for this session (for demo, per request)
    import random
    server_private = toy_generate_private_key()
    server_public = toy_generate_public_key(server_private)
    # Store for later (insecure, demo only)
    g.server_private_key = server_private
    g.server_public_key = server_public
    return {"server_pub_key": server_public}

@router.get("/dh/params")
def dh_params():
    """Return the toy DH parameters (p, g) to the client."""
    return {"p": DH_P, "g": DH_G}

@router.post("/dh/finish")
def dh_finish(data: DHExchange):
    logging.debug(f"[TOY DH] Received DH finish data for username: {data.username}")
    try:
        client_pub = int(data.client_pub_key)
        server_private = g.server_private_key
        shared = toy_derive_shared_key(server_private, client_pub)
        # For demo, just use the shared int as bytes (pad to 16 bytes)
        derived_key = shared.to_bytes(16, 'big')
        dh_sessions[data.username] = derived_key
        return {"message": "DH key established (toy)"}
    except Exception as e:
        logging.error(f"[TOY DH] DH exchange failed for {data.username}: {str(e)}")
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

    # Decrypt the password using DH session key
    derived_key = dh_sessions.get(data.username)
    logging.debug(f"Derived key for {data.username}: {derived_key}")
    if not derived_key:
        logging.error(f"Missing DH session for {data.username}")
        raise HTTPException(status_code=400, detail="Missing DH session")

    try:
        aesgcm = AESGCM(derived_key)
        # The client sends base64-encoded ciphertext and nonce in the password field (as in register)
        encrypted = base64.b64decode(data.password)
        # For login, we expect the client to send the IV and ciphertext concatenated and base64-encoded
        iv = encrypted[:12]
        ciphertext = encrypted[12:]
        decrypted_password = aesgcm.decrypt(iv, ciphertext, None).decode()
    except Exception as e:
        logging.error(f"Decryption failed for {data.username}: {str(e)}")
        raise HTTPException(status_code=401, detail="Invalid credentials (decryption)")

    # Hash the provided password with the stored salt and compare
    import hashlib
    hashed_attempt = hashlib.pbkdf2_hmac('sha256', decrypted_password.encode(), salt, 100_000)
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
