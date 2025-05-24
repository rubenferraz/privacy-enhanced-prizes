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
        "exp": time.time() + (60 * 60) # 1 hour expiration
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

# Função para verificar a validade dos tokens JWT
def verify_token(token: str) -> str:
    """
    Verifica se um token JWT é válido.
    
    Args:
        token: O token JWT a verificar
        
    Returns:
        O username se o token for válido
        
    Raises:
        HTTPException: Se o token for inválido ou tiver expirado
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        username = payload.get("sub")
        
        # Verificar se o token corresponde a uma sessão ativa
        if username not in sessions or sessions[username] != token:
            logging.warning(f"Token válido mas sessão inativa para {username}")
            raise HTTPException(status_code=401, detail="Sessão inválida")
            
        return username
    except jwt.ExpiredSignatureError:
        logging.warning("Token expirado")
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError as e:
        logging.warning(f"Token inválido: {str(e)}")
        raise HTTPException(status_code=401, detail="Token inválido")
    except Exception as e:
        logging.error(f"Erro na verificação do token: {str(e)}")
        raise HTTPException(status_code=401, detail="Erro na verificação do token")

# Parâmetros para o Diffie-Hellman
# 1024 bits
P = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF", 16)
G = 2

# --- Handshake ---
@router.get("/dh/params")
def dh_params():
    """Devolve o P e o G do Diffie-Hellman"""
    logging.debug(f"[DH] Sending DH parameters: P={P}, G={G}")
    return {
        "p": base64.b64encode(P.to_bytes((P.bit_length() + 7) // 8, byteorder="big")).decode('utf-8'),
        "g": G
    }

@router.get("/dh/start")
def dh_start():
    """Gera a chave privada e a chave pública do servidor"""
    logging.debug("[DH] Starting Diffie-Hellman key exchange")
    
    # sk
    server_private_key = secrets.randbelow(P-2) + 2  # Range [2, P-1]
    # pk
    server_public_key = pow(G, server_private_key, P)
    
    # guardar a sk e pk do servidor
    g.server_private_key = server_private_key
    g.server_public_key = server_public_key
    
    # converter a pk para bas64, para se poder enviar para o cliente
    server_public_key_bytes = server_public_key.to_bytes((server_public_key.bit_length() + 7) // 8, byteorder="big")
    server_public_key_b64 = base64.b64encode(server_public_key_bytes).decode('utf-8')
    
    # fica bonito assim ?
    server_public_key_pem = f"-----BEGIN PUBLIC KEY-----\n{server_public_key_b64}\n-----END PUBLIC KEY-----"
    
    return {
        "server_pub_key": server_public_key_pem,
    }

@router.post("/dh/finish")
def dh_finish(data: DHExchange):
    logging.debug(f"[DH] Received DH finish data for username: {data.username}")
    try:
        # extração da pk do cliente (está no formato PEM)
        client_pub_key_pem = data.client_pub_key
        client_pub_key_b64 = client_pub_key_pem.replace('-----BEGIN PUBLIC KEY-----', '').replace('-----END PUBLIC KEY-----', '').replace('\n', '')
        client_pub_key_bytes = base64.b64decode(client_pub_key_b64)
        client_public_key = int.from_bytes(client_pub_key_bytes, byteorder="big")

        # calcula o segredo comum ou partilhado
        server_private_key = g.server_private_key        
        shared_secret = pow(client_public_key, server_private_key, P)
        
        shared_secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, byteorder="big")
        derived_key = hashlib.sha256(shared_secret_bytes).digest()
        dh_sessions[data.username] = derived_key # fica guardada a chave para se poder usar depois no register
        
        logging.debug(f"[DH] Established secure key for {data.username}")
        return {"message": "DH key established"}
    except Exception as e:
        logging.error(f"[DH] Exchange failed for {data.username}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"DH error: {str(e)}")

# --- Registo ---
@router.post("/register")
def register(data: RegisterEncryptedData):
    logging.debug(f"[REGISTER] Attempting to register user: {data.username}")

    if not data.username or not data.encrypted_password or not data.nonce:
        raise HTTPException(status_code=400, detail="Missing fields")

    if data.username in users:
        raise HTTPException(status_code=400, detail="User already exists")

    derived_key = dh_sessions.get(data.username)
    if not derived_key:
        raise HTTPException(status_code=400, detail="Missing DH session")

    try:
        logging.debug(f"[REGISTER] Attempting to decrypt password for user: {data.username}")

        # temos a chave derivada (veio do DH), precisamos de desencriptar a palavra-passe que o cliene enviou
        aesgcm = AESGCM(derived_key)
        nonce_bytes = base64.b64decode(data.nonce)
        encrypted_bytes = base64.b64decode(data.encrypted_password)
        decrypted_password = aesgcm.decrypt(nonce_bytes, encrypted_bytes, None).decode()

        # isto é só para debugging
        logging.debug(f"[REGISTER] Decrypted password for {data.username}: {decrypted_password}")

        # agora que se tem a password crua, vamos fazer o hash da password + salt
        salt = os.urandom(16) # 16 bytes salt
        hashed_password = hashlib.pbkdf2_hmac('sha256', decrypted_password.encode(), salt, 100_000)
        users[data.username] = (hashed_password, salt)
        logging.debug(f"[REGISTER] Stored hashed password and salt for {data.username}")

    except Exception as e:
        logging.error(f"[REGISTER] Decryption failed for {data.username}: {str(e)}")
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")

    logging.debug(f"[REGISTER] User {data.username} successfully registered")
    return {"message": "User registered successfully"}

# --- Login ---
@router.post("/login")
def login(data: LoginData):
    logging.debug(f"[LOGIN] Attempting to login with username: {data.username}")

    # Get stored hash and salt
    user_entry = users.get(data.username)
    if not user_entry:
        logging.error(f"User {data.username} not found")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    hashed_password, salt = user_entry
    logging.debug(f"[LOGIN] Stored hashed password for {data.username}: {hashed_password}")

    # hash da passwd que o utilizador enviou + salt
    import hashlib
    hashed_attempt = hashlib.pbkdf2_hmac('sha256', data.password.encode(), salt, 100_000)
    
    if hashed_attempt == hashed_password:
        token = create_jwt(data.username)
        sessions[data.username] = token
        logging.debug(f"[LOGIN] Login successful for {data.username}")
        return {"token": token}

    logging.error(f"[LOGIN] Invalid credentials for {data.username}")
    raise HTTPException(status_code=401, detail="Invalid credentials")

@router.get("/active_sessions")
def active_sessions():
    active_count = len(sessions)
    logging.debug(f"Currently active sessions: {active_count}")
    return {"active_sessions": active_count}

@router.get("/logout")
def logout(token: str = None, request: Request = None):
    # jwt token 
    logging.debug(f"[LOGOUT] A tentar sair com o token JWT: {token}")
    if not token and request:
        auth = request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth[7:]
    if not token:
        logging.error("[LOGOUT] O token JWT não foi fornecido")
        raise HTTPException(status_code=401, detail="No token provided")
    for username, user_token in list(sessions.items()):
        if user_token == token:
            del sessions[username]
            logging.debug(f"[LOGOUT] User {username} foi-se embora")
            return {"message": "Logged out successfully"}
    logging.error("[LOGOUT] Token JWT inválido")
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

@router.get("/verify-token")
def verify_token_endpoint(request: Request):
    """
    Verifica se o token JWT fornecido é válido.
    
    Returns:
        Validade do token JWT e o username associado, caso seja válido.
    """
    logging.debug("[JWT] Verificação do token JWT")
    
    # Extrair token do cabeçalho Authorization
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        logging.warning("[JWT] Token não foi fornecido nos cabeçalhos")
        return {
            "valid": False,
            "reason": "Token não fornecido",
            "remaining_time": 0
        }
    
    token = auth[7:]  # Remove 'Bearer ' do início
    
    try:
        # Decodificar token sem verificar assinatura primeiro para obter tempo restante
        payload = jwt.decode(token, options={"verify_signature": False})
        exp_time = payload.get("exp", 0)
        current_time = time.time()
        remaining_seconds = max(0, int(exp_time - current_time))
        
        # Agora verificar completamente o token
        username = verify_token(token)
        
        return {
            "valid": True,
            "username": username,
            "remaining_time": remaining_seconds,
            "expires_at": exp_time
        }
        
    except HTTPException as e:
        logging.warning(f"[JWT] Token inválido: {e.detail}")
        return {
            "valid": False,
            "reason": e.detail,
            "remaining_time": 0
        }
    except Exception as e:
        logging.error(f"[JWT] Erro ao verificar token: {str(e)}")
        return {
            "valid": False,
            "reason": "Erro interno ao verificar token",
            "remaining_time": 0
        }
@router.post("/renew-token")
def renew_token(request: Request):
    """
    Renova um token JWT **válido**.
    
    Returns:
        Um novo token JWT + username
    """
    logging.debug("[JWT] Tentando renovar token JWT")
    
    # Extrair token do cabeçalho Authorization
    auth = request.headers.get("Authorization")
    if not auth or not auth.lower().startswith("bearer "):
        logging.warning("[JWT] Token não fornecido nos cabeçalhos")
        raise HTTPException(status_code=401, detail="Token não fornecido")
    
    token = auth[7:]  # Remove 'Bearer ' do início
    
    try:
        username = verify_token(token)
        new_token = create_jwt(username)
        
        sessions[username] = new_token # atualizar no dicionário das sessões
        
        logging.debug(f"[JWT] Token renovado com sucesso para o user {username}")
        
        return {
            "token": new_token,
            "username": username
        }
        
    except HTTPException as e:
        logging.warning(f"[JWT] Falha ao renovar token: {e.detail}")
        raise HTTPException(status_code=401, detail=f"Não foi possível renovar o token: {e.detail}")
    except Exception as e:
        logging.error(f"[JWT] Erro ao renovar token: {str(e)}")
        raise HTTPException(status_code=500, detail="Erro interno ao renovar token")
