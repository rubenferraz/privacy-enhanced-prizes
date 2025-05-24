from fastapi import APIRouter, HTTPException, Request, Depends
import random
import threading
from server.config import SCRATCHCARD_COUNT, WINNER_PERCENTAGE, TIME_PER_ROUND
from server.rsa_utils import rsa_encrypt_raw, rsa_decrypt
import server.config as g
import base64
from pydantic import BaseModel
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from server.auth import sessions, verify_token
import jwt
import logging

router = APIRouter()

# shared state
_current_scratchcards = []
_lock = threading.Lock()

# Track claimed scratchcard indices for the current round
_claimed_indices = set()
_user_claims = {}  # username -> index

# Store round end time (global, updated on each generate_scratchcards)
_round_end = None

# Usar a função verify_token em vez da implementação atual
def get_auth_token(request: Request) -> str:
    """Extrai o token de autenticação dos cabeçalhos da requisição"""
    auth = request.headers.get("authorization", "")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:]  # Remove 'Bearer ' do início
    return ""

# Função atualizada para utilizar verify_token
def get_username_from_token(token: str):
    """Obtém o username a partir do token utilizando verify_token"""
    try:
        return verify_token(token)
    except HTTPException:
        # Se verify_token lançar uma exceção, retorna None para manter compatibilidade
        return None

def generate_scratchcards():
    global _current_scratchcards, _claimed_indices, _user_claims, _round_end
    import datetime
    n_winners = int(SCRATCHCARD_COUNT * WINNER_PERCENTAGE)
    n_losers = SCRATCHCARD_COUNT - n_winners
    cards = [1]*n_winners + [0]*n_losers
    random.shuffle(cards)
    with _lock:
        _current_scratchcards = cards
        _claimed_indices = set()  # Reset claims for new round
        _user_claims = {}         # Reset user claims for new round
        _round_end = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=TIME_PER_ROUND)).isoformat() + "Z"

def get_current_scratchcards():
    with _lock:
        return list(_current_scratchcards)

def get_current_scratchcards_with_claims():
    with _lock:
        return [
            {"index": i, "claimed": i in _claimed_indices}
            for i in range(len(_current_scratchcards))
        ]

def get_round_end():
    with _lock:
        return _round_end


@router.get("/ot/encrypted")
def ot_encrypted():
    """Send the encrypted scratchcards (raw RSA-encrypted, base64-encoded) and claim status."""
    public_key = g.rsa_public_key
    scratchcards = get_current_scratchcards()
    encrypted_cards = []
    for card in scratchcards:
        card_bytes = str(card).encode()
        enc = rsa_encrypt_raw(public_key, card_bytes)
        encrypted_cards.append(base64.b64encode(enc).decode())
    claims = get_current_scratchcards_with_claims()
    return {
        "encrypted_scratchcards": encrypted_cards,
        "claims": claims,
        "round_end": get_round_end()
    }

class OTRequest(BaseModel):
    blinded_value: str  # base64-encoded
    index: int

@router.post("/ot/reveal")
def ot_reveal(data: OTRequest, request: Request):
    """Reveal the scratchcard to the user using OT (RSA decryption of blinded value)."""
    # Obter e verificar o token de autenticação
    token = get_auth_token(request)
    if not token:
        raise HTTPException(status_code=401, detail="Token de autenticação ausente")
    
    try:
        username = verify_token(token)
    except HTTPException as e:
        # Propagar a exceção da verificação de token
        raise e
    
    logging.debug(f"[OT]: Autenticado como: {username}")
    
    with _lock:
        if username in _user_claims:
            raise HTTPException(status_code=400, detail="Utilizador já reclamou uma raspadinha nesta ronda")
        if data.index in _claimed_indices:
            raise HTTPException(status_code=400, detail="Raspadinha já foi reclamada")
        if data.index < 0 or data.index >= len(_current_scratchcards):
            raise HTTPException(status_code=400, detail="Índice de raspadinha inválido")
        _claimed_indices.add(data.index)
        _user_claims[username] = data.index
        logging.debug(f"[OT]: Utilizador {username} reclamou a carta no índice {data.index}")
    
    blinded = base64.b64decode(data.blinded_value)
    logging.debug(f"[OT]: Received blinded value (first 20 bytes): {blinded[:20].hex()}")
    
    try:
        privkey = g.rsa_private_key
        logging.debug(f"[OT]: Private key type: {type(privkey)}")
        
        numbers = privkey.private_numbers()
        logging.debug(f"[OT]: Got private numbers")
        
        n = numbers.public_numbers.n
        d = numbers.d
        logging.debug(f"[OT]: n (first 20 chars): {str(n)[:20]}...")
        logging.debug(f"[OT]: d (first 20 chars): {str(d)[:20]}...")
        
        blinded_int = int.from_bytes(blinded, byteorder='big')
        logging.debug(f"[OT]: Blinded int (first 20 chars): {str(blinded_int)[:20]}...")
        
        revealed_int = pow(blinded_int, d, n)
        logging.debug(f"[OT]: Revealed int (first 20 chars): {str(revealed_int)[:20]}...")
        
        k = (n.bit_length() + 7) // 8
        logging.debug(f"[OT]: Key size in bytes: {k}")
        
        revealed_bytes = revealed_int.to_bytes(k, byteorder='big')
        logging.debug(f"[OT]: Revealed bytes (first 20 bytes): {revealed_bytes[:20].hex()}")
        
        encoded = base64.b64encode(revealed_bytes).decode()
        logging.debug(f"[OT]: Final encoded result (first 20 chars): {encoded[:20]}...")
        
        return {"revealed": encoded}
    except Exception as e:
        logging.error(f"[OT]: Error in reveal: {str(e)}", exc_info=True)
        raise HTTPException(status_code=400, detail=f"OT failed: {str(e)}")