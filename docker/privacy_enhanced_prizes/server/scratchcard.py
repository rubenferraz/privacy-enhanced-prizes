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
from server.auth import sessions
import jwt

router = APIRouter()

# shared state
_current_scratchcards = []
_lock = threading.Lock()

# Track claimed scratchcard indices for the current round
_claimed_indices = set()
_user_claims = {}  # username -> index

# Store round end time (global, updated on each generate_scratchcards)
_round_end = None

def get_username_from_token(token: str):
    # Find username by token in sessions
    for username, t in sessions.items():
        if t == token:
            return username
    # Try to decode JWT directly if not found
    try:
        payload = jwt.decode(token, "superseguro", algorithms=["HS256"])
        return payload.get("sub")
    except Exception:
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
        # Set round end time using TIME_PER_ROUND from config (in minutes)
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
        # Pad card to modulus length
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
    # Get token from Authorization header
    auth = request.headers.get("authorization") or ""
    token = auth.replace("Bearer ", "").strip()
    username = get_username_from_token(token)
    if not username:
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    with _lock:
        if username in _user_claims:
            raise HTTPException(status_code=400, detail="User already claimed a scratchcard this round")
        if data.index in _claimed_indices:
            raise HTTPException(status_code=400, detail="Scratchcard already claimed")
        if data.index < 0 or data.index >= len(_current_scratchcards):
            raise HTTPException(status_code=400, detail="Invalid scratchcard index")
        _claimed_indices.add(data.index)
        _user_claims[username] = data.index
    blinded = base64.b64decode(data.blinded_value)
    try:
        privkey = g.rsa_private_key
        numbers = privkey.private_numbers()
        n = numbers.public_numbers.n
        d = numbers.d
        blinded_int = int.from_bytes(blinded, byteorder='big')
        revealed_int = pow(blinded_int, d, n)
        k = (n.bit_length() + 7) // 8
        revealed_bytes = revealed_int.to_bytes(k, byteorder='big')
        return {"revealed": base64.b64encode(revealed_bytes).decode()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"OT failed: {str(e)}")