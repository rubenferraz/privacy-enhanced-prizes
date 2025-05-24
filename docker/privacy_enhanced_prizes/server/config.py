# --- Scratchcard Config ---
SCRATCHCARD_COUNT = 20
WINNER_PERCENTAGE = 0.10
TIME_PER_ROUND = 2 # 1 minute

# --- RSA Config ---
RSA_KEY_SIZE = 2048  # bits

# --- MAC Config ---
MAC_SECRET = "8f39e7bc45d2a7c18b1d9e5a7d3426f9"  # Secure random key for HMAC

# --- Global State (initialized as None, set at runtime) ---
dh_parameters = None
server_private_key = None
server_public_key = None
server_pub_b64 = None

rsa_private_key = None
rsa_public_key = None
