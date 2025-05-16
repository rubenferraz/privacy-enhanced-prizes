# --- Scratchcard Config ---
SCRATCHCARD_COUNT = 12
WINNER_PERCENTAGE = 0.10
TIME_PER_ROUND = 1 # 1 minute

# --- RSA Config ---
RSA_KEY_SIZE = 2048  # bits

# --- Global State (initialized as None, set at runtime) ---
dh_parameters = None
server_private_key = None
server_public_key = None
server_pub_b64 = None

rsa_private_key = None
rsa_public_key = None
