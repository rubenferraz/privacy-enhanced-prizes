from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi import BackgroundTasks
from server.auth import router as auth_router
from server.scratchcard import router as scratchcard_router, generate_scratchcards, get_current_scratchcards
from server.utils import generate_dh_keys
from server.rsa_utils import generate_rsa_keys
from server.crypto import router as crypto_router
from server.mac_middleware import MacMiddleware  # Import the MAC middleware
from server.config import TIME_PER_ROUND
import server.config as g
import uvicorn
import logging
import asyncio
import datetime

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)
logging.getLogger('server.mac_middleware').setLevel(logging.DEBUG)
logging.getLogger('server.mac_utils').setLevel(logging.DEBUG)

# chaves DH
g.dh_parameters, g.server_private_key, g.server_public_key, g.server_pub_b64 = generate_dh_keys()

app = FastAPI(
    title="PrivacyEnhancedPrizes API",
    description="API backend for secure digital scratchcard distribution.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(MacMiddleware) # middleware para o MAC

app.include_router(auth_router, prefix="/auth")
app.include_router(scratchcard_router, prefix="/scratchcard")
app.include_router(crypto_router, prefix="/crypto")

@app.get("/")
def read_root():
    return {"message": "PrivacyEnhancedPrizes API is running."}

@app.get("/health")
def read_health():
    return {"status": "ok"}

@app.get("/mac-test")
def mac_test():
    """Simple endpoint that returns a JSON response with MAC header"""
    return {"mac": "test", "timestamp": str(datetime.datetime.now())}

@app.get("/scratchcards")
def get_scratchcards():
    return {"scratchcards": get_current_scratchcards()}

async def periodic_scratchcard_generation():
    while True:
        generate_scratchcards()
        await asyncio.sleep(TIME_PER_ROUND * 60)

# gerar as chaves RSA
@app.on_event("startup")
async def startup_event():
    g.rsa_private_key, g.rsa_public_key = generate_rsa_keys()
    asyncio.create_task(periodic_scratchcard_generation())

if __name__ == "__main__":
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)