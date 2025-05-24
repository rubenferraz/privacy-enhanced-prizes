import hmac
import hashlib
import base64
from fastapi import Request, Response, HTTPException
import server.config as g
import json
import logging

logger = logging.getLogger(__name__)

def generate_mac(data, secret=g.MAC_SECRET):
    """Generate HMAC-SHA256 for given data using the server MAC secret."""
    if isinstance(data, bytes):
        data_bytes = data
    else:
        data_bytes = data.encode('utf-8')
    h = hmac.new(secret.encode('utf-8'), data_bytes, hashlib.sha256)
    result = base64.b64encode(h.digest()).decode('utf-8')
    # logger.debug(f"[MAC] Generated MAC: {result[:20]}... for data of length {len(data_bytes)} bytes")
    return result

def verify_mac(data, mac, secret=g.MAC_SECRET):
    """Verify if the provided MAC matches the calculated MAC for the data."""
    expected_mac = generate_mac(data, secret)
    result = hmac.compare_digest(expected_mac, mac)
    #  logger.debug(f"[MAC] MAC verification: {'SUCCESS' if result else 'FAILED'}")
    return result
