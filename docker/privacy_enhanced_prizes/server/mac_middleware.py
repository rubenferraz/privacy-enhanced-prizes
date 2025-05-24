from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import json
from server.mac_utils import generate_mac, verify_mac
import logging

logger = logging.getLogger(__name__)

class MacMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Verify MAC on incoming request (this part is working)
        try:
            mac_header = request.headers.get("X-MAC")
            if mac_header and request.method in ["POST", "PUT", "PATCH"]:
                body = await request.body()
                # Store body for later use
                async def get_body():
                    return body
                request._body = body
                request.body = get_body
                
                body_str = body.decode("utf-8")
                
                if not verify_mac(body_str, mac_header):
                    logger.warning(f"[MAC] MAC validation failed for request to {request.url.path}")
                    return Response(
                        content=json.dumps({"detail": "Invalid MAC"}),
                        status_code=403,
                        media_type="application/json"
                    )
                # logger.debug(f"[MAC] MAC validation successful for request to {request.url.path}")
        except Exception as e:
            logger.error(f"[MAC] MAC verification error: {str(e)}")
        
        # Process the request
        response = await call_next(request)
        
        # IMPROVED: Add MAC to response headers for any JSON response
        try:
            content_type = response.headers.get("content-type", "")
            if "json" in content_type.lower():
                # Create a simple Response we can modify
                resp_body = b""
                async for chunk in response.body_iterator:
                    resp_body += chunk
                
                # Generate MAC from the response body
                mac = generate_mac(resp_body)
                
                # Create new response with MAC header
                headers = dict(response.headers.items()) | {"X-MAC": mac}
                # logger.debug(f"[MAC] Added MAC header to response for {request.url.path}")
                
                return Response(
                    content=resp_body,
                    status_code=response.status_code,
                    headers=headers,
                    media_type=content_type
                )
        except Exception as e:
            logger.error(f"Error adding MAC to response: {str(e)}")
        
        return response
