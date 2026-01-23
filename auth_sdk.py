"""
Python Signature Verification Library
Synced with Go middleware logic for Chrome Extension Auth System

Usage:
    from auth_sdk import verify_signature, calculate_signature
    
    # In Flask/FastAPI middleware:
    is_valid = verify_signature(request, token)
    
    # For signing requests:
    signature = calculate_signature(method, url, body, timestamp, temp_id, token)
"""

import hmac
import hashlib
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs

def sort_query_string(query_params: Dict[str, list]) -> str:
    """Sort query parameters alphabetically"""
    if not query_params:
        return ""
    
    sorted_keys = sorted(query_params.keys())
    pairs = []
    
    for key in sorted_keys:
        values = sorted(query_params[key])
        for value in values:
            pairs.append(f"{key}={value}")
    
    return "&".join(pairs)

def sha256_hex(data: bytes) -> str:
    """Calculate SHA256 hash and return hex string"""
    return hashlib.sha256(data).hexdigest()

def hmac_sha256(data: str, key: str) -> str:
    """Calculate HMAC-SHA256 and return hex string"""
    h = hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256)
    return h.hexdigest()

def calculate_signature(
    method: str,
    url: str,
    body: Optional[bytes],
    timestamp: str,
    temp_id: str,
    token: str
) -> str:
    """
    Calculate request signature matching Go middleware logic
    
    Args:
        method: HTTP method (GET, POST, PUT, DELETE)
        url: Full request URL
        body: Request body bytes (None for GET)
        timestamp: Unix timestamp string
        temp_id: Device ID from x-temp-id header
        token: Current valid token
    
    Returns:
        Hex-encoded HMAC-SHA256 signature
    """
    if method == "GET":
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        sorted_query = sort_query_string(query_params)
        payload = f"{sorted_query}|{timestamp}|{temp_id}"
    else:
        body_bytes = body if body else b''
        body_hash = sha256_hex(body_bytes)
        payload = f"{body_hash}|{timestamp}|{temp_id}"
    
    return hmac_sha256(payload, token)

def verify_signature(
    method: str,
    url: str,
    body: Optional[bytes],
    headers: Dict[str, str],
    token: str
) -> bool:
    """
    Verify request signature
    
    Args:
        method: HTTP method
        url: Full request URL
        body: Request body bytes
        headers: Request headers dict
        token: Current valid token
    
    Returns:
        True if signature is valid, False otherwise
    """
    client_sign = headers.get('x-sign')
    timestamp = headers.get('x-timestamp')
    temp_id = headers.get('x-temp-id')
    
    if not all([client_sign, timestamp, temp_id]):
        return False
    
    server_sign = calculate_signature(method, url, body, timestamp, temp_id, token)
    
    return hmac.compare_digest(server_sign, client_sign)

# Flask middleware example
def flask_signature_middleware(app):
    """
    Flask middleware for signature verification
    
    Usage:
        from flask import Flask
        from auth_sdk import flask_signature_middleware
        
        app = Flask(__name__)
        flask_signature_middleware(app)
    """
    from flask import request, jsonify
    
    @app.before_request
    def verify_request_signature():
        if request.endpoint in ['login', 'static']:
            return None
        
        auth_header = request.headers.get('Authorization', '')
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Invalid authorization header'}), 401
        
        token = auth_header[7:]
        
        body = request.get_data() if request.method != 'GET' else None
        
        if not verify_signature(request.method, request.url, body, request.headers, token):
            return jsonify({'error': 'Signature verification failed'}), 403
        
        return None

# FastAPI dependency example
def fastapi_signature_dependency(request, token: str):
    """
    FastAPI dependency for signature verification
    
    Usage:
        from fastapi import FastAPI, Depends, Header
        from auth_sdk import fastapi_signature_dependency
        
        app = FastAPI()
        
        @app.get("/api/data")
        def get_data(verified=Depends(fastapi_signature_dependency)):
            return {"message": "success"}
    """
    from fastapi import HTTPException
    
    body = None
    if request.method != "GET":
        body = request.body()
    
    headers = dict(request.headers)
    
    if not verify_signature(request.method, str(request.url), body, headers, token):
        raise HTTPException(status_code=403, detail="Signature verification failed")
    
    return True
