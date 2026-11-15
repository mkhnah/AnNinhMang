"""Bounded per-process receipts. Public IDs are bearer capabilities, never log them.

Restart/eviction/expiry requires re-verification. No PDFs or private key material stored.
"""
import secrets
import threading
import time
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException
from backend.app.schemas.verify import VerificationResultResponse

TTL_SECONDS = 600
MAX_RECEIPTS = 1024
_LOCK = threading.Lock()
_RECEIPTS = {}

def issue(result: VerificationResultResponse, actor_id=None, document_id=None):
    token = secrets.token_urlsafe(32)
    result.verification_receipt = token
    result.receipt_expires_at = datetime.now(timezone.utc) + timedelta(seconds=TTL_SECONDS)
    now = time.monotonic()
    with _LOCK:
        expired = [key for key, value in _RECEIPTS.items() if value[0] <= now]
        for key in expired:
            del _RECEIPTS[key]
        if len(_RECEIPTS) >= MAX_RECEIPTS:
            del _RECEIPTS[next(iter(_RECEIPTS))]
        _RECEIPTS[token] = (now + TTL_SECONDS, actor_id, document_id, result.model_dump_json())
    return result

def lookup(token):
    with _LOCK:
        value = _RECEIPTS.get(token)
        if value is None or value[0] <= time.monotonic():
            _RECEIPTS.pop(token, None)
            raise HTTPException(404, "Receipt unavailable or expired; verify again")
        return value[1], value[2], VerificationResultResponse.model_validate_json(value[3])
