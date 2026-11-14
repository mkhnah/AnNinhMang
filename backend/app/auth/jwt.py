import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from backend.app.core.config import settings


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def hash_token(raw_token: str) -> str:
    """Computes SHA-256 hash of raw token string to prevent storing raw secrets in DB."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def generate_secure_token(nbytes: int = 32) -> str:
    """Generates cryptographically strong URL-safe random token (256-bit entropy default)."""
    return secrets.token_urlsafe(nbytes)


def create_access_token(user_id: str, role: str, extra_claims: Optional[Dict[str, Any]] = None) -> str:
    """
    Creates a signed JWT access token with short lifetime (15 mins).
    Explicitly uses HS256 algorithm and includes standard claims.
    """
    now = utc_now()
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload: Dict[str, Any] = {
        "sub": user_id,
        "role": role,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "jti": secrets.token_hex(16),
    }

    if extra_claims:
        payload.update(extra_claims)

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return token


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and validates a JWT access token.
    Enforces strict algorithm check (rejects 'none' and algorithm confusion).
    Raises ExpiredSignatureError or InvalidTokenError if invalid.
    """
    payload = jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        options={
            "verify_signature": True,
            "verify_exp": True,
            "verify_iat": True,
            "require": ["sub", "role", "exp", "type"],
        }
    )

    if payload.get("type") != "access":
        raise InvalidTokenError("Invalid token type: expected 'access'")

    return payload
