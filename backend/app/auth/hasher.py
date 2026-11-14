import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger(__name__)

# Argon2id configuration per NIST & OWASP recommendations
# Memory: 64MB (65536 KiB), Time: 3 iterations, Parallelism: 4 threads
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)

# Pre-computed dummy hash using the exact same parameters
# Used for constant-time comparison when an account does not exist (mitigates timing attacks)
_DUMMY_HASH = _hasher.hash("dummy_fallback_password_for_timing_mitigation")


def hash_password(password: str) -> str:
    """Hash a plaintext password using Argon2id with 64MB memory cost."""
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.
    Returns True if valid, False if mismatch or invalid hash.
    Never raises an exception to the caller.
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as e:
        logger.error("Unexpected error during password verification: %s", type(e).__name__)
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Check if the hash was created with older parameters and needs updating."""
    try:
        return _hasher.check_needs_rehash(hashed_password)
    except Exception:
        return True


def dummy_verify() -> None:
    """
    Executes Argon2id verification against a dummy hash.
    Used when a requested user email does not exist in the database,
    ensuring that invalid-email requests take the same time as invalid-password requests.
    """
    try:
        _hasher.verify(_DUMMY_HASH, "incorrect_dummy_attempt")
    except Exception:
        pass
