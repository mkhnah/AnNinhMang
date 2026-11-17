"""Atomic audit appends and deterministic verification of retained evidence.

The checkpoint detects truncation while it remains trusted. A database administrator
able to rewrite both logs and checkpoint can recompute this unkeyed chain.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import ipaddress
import re
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select, update

from backend.app.crypto.jcs import canonicalize, parse_strict_json
from backend.app.models.audit import AuditChainState, AuditLog, GENESIS_HASH


# Only server-derived, typed metadata is retained. Free text, nested payloads,
# filenames, labels, headers, manifests and credentials have no permitted field.
DETAIL_FIELDS = {
    "USER_LOGIN": {"reason", "http_status"},
    "KEY_GENERATE": {"algorithm", "fingerprint"},
    "KEY_REVOKE": {"fingerprint"},
    "DOCUMENT_UPLOAD": {"document_id", "version_no", "file_size_bytes", "file_sha256"},
    "DOCUMENT_SIGN": {"key_id", "signature_id", "manifest_sha256"},
    "DOCUMENT_VERIFY": {"verification_id", "verification_mode", "summary_status", "cryptographic_validity", "document_integrity"},
    "SHARE_QR": {"version_id", "expires_in_days"},
    "SHARE_REVOKE": set(),
    "ACCESS_DENIED_IDOR": {"reason"},
    "ACCESS_DENIED_ROLE": {"reason"},
    "CERTIFICATE_ISSUE": {"key_id", "fingerprint"},
    "CERTIFICATE_RENEW": {"key_id", "fingerprint"},
    "CERTIFICATE_REVOKE": set(),
    "CERTIFICATE_VERIFY": {"fingerprint", "outcome"},
    "IDENTITY_REVIEW": {"outcome"},
    "CA_ROTATE": {"fingerprint"},
    "CA_COMPROMISED": {"fingerprint"},
}
ENUM_VALUES = {
    "outcome": {"APPROVED", "REJECTED", "VALID", "INVALID", "POSSESSION_VERIFIED"},
    "algorithm": {"RSA-PSS-3072"},
    "reason": {"INVALID_CREDENTIALS", "LOCKED", "DISABLED", "OWNER_MISMATCH", "RESOURCE_UNAVAILABLE", "ROLE_REQUIRED"},
    "verification_mode": {"INTERNAL", "INDEPENDENT_DETACHED", "PUBLIC_SHARED"},
    "summary_status": {"VERIFIED", "INTEGRITY_COMPROMISED", "SIGNATURE_INVALID", "REVOKED_KEY", "UNVERIFIABLE"},
    "cryptographic_validity": {"VALID", "INVALID", "UNVERIFIABLE"},
    "document_integrity": {"UNCHANGED", "TAMPERED", "UNKNOWN"},
}
TARGET_TYPES = {"USER", "KEY", "CHALLENGE", "DOCUMENT", "VERSION", "SIGNING_SESSION", "SHARE", "VERIFICATION", "CERTIFICATE", "CA", "IDENTITY_REVIEW"}
USER_AGENTS = ("Firefox", "Edg", "Chrome", "Safari")


def _identifier(value):
    if value is None:
        return None
    text = str(value)
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,36}", text):
        raise ValueError("Invalid audit identifier")
    return text


def sanitize_details(action, details):
    """Discard all fields and values outside the event's explicit schema."""
    clean = {}
    for key, value in (details or {}).items():
        if key not in DETAIL_FIELDS[action]:
            continue
        if key.endswith("_id"):
            try:
                clean[key] = _identifier(value)
            except (ValueError, TypeError, AttributeError):
                continue
        elif key in {"fingerprint", "file_sha256", "manifest_sha256"}:
            if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value):
                clean[key] = value
        elif key in {"http_status", "version_no", "file_size_bytes", "expires_in_days"}:
            if type(value) is int and 0 <= value <= 2**53 - 1:
                clean[key] = value
        elif isinstance(value, str) and value in ENUM_VALUES.get(key, set()):
            clean[key] = value
    return clean


def request_context(client_ip=None, user_agent=None):
    try:
        peer = str(ipaddress.ip_address(client_ip))
    except ValueError:
        peer = None
    # User-Agent is arbitrary input and may contain tokens or secrets.
    family = next((name for name in USER_AGENTS if name + "/" in (user_agent or "")), None)
    return {"client_ip": peer, "user_agent": family}


def _timestamp(value):
    utc = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    return utc.isoformat(timespec="microseconds").replace("+00:00", "Z")


def compute_entry_hash(entry):
    details = parse_strict_json(entry.details_json)
    if canonicalize(details).decode("utf-8") != entry.details_json:
        raise ValueError("Noncanonical audit details")
    payload = {name: getattr(entry, name) for name in (
        "prev_hash", "actor_id", "action", "target_type", "target_id", "client_ip", "user_agent", "status"
    )}
    payload.update(schema_version=1, id=str(entry.id), created_at=_timestamp(entry.created_at),
                   details_hash=hashlib.sha256(canonicalize(details)).hexdigest())
    return hashlib.sha256(b"DOCSIGN_AUDIT_V1\x00" + canonicalize(payload)).hexdigest()


def append_audit(db, action, *, actor_id=None, target_type, target_id=None, status="SUCCESS", details=None, context=None):
    """Append within the caller's transaction, leaving commit/rollback to it.

    UPDATE acquires SQLite's writer lock before reading the head, including when
    multiple processes append. The checkpoint advances in the same transaction.
    """
    if action not in DETAIL_FIELDS or target_type not in TARGET_TYPES or status not in {"SUCCESS", "FAILURE", "DENIED"}:
        raise ValueError("Unsupported audit event")
    clean = sanitize_details(action, details)
    actor_id, target_id = _identifier(actor_id), _identifier(target_id)
    metadata = context if context is not None else db.info.get("audit_context", {})
    safe_context = request_context(metadata.get("client_ip"))
    safe_context["user_agent"] = metadata.get("user_agent") if metadata.get("user_agent") in USER_AGENTS else None
    db.flush()
    locked = db.execute(update(AuditChainState).where(AuditChainState.id == 1)
                        .values(last_id=AuditChainState.last_id).execution_options(synchronize_session=False))
    if locked.rowcount != 1:
        raise HTTPException(503, "Audit checkpoint unavailable")
    last_id, last_hash = db.execute(select(AuditChainState.last_id, AuditChainState.last_hash).where(AuditChainState.id == 1)).one()
    tail = db.execute(select(AuditLog.id, AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1)).first()
    expected = (last_id, last_hash) if last_id else None
    if (tuple(tail) if tail else None) != expected or (last_id == 0 and last_hash != GENESIS_HASH):
        raise HTTPException(503, "Audit checkpoint mismatch")
    entry = AuditLog(id=last_id + 1, prev_hash=last_hash, actor_id=actor_id, action=action,
                     target_type=target_type, target_id=target_id, status=status,
                     client_ip=safe_context["client_ip"], user_agent=safe_context["user_agent"],
                     details_json=canonicalize(clean).decode("utf-8"), created_at=datetime.now(timezone.utc))
    entry.entry_hash = compute_entry_hash(entry)
    db.add(entry)
    db.flush()
    db.execute(update(AuditChainState).where(AuditChainState.id == 1)
               .values(last_id=entry.id, last_hash=entry.entry_hash).execution_options(synchronize_session=False))
    return entry


def log_access_denied(db, actor_id, target_type, target_id, *, reason="OWNER_MISMATCH"):
    """Retain the denial after discarding any uncommitted business changes."""
    if reason == "RESOURCE_UNAVAILABLE":
        try:
            target_id = str(UUID(str(target_id)))
        except (ValueError, TypeError, AttributeError):
            target_id = None
    db.rollback()
    try:
        action = "ACCESS_DENIED_ROLE" if reason == "ROLE_REQUIRED" else "ACCESS_DENIED_IDOR"
        append_audit(db, action, actor_id=actor_id, target_type=target_type,
                     target_id=target_id, status="DENIED", details={"reason": reason})
        db.commit()
    except BaseException:
        db.rollback()
        raise


@dataclass(frozen=True)
class AuditChainVerification:
    valid: bool
    checked_entries: int
    error_id: int | None = None
    reason: str | None = None


def verify_audit_chain(db):
    """Check a consistent database snapshot, returning the first corrupt ID."""
    begin_read_snapshot(db)
    head = db.execute(select(AuditChainState.last_id, AuditChainState.last_hash).where(AuditChainState.id == 1)).first()
    if head is None:
        return AuditChainVerification(False, 0, reason="CHECKPOINT_MISSING")
    previous = GENESIS_HASH
    checked = 0
    # Read columns instead of the identity map so earlier ORM reads cannot mask tampering.
    rows = db.execute(select(*AuditLog.__table__.columns).order_by(AuditLog.id).execution_options(yield_per=200))
    for row in rows:
        entry = AuditLog(**row._mapping)
        if entry.id != checked + 1:
            return AuditChainVerification(False, checked, checked + 1, "ENTRY_MISSING")
        if entry.prev_hash != previous:
            return AuditChainVerification(False, checked, entry.id, "PREVIOUS_HASH_MISMATCH")
        try:
            computed = compute_entry_hash(entry)
        except (ValueError, TypeError, UnicodeError, AttributeError, RecursionError):
            return AuditChainVerification(False, checked, entry.id, "INVALID_ENTRY")
        if computed != entry.entry_hash:
            return AuditChainVerification(False, checked, entry.id, "ENTRY_HASH_MISMATCH")
        previous = entry.entry_hash
        checked += 1
    if checked != head.last_id or previous != head.last_hash:
        return AuditChainVerification(False, checked, checked + 1, "CHECKPOINT_MISMATCH")
    return AuditChainVerification(True, checked)


def begin_read_snapshot(db):
    """Keep related admin reads on the same SQLite snapshot."""
    connection = db.connection()
    if connection.dialect.name == "sqlite" and not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql("BEGIN")
