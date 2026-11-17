"""Private review evidence and one-use proof of current key possession."""
import base64
from datetime import datetime, timedelta, timezone
import secrets
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from fastapi import HTTPException
from sqlalchemy import select, update, func

from backend.app.crypto.jcs import canonicalize, parse_strict_json
from backend.app.models.certificate import IdentityReview, PossessionChallenge
from backend.app.services.audit_service import append_audit
from backend.app.services.certificate_service import owned_certificate, utc
from backend.app.services.pki_verification import inspect_certificate


def review_dto(row):
    return dict(id=row.id, user_id=row.user_id, claims=parse_strict_json(row.claims_json), status=row.status,
        reviewer_id=row.reviewer_id, reviewed_at=utc(row.reviewed_at) if row.reviewed_at else None,
        reason=row.reason, created_at=utc(row.created_at))


def request_review(db, user_id, req):
    # Acquire a writer before checking the pending-request limit.
    db.rollback()
    try:
        db.connection().exec_driver_sql('BEGIN IMMEDIATE')
        if db.scalar(select(IdentityReview.id).where(IdentityReview.user_id == user_id, IdentityReview.status == 'PENDING')):
            raise HTTPException(409, 'IDENTITY_REVIEW_PENDING')
        row = IdentityReview(id=str(uuid.uuid4()), user_id=user_id, claims_json=canonicalize(req.model_dump()).decode())
        db.add(row)
        db.commit()
        return review_dto(row)
    except Exception:
        db.rollback()
        raise


def decide(db, reviewer_id, review_id, req):
    row = db.get(IdentityReview, review_id)
    if row is None:
        raise HTTPException(404, 'Review unavailable')
    if row.user_id == reviewer_id:
        raise HTTPException(409, 'SELF_REVIEW_FORBIDDEN')
    try:
        result = db.execute(update(IdentityReview).where(IdentityReview.id == review_id, IdentityReview.status == 'PENDING')
            .values(status=req.status, reviewer_id=reviewer_id, reviewed_at=datetime.now(timezone.utc), reason=req.reason)
            .execution_options(synchronize_session=False))
        if result.rowcount != 1:
            db.rollback()
            row = db.get(IdentityReview, review_id, populate_existing=True)
            if row.status != req.status or row.reason != req.reason or row.reviewer_id != reviewer_id:
                raise HTTPException(409, 'IDENTITY_REVIEW_ALREADY_DECIDED')
            return review_dto(row)
        append_audit(db, 'IDENTITY_REVIEW', actor_id=reviewer_id, target_type='IDENTITY_REVIEW', target_id=review_id,
            details={'outcome': req.status})
        db.commit()
        return review_dto(db.get(IdentityReview, review_id, populate_existing=True))
    except Exception:
        db.rollback()
        raise


def possession_challenge(db, user, certificate_id):
    cert = owned_certificate(db, user, certificate_id)
    if cert.user_id != user.id:
        raise HTTPException(404, 'Certificate unavailable')
    if not inspect_certificate(db, cert.certificate_pem)['verified']:
        raise HTTPException(409, 'CERTIFICATE_UNAVAILABLE')
    now = datetime.now(timezone.utc)
    db.query(PossessionChallenge).filter(PossessionChallenge.expires_at <= now).delete(synchronize_session=False)
    count = db.scalar(select(func.count()).select_from(PossessionChallenge).where(
        PossessionChallenge.user_id == user.id, PossessionChallenge.is_used.is_(False)))
    if count >= 5:
        db.rollback()
        raise HTTPException(429, 'Too many possession challenges')
    challenge_id = str(uuid.uuid4())
    payload = dict(context='DOCSIGN_VERIFY_POSSESSION_V1', purpose='VERIFY_POSSESSION', challenge_id=challenge_id,
        nonce=secrets.token_urlsafe(32), user_id=user.id, certificate_sha256=cert.fingerprint)
    expires = now + timedelta(minutes=5)
    db.add(PossessionChallenge(id=challenge_id, user_id=user.id, certificate_id=cert.id,
        payload_json=canonicalize(payload).decode(), expires_at=expires))
    db.commit()
    return dict(challenge_id=challenge_id, payload=payload, expires_at=expires)


def verify_possession(db, user, req):
    row = db.get(PossessionChallenge, req.challenge_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(404, 'Challenge unavailable')
    cert = owned_certificate(db, user, row.certificate_id)
    payload = parse_strict_json(row.payload_json)
    if payload.get('context') != 'DOCSIGN_VERIFY_POSSESSION_V1' or payload.get('certificate_sha256') != cert.fingerprint:
        raise HTTPException(409, 'CHALLENGE_BINDING_INVALID')
    try:
        signature = base64.b64decode(req.signature_b64, validate=True)
        if len(signature) != 384 or base64.b64encode(signature).decode() != req.signature_b64:
            raise ValueError('Invalid signature')
        x509.load_pem_x509_certificate(cert.certificate_pem.encode()).public_key().verify(signature,
            canonicalize(payload), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    except Exception:
        raise HTTPException(422, 'POSSESSION_PROOF_INVALID') from None
    try:
        consumed = db.execute(update(PossessionChallenge).where(PossessionChallenge.id == row.id,
            PossessionChallenge.is_used.is_(False), func.julianday(PossessionChallenge.expires_at) > func.julianday('now'))
            .values(is_used=True).execution_options(synchronize_session=False))
        if consumed.rowcount != 1:
            raise HTTPException(409, 'CHALLENGE_USED_OR_EXPIRED')
        result = inspect_certificate(db, cert.certificate_pem)
        if not result['verified']:
            raise HTTPException(409, 'CERTIFICATE_UNAVAILABLE')
        append_audit(db, 'CERTIFICATE_VERIFY', actor_id=user.id, target_type='CERTIFICATE', target_id=cert.id,
            details={'fingerprint': cert.fingerprint, 'outcome': 'POSSESSION_VERIFIED'})
        db.commit()
        return {**result, 'possession': 'VERIFIED', 'possession_verified_at': datetime.now(timezone.utc)}
    except Exception:
        db.rollback()
        raise
