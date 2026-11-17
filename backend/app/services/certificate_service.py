"""Account certificate issuance, ownership, PoP and transactional lifecycle."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import secrets
import uuid

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError, OperationalError

from backend.app.core.config import settings
from backend.app.crypto.certificates import fingerprint, issue_leaf, load_ca, validate_leaf
from backend.app.crypto.jcs import canonicalize, parse_strict_json
from backend.app.models.certificate import Certificate, CertificateAuthority, CertificateChallenge, CertificateOperation, IdentityReview
from backend.app.models.enums import KeyStatus, UserRole, UserStatus
from backend.app.models.key import PublicKey
from backend.app.models.user import User
from backend.app.schemas.certificate import CertificateResponse
from backend.app.services.audit_service import append_audit, begin_read_snapshot, log_access_denied


def utc(value):
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def operation_identity(kind, request, idempotency_key):
    digest = hashlib.sha256(canonicalize({"kind": kind, "request": request})).hexdigest()
    token_hash = hashlib.sha256(idempotency_key.encode()).hexdigest()
    return kind, digest, token_hash


def find_operation(db, user_id, operation):
    kind, digest, token_hash = operation
    row = db.execute(select(CertificateOperation.kind, CertificateOperation.request_digest,
                            CertificateOperation.certificate_id, CertificateOperation.key_id).where(
        CertificateOperation.user_id == user_id, CertificateOperation.idempotency_hash == token_hash,
    )).first()
    if row is None:
        return None
    if row.kind != kind or row.request_digest != digest:
        raise HTTPException(409, "IDEMPOTENCY_CONFLICT")
    cert = db.get(Certificate, row.certificate_id, populate_existing=True)
    if cert is None or cert.user_id != user_id or cert.key_id != row.key_id:
        raise HTTPException(409, "CERTIFICATE_OPERATION_EVIDENCE_INVALID")
    return cert


def certificate_response(db, certificate):
    now = datetime.now(timezone.utc)
    issuer = db.execute(select(CertificateAuthority.trust_status, CertificateAuthority.compromised_at,
                               CertificateAuthority.not_after).where(CertificateAuthority.id == certificate.ca_id)).one()
    key = db.execute(select(PublicKey.status, PublicKey.revoked_at).where(PublicKey.id == certificate.key_id)).one()
    status = "ACTIVE"
    if certificate.revoked_at is not None or key.status == KeyStatus.REVOKED or key.revoked_at is not None:
        status = "REVOKED"
    elif issuer.trust_status != "TRUSTED" or issuer.compromised_at is not None:
        status = "CA_UNTRUSTED"
    elif now < utc(certificate.not_before):
        status = "NOT_YET_VALID"
    elif now >= min(utc(certificate.not_after), utc(issuer.not_after)):
        status = "EXPIRED"
    return CertificateResponse(**{column.name: getattr(certificate, column.name)
        for column in Certificate.__table__.columns if column.name != "identity_review_id"}, status=status,
        identity_assurance="ADMIN_REVIEWED" if certificate.identity_review_id else "ACCOUNT_BOUND",
        reviewed_at=(db.get(IdentityReview, certificate.identity_review_id).reviewed_at if certificate.identity_review_id else None))


def owned_certificate(db, user, certificate_id):
    certificate = db.get(Certificate, certificate_id, populate_existing=True)
    if certificate is None:
        raise HTTPException(404, "Certificate unavailable")
    if certificate.user_id != user.id and user.role != UserRole.ADMIN:
        log_access_denied(db, user.id, "CERTIFICATE", certificate.id)
        raise HTTPException(404, "Certificate unavailable")
    return certificate


def list_certificates(db, user_id, limit, offset, key_id=None):
    begin_read_snapshot(db)
    predicates = [Certificate.user_id == user_id] if user_id is not None else []
    if key_id is not None:
        predicates.append(Certificate.key_id == key_id)
    rows = db.scalars(select(Certificate).where(*predicates)
        .order_by(Certificate.issued_at.desc(), Certificate.id).limit(limit).offset(offset)).all()
    return {"items": [certificate_response(db, cert) for cert in rows],
            "total": db.scalar(select(func.count()).select_from(Certificate).where(*predicates)),
            "limit": limit, "offset": offset}


def owned_key(db, user_id, key_id):
    key = db.get(PublicKey, key_id, populate_existing=True)
    if key is None or key.user_id != user_id:
        log_access_denied(db, user_id, "KEY", key_id, reason="RESOURCE_UNAVAILABLE")
        raise HTTPException(404, "Key unavailable")
    if key.status != KeyStatus.ACTIVE or key.revoked_at is not None:
        raise HTTPException(409, "KEY_REVOKED")
    if key.algorithm != "RSA-PSS-3072":
        raise HTTPException(409, "CERTIFICATE_KEY_PROFILE_UNSUPPORTED")
    return key


def prepare_certificate(user_id, public_key):
    ca = load_ca()
    try:
        certificate = issue_leaf(ca, user_id, public_key)
        validate_leaf(certificate, ca.certificate, settings.CA_TRUSTED_ROOT_SHA256, user_id, public_key)
    except Exception:
        raise HTTPException(503, "PKI_CERTIFICATE_SIGNING_FAILED") from None
    return ca, certificate


def check_issuance_quota(db, user_id):
    recent = db.scalar(select(func.count()).select_from(Certificate).where(
        Certificate.user_id == user_id,
        Certificate.issued_at >= datetime.now(timezone.utc) - timedelta(days=1)))
    if recent >= settings.PKI_CERTIFICATES_PER_DAY:
        raise HTTPException(429, "CERTIFICATE_ISSUANCE_QUOTA")


def approved_identity(db, user_id):
    return db.scalar(select(IdentityReview).where(IdentityReview.user_id == user_id,
        IdentityReview.status == 'APPROVED').order_by(IdentityReview.reviewed_at.desc(), IdentityReview.id.desc()).limit(1))


def prepare_for_user(db, user_id, public):
    candidate = prepare_certificate(user_id, public)
    review = approved_identity(db, user_id)
    if review is None:
        return candidate
    ca, _ = candidate
    name = parse_strict_json(review.claims_json)['full_name']
    try:
        return ca, issue_leaf(ca, user_id, public, name), review.id
    except Exception:
        raise HTTPException(503, 'PKI_CERTIFICATE_SIGNING_FAILED') from None


def persist_certificate(db, user_id, key_id, candidate, operation):
    """Caller holds the SQLite writer through its conditional nonce UPDATE."""
    ca, leaf = candidate[:2]
    review_id = candidate[2] if len(candidate) == 3 else None
    if review_id is not None:
        current_review = approved_identity(db, user_id)
        if current_review is None or current_review.id != review_id:
            raise HTTPException(409, "IDENTITY_SNAPSHOT_CHANGED")
        from cryptography.x509.oid import NameOID
        if leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != parse_strict_json(current_review.claims_json)['full_name']:
            raise HTTPException(409, "IDENTITY_SNAPSHOT_CHANGED")
    now = datetime.now(timezone.utc)
    if db.scalar(select(User.status).where(User.id == user_id)) != UserStatus.ACTIVE:
        raise HTTPException(409, "ACCOUNT_INACTIVE")
    key = db.execute(select(PublicKey.user_id, PublicKey.status, PublicKey.revoked_at,
                            PublicKey.spki_pem, PublicKey.fingerprint, PublicKey.algorithm).where(PublicKey.id == key_id)).one()
    if (key.user_id != user_id or key.status != KeyStatus.ACTIVE or key.revoked_at is not None
            or key.algorithm != "RSA-PSS-3072"):
        raise HTTPException(409, "KEY_REVOKED_OR_OWNER_CHANGED")
    try:
        current_public = serialization.load_pem_public_key(key.spki_pem.encode())
        validate_leaf(leaf, ca.certificate, settings.CA_TRUSTED_ROOT_SHA256, user_id, current_public, now)
        if hashlib.sha256(current_public.public_bytes(serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest() != key.fingerprint:
            raise ValueError("Fingerprint mismatch")
    except Exception:
        raise HTTPException(409, "CERTIFICATE_FINAL_BINDING_INVALID") from None
    check_issuance_quota(db, user_id)
    if not leaf.not_valid_before_utc <= now < leaf.not_valid_after_utc:
        raise HTTPException(409, "CERTIFICATE_CANDIDATE_EXPIRED")
    ca_pem = ca.certificate.public_bytes(serialization.Encoding.PEM).decode()
    issuer = db.execute(select(CertificateAuthority.id, CertificateAuthority.certificate_pem,
        CertificateAuthority.issuance_enabled, CertificateAuthority.trust_status, CertificateAuthority.compromised_at
    ).where(CertificateAuthority.fingerprint == ca.fingerprint)).first()
    if issuer is None:
        record = CertificateAuthority(id=str(uuid.uuid4()), fingerprint=ca.fingerprint, certificate_pem=ca_pem,
            subject=ca.certificate.subject.rfc4514_string(), not_before=ca.certificate.not_valid_before_utc,
            not_after=ca.certificate.not_valid_after_utc)
        db.add(record)
        db.flush()
        issuer_id = record.id
    else:
        if (not issuer.issuance_enabled or issuer.trust_status != "TRUSTED"
                or issuer.compromised_at is not None or issuer.certificate_pem != ca_pem):
            raise HTTPException(409, "CA_ISSUANCE_UNAVAILABLE")
        issuer_id = issuer.id
    cert = Certificate(id=str(uuid.uuid4()), key_id=key_id, user_id=user_id, ca_id=issuer_id,
        serial=format(leaf.serial_number, "x"), fingerprint=fingerprint(leaf),
        certificate_pem=leaf.public_bytes(serialization.Encoding.PEM).decode(), subject=leaf.subject.rfc4514_string(),
        not_before=leaf.not_valid_before_utc, not_after=leaf.not_valid_after_utc, issued_at=now, identity_review_id=review_id)
    db.add(cert)
    db.flush()
    db.execute(update(PublicKey).where(PublicKey.id == key_id).values(current_certificate_id=cert.id)
               .execution_options(synchronize_session=False))
    kind, digest, token_hash = operation
    db.add(CertificateOperation(user_id=user_id, kind=kind, request_digest=digest,
                               idempotency_hash=token_hash, key_id=key_id, certificate_id=cert.id))
    append_audit(db, "CERTIFICATE_RENEW" if kind == "RENEW_CERT" else "CERTIFICATE_ISSUE",
                 actor_id=user_id, target_type="CERTIFICATE", target_id=cert.id,
                 details={"key_id": key_id, "fingerprint": cert.fingerprint})
    return cert


def create_challenge(db, user_id, request):
    if not settings.PKI_ENABLED:
        raise HTTPException(503, "PKI_DISABLED")
    key = owned_key(db, user_id, request.key_id)
    if request.purpose == "RENEW_CERT":
        cert = db.get(Certificate, request.certificate_id)
        if cert is None or cert.user_id != user_id or cert.key_id != key.id:
            raise HTTPException(404, "Certificate unavailable")
        if cert.revoked_at is not None:
            raise HTTPException(409, "CERTIFICATE_REVOKED")
    elif request.certificate_id is not None:
        raise HTTPException(422, "ISSUE_CERT expects no certificate_id")
    elif key.current_certificate_id is not None:
        raise HTTPException(409, "Use certificate renewal for a certified key")
    now = datetime.now(timezone.utc)
    # First write serializes the pending-challenge quota across workers.
    db.query(CertificateChallenge).filter(CertificateChallenge.user_id == user_id,
                                          CertificateChallenge.expires_at <= now).delete(synchronize_session=False)
    pending = db.scalar(select(func.count()).select_from(CertificateChallenge).where(
        CertificateChallenge.user_id == user_id, CertificateChallenge.is_used.is_(False)))
    if pending >= 5:
        db.rollback()
        raise HTTPException(429, "Too many pending certificate challenges")
    challenge_id = str(uuid.uuid4())
    payload = {"schema_version": 1, "context": "DOCSIGN_CERTIFICATE_POP_V1", "purpose": request.purpose,
        "challenge_id": challenge_id, "challenge_nonce": secrets.token_urlsafe(32), "user_id": user_id,
        "key_id": key.id, "fingerprint": key.fingerprint, "certificate_id": request.certificate_id}
    expires = now + timedelta(minutes=5)
    db.add(CertificateChallenge(id=challenge_id, user_id=user_id, key_id=key.id,
        certificate_id=request.certificate_id, purpose=request.purpose, payload_json=canonicalize(payload).decode(),
        expires_at=expires))
    db.commit()
    return {"challenge_id": challenge_id, "payload": payload, "expires_at": expires}


def issue_for_existing_key(db, user_id, request, purpose, certificate_id=None):
    operation = operation_identity(purpose, {**request.model_dump(), "certificate_id": certificate_id}, request.idempotency_key)
    previous = find_operation(db, user_id, operation)
    if previous is not None:
        return certificate_response(db, previous)
    challenge = db.get(CertificateChallenge, request.challenge_id, populate_existing=True)
    if (challenge is None or challenge.user_id != user_id or challenge.purpose != purpose
            or challenge.certificate_id != certificate_id or challenge.is_used
            or utc(challenge.expires_at) <= datetime.now(timezone.utc)):
        db.rollback()
        previous = find_operation(db, user_id, operation)
        if previous is not None:
            return certificate_response(db, previous)
        raise HTTPException(409, "CERTIFICATE_CHALLENGE_UNAVAILABLE")
    key = owned_key(db, user_id, challenge.key_id)
    try:
        public = serialization.load_pem_public_key(key.spki_pem.encode())
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise HTTPException(409, "KEY_EVIDENCE_INVALID") from None
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 3072 or public.public_numbers().e != 65537:
        raise HTTPException(409, "CERTIFICATE_KEY_PROFILE_UNSUPPORTED")
    canonical = canonicalize(parse_strict_json(challenge.payload_json))
    expected_fingerprint = hashlib.sha256(public.public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    payload = parse_strict_json(challenge.payload_json)
    if (payload.get("fingerprint") != expected_fingerprint or key.fingerprint != expected_fingerprint
            or payload.get("context") != "DOCSIGN_CERTIFICATE_POP_V1" or payload.get("purpose") != purpose
            or payload.get("user_id") != user_id or payload.get("key_id") != key.id
            or payload.get("challenge_id") != challenge.id or payload.get("certificate_id") != certificate_id):
        raise HTTPException(409, "CERTIFICATE_CHALLENGE_BINDING_INVALID")
    try:
        signature = base64.b64decode(request.pop_signature_b64, validate=True)
        if len(signature) != 384 or base64.b64encode(signature).decode() != request.pop_signature_b64:
            raise ValueError("Noncanonical signature")
        public.verify(signature, canonical, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    except (ValueError, InvalidSignature):
        raise HTTPException(422, "CERTIFICATE_POP_INVALID") from None
    check_issuance_quota(db, user_id)
    candidate = prepare_for_user(db, user_id, public)
    challenge_id, key_id = challenge.id, key.id
    try:
        conditions = [CertificateChallenge.id == challenge_id, CertificateChallenge.user_id == user_id,
            CertificateChallenge.key_id == key_id, CertificateChallenge.purpose == purpose,
            CertificateChallenge.payload_json == canonical.decode(), CertificateChallenge.is_used.is_(False),
            func.julianday(CertificateChallenge.expires_at) > func.julianday("now")]
        consumed = db.execute(update(CertificateChallenge).where(*conditions).values(is_used=True)
                              .execution_options(synchronize_session=False))
        if consumed.rowcount != 1:
            db.rollback()
            previous = find_operation(db, user_id, operation)
            if previous is not None:
                return certificate_response(db, previous)
            raise HTTPException(409, "CERTIFICATE_CHALLENGE_UNAVAILABLE")
        if purpose == "RENEW_CERT":
            active = db.scalar(select(Certificate.id).where(Certificate.id == certificate_id,
                Certificate.user_id == user_id, Certificate.key_id == key_id, Certificate.revoked_at.is_(None)))
            if active is None:
                raise HTTPException(409, "CERTIFICATE_REVOKED")
        elif db.scalar(select(PublicKey.current_certificate_id).where(PublicKey.id == key_id)) is not None:
            raise HTTPException(409, "Use certificate renewal for a certified key")
        cert = persist_certificate(db, user_id, key_id, candidate, operation)
        db.commit()
        return certificate_response(db, cert)
    except HTTPException:
        db.rollback()
        raise
    except (IntegrityError, OperationalError):
        db.rollback()
        previous = find_operation(db, user_id, operation)
        if previous is not None:
            return certificate_response(db, previous)
        raise HTTPException(503, "Certificate storage unavailable; retry the same request") from None
    except Exception:
        db.rollback()
        raise HTTPException(503, "Certificate issuance unavailable") from None


def revoke_certificates_for_key(db, key_id, actor_id):
    ids = db.scalars(select(Certificate.id).where(Certificate.key_id == key_id, Certificate.revoked_at.is_(None))).all()
    now = datetime.now(timezone.utc)
    db.execute(update(Certificate).where(Certificate.key_id == key_id, Certificate.revoked_at.is_(None))
               .values(revoked_at=now, revocation_reason="KEY_COMPROMISE").execution_options(synchronize_session=False))
    for certificate_id in ids:
        append_audit(db, "CERTIFICATE_REVOKE", actor_id=actor_id, target_type="CERTIFICATE", target_id=certificate_id)


def revoke_certificate(db, user, certificate_id, reason):
    certificate = owned_certificate(db, user, certificate_id)
    try:
        changed = db.execute(update(Certificate).where(Certificate.id == certificate.id, Certificate.revoked_at.is_(None))
            .values(revoked_at=datetime.now(timezone.utc), revocation_reason=reason).execution_options(synchronize_session=False))
        if changed.rowcount == 1:
            append_audit(db, "CERTIFICATE_REVOKE", actor_id=user.id, target_type="CERTIFICATE", target_id=certificate.id)
        db.commit()
        db.refresh(certificate)
        return certificate_response(db, certificate)
    except Exception:
        db.rollback()
        raise HTTPException(503, "Certificate revocation unavailable") from None
