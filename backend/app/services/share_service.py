import base64
import hashlib
import logging
import re
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin

from fastapi import HTTPException
from sqlalchemy import select, update, insert, literal
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.document import Document, DocumentVersion, VersionState
from backend.app.models.key import PublicKey
from backend.app.models.share import ShareToken
from backend.app.models.signature import Signature
from backend.app.schemas.share import (
    PublicShareVerificationResponse,
    PublicVerificationDimensions,
    PublicVerificationSummary,
    ShareCreateResponse,
)
from backend.app.services.verification_service import VerificationService
from backend.app.services.audit_service import append_audit, log_access_denied
from backend.app.services.pki_verification import signing_certificate
from backend.app.storage.base import IStorageService

logger = logging.getLogger("docsign.share")

TOKEN_REGEX = re.compile(r"^[A-Za-z0-9_-]{43}$")


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def generate_share_token() -> str:
    """Generates a high-entropy 256-bit unguessable Base64URL token (43 chars, no padding)."""
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def token_digest(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def validate_canonical_token(raw_token: str) -> None:
    """
    Validates that raw_token strictly conforms to canonical Base64URL encoding
    of 32 cryptographically secure random bytes without padding.
    Rejects any uncanonical bits, malformed characters, or improper length.
    Never logs raw_token.
    """
    if not isinstance(raw_token, str) or len(raw_token) != 43 or not TOKEN_REGEX.match(raw_token):
        raise HTTPException(404, "Liên kết không tồn tại")
    
    # 43 chars requires 1 '=' to align to 44 bytes for standard base64 decoding
    padded = raw_token + "="
    try:
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        raise HTTPException(404, "Liên kết không tồn tại")
    
    if len(decoded) != 32:
        raise HTTPException(404, "Liên kết không tồn tại")
    
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != raw_token:
        raise HTTPException(404, "Liên kết không tồn tại")


def create_share(
    db: Session,
    user_id: str,
    version_id: str,
    expires_in_days: int | None,
    label: str | None,
    storage: IStorageService,
) -> ShareCreateResponse:
    # 1. Expiry bounds validation
    if expires_in_days is None:
        days = settings.SHARE_DEFAULT_EXPIRY_DAYS
    else:
        if expires_in_days < 1 or expires_in_days > settings.SHARE_MAX_EXPIRY_DAYS:
            raise HTTPException(
                422,
                f"Thời hạn chia sẻ không hợp lệ: phải từ 1 đến {settings.SHARE_MAX_EXPIRY_DAYS} ngày"
            )
        days = expires_in_days

    # 2. Authenticate & Authorize owner
    version = db.scalar(
        select(DocumentVersion)
        .join(Document, DocumentVersion.document_id == Document.id)
        .where(DocumentVersion.id == version_id, Document.owner_id == user_id)
    )
    if version is None:
        log_access_denied(db, user_id, "VERSION", version_id, reason="RESOURCE_UNAVAILABLE")
        raise HTTPException(404, "Không tìm thấy phiên bản tài liệu hoặc bạn không có quyền truy cập")

    # 3. Version state & Signature existence check
    if version.state != VersionState.SIGNED:
        raise HTTPException(409, "Chỉ có thể chia sẻ phiên bản tài liệu đã ký số hoàn tất")

    signature = db.scalar(select(Signature).where(Signature.version_id == version.id))
    if signature is None:
        raise HTTPException(409, "Phiên bản chưa có chữ ký số hợp lệ trong hệ thống")

    verified_ids = (version.id, version.document_id, signature.id, signature.key_id, signature.manifest_sha256)

    # 4. Phase 5 Verification Engine Gate (Read-only, no write lock held)
    result = VerificationService.verify_shared(db, version, signature, storage)

    # 5. Strict verification criteria for share issuance
    if result.evidence_consistency != "CONSISTENT":
        raise HTTPException(422, "Dữ liệu bằng chứng chữ ký số không nhất quán với tài liệu")

    dims = result.results
    if signature.signature_format == 'DETACHED_JCS_V2' and result.summary_status != 'VERIFIED':
        raise HTTPException(422, 'Chứng chỉ hoặc ràng buộc danh tính không còn hợp lệ')
    cv = getattr(dims.cryptographic_validity, "value", str(dims.cryptographic_validity))
    if cv != "VALID":
        raise HTTPException(422, "Chữ ký số không hợp lệ về mặt toán học mật mã")

    di = getattr(dims.document_integrity, "value", str(dims.document_integrity))
    if di != "UNCHANGED":
        raise HTTPException(422, "Tệp PDF không còn nguyên bản hoặc đã bị sửa đổi/thiếu tệp lưu trữ")

    # Issuance policy: Signing key must be currently ACTIVE at issuance time
    krs = getattr(dims.key_revocation_status, "value", str(dims.key_revocation_status))
    if krs != "ACTIVE":
        raise HTTPException(422, "Chính sách phát hành: Khóa ký đã bị thu hồi, không thể tạo liên kết chia sẻ mới")

    ko = getattr(dims.key_ownership, "value", str(dims.key_ownership))
    if ko != "VERIFIED_POP" or dims.key_registry_binding != "MATCHED":
        raise HTTPException(422, "Khóa ký chưa được xác thực quyền sở hữu (Proof-of-Possession)")

    # 6. Generate 256-bit entropy token
    raw_token = generate_share_token()
    token_hash_val = token_digest(raw_token)
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(days=days)

    # Verification performs no work while a writer is held. End any read
    # transaction before taking SQLite's RESERVED writer lock, then perform
    # one conditional insert against fresh columns (never cached ORM state).
    version_id, document_id, signature_id, key_id, manifest_hash = verified_ids
    share_id = str(uuid.uuid4())
    clean_label = label.strip() if label and label.strip() else None
    db.rollback()
    try:
        db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        if signature.signature_format == 'DETACHED_JCS_V2':
            from backend.app.crypto.jcs import parse_strict_json
            manifest = parse_strict_json(signature.canonical_manifest_json)
            signing_certificate(db, user_id, key_id, certificate_sha256=manifest['certificate_sha256'])
        eligible = (
            select(literal(share_id), DocumentVersion.id, literal(user_id),
                   literal(token_hash_val), literal(now), literal(expires_at), literal(clean_label))
            .select_from(DocumentVersion)
            .join(Document, Document.id == DocumentVersion.document_id)
            .join(Signature, Signature.version_id == DocumentVersion.id)
            .join(PublicKey, PublicKey.id == Signature.key_id)
            .where(DocumentVersion.id == version_id,
                   DocumentVersion.document_id == document_id,
                   Document.owner_id == user_id,
                   DocumentVersion.state == VersionState.SIGNED,
                   Signature.id == signature_id, Signature.key_id == key_id,
                   Signature.signer_id == user_id, Signature.manifest_sha256 == manifest_hash,
                   PublicKey.user_id == user_id, PublicKey.status == "ACTIVE",
                   PublicKey.revoked_at.is_(None))
        )
        inserted = db.execute(insert(ShareToken).from_select(
            ["id", "version_id", "created_by", "token_hash", "created_at", "expires_at", "label"],
            eligible, include_defaults=False))
        if inserted.rowcount != 1:
            raise HTTPException(422, "Quyền sở hữu, bằng chứng hoặc trạng thái khóa đã thay đổi; không phát hành liên kết")
        append_audit(db, "SHARE_QR", actor_id=user_id, target_type="SHARE", target_id=share_id,
                     details={"version_id": version_id, "expires_in_days": days})
        db.commit()
    except HTTPException:
        db.rollback()
        raise
    except Exception:
        db.rollback()
        raise HTTPException(503, "Không thể lưu trữ liên kết chia sẻ trong cơ sở dữ liệu")

    # 8. Build share URL
    base = settings.PUBLIC_APP_BASE_URL.rstrip("/") + "/"
    share_url = urljoin(base, f"verify/share/{raw_token}")

    return ShareCreateResponse(
        id=share_id,
        version_id=version_id,
        share_url=share_url,
        expires_at=expires_at,
        label=clean_label,
    )


def revoke_share(db: Session, user_id: str, share_id: str) -> None:
    """
    Revokes a share token with idempotent semantics.
    Enforces document ownership or token creator authorization.
    """
    row = db.execute(
        select(ShareToken.id, ShareToken.revoked_at, Document.owner_id, ShareToken.created_by)
        .join(DocumentVersion, ShareToken.version_id == DocumentVersion.id)
        .join(Document, DocumentVersion.document_id == Document.id)
        .where(ShareToken.id == share_id)
    ).first()

    if row is None:
        log_access_denied(db, user_id, "SHARE", share_id, reason="RESOURCE_UNAVAILABLE")
        raise HTTPException(404, "Không tìm thấy liên kết chia sẻ")

    s_id, s_revoked_at, doc_owner_id, s_created_by = row
    if user_id != doc_owner_id and user_id != s_created_by:
        log_access_denied(db, user_id, "SHARE", share_id)
        raise HTTPException(404, "Không tìm thấy liên kết chia sẻ")

    # Idempotent: already revoked
    if s_revoked_at is not None:
        return

    now = datetime.now(timezone.utc)
    res = db.execute(
        update(ShareToken)
        .where(ShareToken.id == share_id, ShareToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    if res.rowcount == 1:
        append_audit(db, "SHARE_REVOKE", actor_id=user_id, target_type="SHARE", target_id=share_id)
    db.commit()

    if res.rowcount != 1:
        # Check if concurrent request already completed revocation
        fresh_revoked = db.execute(
            select(ShareToken.revoked_at).where(ShareToken.id == share_id)
        ).scalar()
        if fresh_revoked is None:
            raise HTTPException(404, "Không tìm thấy liên kết chia sẻ")


def verify_share(
    db: Session,
    raw_token: str,
    storage: IStorageService,
    client_ip: str | None = None,
) -> PublicShareVerificationResponse:
    # 1. Canonical Base64URL validation
    validate_canonical_token(raw_token)

    # 2. Initial hash lookup
    digest = token_digest(raw_token)
    share = db.scalar(select(ShareToken).where(ShareToken.token_hash == digest))
    if share is None or share.revoked_at is not None:
        raise HTTPException(404, "Liên kết không tồn tại")

    now = datetime.now(timezone.utc)
    if _utc(share.expires_at) <= now:
        raise HTTPException(410, "Liên kết đã hết hạn")

    version = db.scalar(
        select(DocumentVersion).join(Document).where(DocumentVersion.id == share.version_id)
    )
    signature = db.scalar(select(Signature).where(Signature.version_id == share.version_id))
    if version is None or signature is None or version.state != VersionState.SIGNED:
        raise HTTPException(404, "Liên kết không tồn tại")

    # 3. Execute Verification Engine
    result = VerificationService.verify_shared(db, version, signature, storage)

    # 4. Stale ORM state prevention: Re-check scalar columns directly from database
    recheck = db.execute(
        select(ShareToken.revoked_at, ShareToken.expires_at)
        .where(ShareToken.id == share.id)
    ).first()

    if recheck is None or recheck[0] is not None:
        raise HTTPException(404, "Liên kết không tồn tại")

    if _utc(recheck[1]) <= datetime.now(timezone.utc):
        raise HTTPException(410, "Liên kết đã hết hạn")

    # 5. Sanitize and allowlist warnings (strip internal paths or error traces)
    allowed_warnings = [
        w for w in result.warnings
        if not any(sub in w for sub in ["/data/", "\\", "line ", "Traceback", "sqlite", ".db", "Error:"])
    ]

    dims = result.results
    raw_cv = getattr(dims.cryptographic_validity, "value", str(dims.cryptographic_validity))
    raw_di = getattr(dims.document_integrity, "value", str(dims.document_integrity))
    raw_ko = getattr(dims.key_ownership, "value", str(dims.key_ownership))
    raw_ct = getattr(dims.certificate_trust, "value", str(dims.certificate_trust))
    raw_krs = getattr(dims.key_revocation_status, "value", str(dims.key_revocation_status))
    raw_ts = (
        dims.declared_timestamp.isoformat()
        if getattr(dims, "declared_timestamp", None)
        else (dims.server_timestamp.isoformat() if getattr(dims, "server_timestamp", None) else None)
    )
    raw_tl = getattr(dims.timestamp_trust_level, "value", str(dims.timestamp_trust_level))

    public_dims = PublicVerificationDimensions(
        **{name: getattr(dims, name) for name in ('certificate_binding', 'certificate_chain', 'certificate_validity',
            'certificate_revocation', 'identity_binding', 'identity_assurance', 'trust_scope')},
        cryptographic_validity=raw_cv,
        document_integrity=raw_di,
        key_ownership=raw_ko,
        certificate_trust=raw_ct,
        key_revocation_status=raw_krs,
        declared_timestamp=raw_ts,
        verification_time=dims.verification_time,
        timestamp_trust_level=raw_tl,
        trusted_timestamp=dims.trusted_timestamp,
        timestamp_status=dims.timestamp_status,
        timestamp_scope=dims.timestamp_scope,
    )

    summary_val = getattr(result.summary_status, "value", str(result.summary_status))
    public_summary = PublicVerificationSummary(
        summary_status=summary_val,
        evidence_consistency=result.evidence_consistency,
        results=public_dims,
        warnings=allowed_warnings,
        warning_codes=result.warning_codes,
    )

    return PublicShareVerificationResponse(
        title=version.document.title,
        version_no=version.version_no,
        original_filename=version.original_filename,
        expires_at=_utc(recheck[1]),
        verified_at=datetime.now(timezone.utc),
        signer_fingerprint=result.signer_fingerprint,
        results=public_summary,
    )
