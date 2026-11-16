import base64
import hashlib
import json
import re
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException, status
from sqlalchemy import select, and_, func, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from backend.app.models.enums import KeyStatus
from backend.app.models.key import PublicKey, SigningChallenge
from backend.app.schemas.key import ChallengeCreateRequest, ChallengeResponse, KeyRegisterRequest, PublicKeyResponse
from backend.app.services.audit_service import append_audit, log_access_denied


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def canonicalize_pop_payload(
    schema_version: int,
    purpose: str,
    challenge_id: str,
    challenge_nonce: str,
    user_id: str,
    algorithm: str,
    fingerprint: str
) -> bytes:
    """PoP schema v1 only: seven fixed fields, ASCII identifiers, UTF-8 JSON.

    Field order is alphabetical, separators are ',' and ':', with no whitespace.
    This is not a general RFC 8785 implementation.
    """
    payload = {
        "algorithm": algorithm,
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
        "fingerprint": fingerprint,
        "purpose": purpose,
        "schema_version": schema_version,
        "user_id": user_id,
    }
    if type(schema_version) is not int or schema_version != 1:
        raise ValueError('Unsupported PoP schema version')
    if algorithm != 'RSA-PSS-3072' or purpose != 'REGISTER_KEY':
        raise ValueError('Unsupported PoP algorithm or purpose')
    for field in ('challenge_id', 'user_id'):
        if not isinstance(payload[field], str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', payload[field]):
            raise ValueError('Invalid PoP identifier')
    if not isinstance(challenge_nonce, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,128}', challenge_nonce):
        raise ValueError('Invalid PoP nonce')
    if not isinstance(fingerprint, str) or not re.fullmatch(r'[a-f0-9]{64}', fingerprint):
        raise ValueError('Invalid PoP fingerprint')
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")



class KeyService:
    @staticmethod
    def create_signing_challenge(
        db: Session,
        user_id: str,
        req: ChallengeCreateRequest
    ) -> ChallengeResponse:
        now = utc_now()

        # Clean up expired challenges for this user
        db.query(SigningChallenge).filter(
            SigningChallenge.user_id == user_id,
            SigningChallenge.expires_at <= now
        ).delete(synchronize_session=False)

        # Rate limiting: limit pending unused challenges per user to 5
        pending_count = db.scalar(
            select(func.count(SigningChallenge.id)).where(
                SigningChallenge.user_id == user_id,
                SigningChallenge.is_used == False,
                SigningChallenge.expires_at > now
            )
        )
        if pending_count and pending_count >= 5:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Quá nhiều yêu cầu challenge chưa hoàn tất. Vui lòng thử lại sau vài phút."
            )

        # Validate required fingerprint binding
        if not req.fingerprint:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Challenge bắt buộc phải ràng buộc với fingerprint của Public Key"
            )

        # Generate CSPRNG 32 bytes (256-bit entropy) url-safe base64 string
        nonce = secrets.token_urlsafe(32)
        ttl = timedelta(minutes=5)
        expires_at = now + ttl

        challenge = SigningChallenge(
            id=str(uuid.uuid4()),
            user_id=user_id,
            challenge_nonce=nonce,
            purpose=req.purpose,
            expected_algorithm=req.algorithm,
            expected_fingerprint=req.fingerprint.lower(),
            is_used=False,
            expires_at=expires_at,
            created_at=now
        )
        db.add(challenge)
        db.commit()
        db.refresh(challenge)

        return ChallengeResponse(
            challenge_id=challenge.id,
            challenge_nonce=challenge.challenge_nonce,
            expires_at=challenge.expires_at,
            purpose=challenge.purpose,
            expected_algorithm=challenge.expected_algorithm,
            expected_fingerprint=challenge.expected_fingerprint
        )

    @staticmethod
    def register_public_key(
        db: Session,
        user_id: str,
        req: KeyRegisterRequest
    ) -> PublicKeyResponse:
        now = utc_now()

        # 1. Parse PEM and validate cryptographic properties
        try:
            public_key = serialization.load_pem_public_key(req.public_key_pem.encode("utf-8"))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Định dạng PEM không thể nạp: {str(e)}"
            )

        # 2. Enforce algorithm & key size
        if req.algorithm == "RSA-PSS-3072":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Khóa công khai không phải là RSA Public Key"
                )
            if public_key.key_size != 3072:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Kích thước khóa RSA ({public_key.key_size}-bit) không đạt chuẩn yêu cầu bảo mật 3072-bit"
                )
            if public_key.public_numbers().e != 65537:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Số mũ công khai e phải bằng 65537"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Thuật toán '{req.algorithm}' chưa được hỗ trợ"
            )

        # 3. Export canonical SPKI DER and compute exact SHA-256 fingerprint
        spki_der = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        computed_fingerprint = hashlib.sha256(spki_der).hexdigest().lower()

        # 4. Fetch and validate Signing Challenge first (prevents probe attacks and detects replay immediately)
        challenge = db.scalar(
            select(SigningChallenge).where(SigningChallenge.id == req.challenge_id)
        )
        if not challenge:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signing challenge không tồn tại"
            )

        if challenge.user_id != user_id:
            log_access_denied(db, user_id, "CHALLENGE", challenge.id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Challenge không thuộc về tài khoản hiện tại (phòng chống cross-user replay)"
            )

        if challenge.is_used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Challenge này đã được sử dụng trước đó (Replay attack prevented)"
            )

        exp = ensure_utc(challenge.expires_at)
        if exp is not None and exp <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signing challenge đã hết hạn. Vui lòng xin cấp challenge mới."
            )

        if challenge.purpose != "REGISTER_KEY":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Mục đích challenge không phù hợp"
            )

        if challenge.expected_algorithm != req.algorithm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Thuật toán không khớp với challenge (Kỳ vọng: {challenge.expected_algorithm}, Nhận: {req.algorithm})"
            )

        if not challenge.expected_fingerprint or challenge.expected_fingerprint.lower() != computed_fingerprint:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Fingerprint của khóa không khớp với fingerprint đã đăng ký trong challenge"
            )

        # 5. Check for duplicate fingerprint in database
        existing_key = db.scalar(
            select(PublicKey).where(PublicKey.fingerprint == computed_fingerprint)
        )
        if existing_key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Khóa công khai với fingerprint '{computed_fingerprint}' đã tồn tại trong hệ thống"
            )

        # 6. Reconstruct canonical PoP payload and verify signature (CPU-heavy, executed BEFORE DB write lock)
        pop_payload_bytes = canonicalize_pop_payload(
            schema_version=1,
            purpose="REGISTER_KEY",
            challenge_id=challenge.id,
            challenge_nonce=challenge.challenge_nonce,
            user_id=user_id,
            algorithm=req.algorithm,
            fingerprint=computed_fingerprint
        )

        try:
            signature_bytes = base64.b64decode(req.pop_signature_b64)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Chữ ký PoP không phải là chuỗi Base64 hợp lệ"
            )

        try:
            public_key.verify(
                signature_bytes,
                pop_payload_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=32
                ),
                hashes.SHA256()
            )
        except InvalidSignature:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Xác thực Proof-of-Possession thất bại: Chữ ký không hợp lệ với Public Key được cung cấp"
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Lỗi khi xác minh chữ ký PoP: {str(e)}"
            )

        # 7. Atomic Conditional UPDATE to consume challenge and insert key atomically
        # Prevents race conditions on SQLite without long locks.
        try:
            update_stmt = (
                update(SigningChallenge)
                .where(
                    SigningChallenge.id == challenge.id,
                    SigningChallenge.is_used == False,
                    SigningChallenge.user_id == user_id,
                    SigningChallenge.purpose == "REGISTER_KEY",
                    SigningChallenge.expected_algorithm == req.algorithm,
                    SigningChallenge.expected_fingerprint == computed_fingerprint,
                    # SQLite DateTime is stored as UTC without an offset. julianday
                    # evaluates the database clock when UPDATE actually executes.
                    func.julianday(SigningChallenge.expires_at) > func.julianday('now')
                )
                .values(is_used=True)
                .execution_options(synchronize_session=False)
            )
            result = db.execute(update_stmt)
            if result.rowcount != 1:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Challenge này đã được sử dụng trước đó hoặc đã hết hạn (Race condition prevented)"
                )

            # 8. Standardize PEM format
            normalized_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode("utf-8").strip()

            # 9. Create and persist PublicKey record
            new_key = PublicKey(
                id=str(uuid.uuid4()),
                user_id=user_id,
                algorithm=req.algorithm,
                spki_pem=normalized_pem,
                fingerprint=computed_fingerprint,
                status=KeyStatus.ACTIVE,
                created_at=now
            )
            db.add(new_key)
            append_audit(db, "KEY_GENERATE", actor_id=user_id, target_type="KEY", target_id=new_key.id,
                         details={"algorithm": new_key.algorithm, "fingerprint": computed_fingerprint})
            db.commit()
            db.refresh(new_key)

            return PublicKeyResponse.model_validate(new_key)
        except HTTPException:
            raise
        except IntegrityError as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Xung đột dữ liệu: khóa đã đăng ký hoặc challenge không còn hợp lệ"
            )
        except OperationalError as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cơ sở dữ liệu đang bận, vui lòng thử lại sau"
            )
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Không thể đăng ký khóa; vui lòng thử lại"
            )

    @staticmethod
    def list_my_keys(db: Session, user_id: str) -> List[PublicKeyResponse]:
        keys = db.scalars(
            select(PublicKey)
            .where(PublicKey.user_id == user_id)
            .order_by(PublicKey.created_at.desc())
        ).all()
        return [PublicKeyResponse.model_validate(k) for k in keys]

    @staticmethod
    def revoke_key(db: Session, user_id: str, key_id: str) -> PublicKeyResponse:
        key = db.scalar(
            select(PublicKey).where(PublicKey.id == key_id)
        )
        if not key:
            log_access_denied(db, user_id, "KEY", key_id, reason="RESOURCE_UNAVAILABLE")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Không tìm thấy khóa công khai"
            )

        if key.user_id != user_id:
            log_access_denied(db, user_id, "KEY", key.id)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Bạn không có quyền thu hồi khóa của người dùng khác"
            )

        if key.status == KeyStatus.REVOKED:
            # Idempotent response
            return PublicKeyResponse.model_validate(key)

        changed = db.execute(update(PublicKey).where(
            PublicKey.id == key_id, PublicKey.user_id == user_id, PublicKey.status != KeyStatus.REVOKED
        ).values(status=KeyStatus.REVOKED, revoked_at=utc_now()).execution_options(synchronize_session=False))
        if changed.rowcount == 1:
            append_audit(db, "KEY_REVOKE", actor_id=user_id, target_type="KEY", target_id=key_id,
                         details={"fingerprint": key.fingerprint})
        db.commit()
        db.refresh(key)

        return PublicKeyResponse.model_validate(key)
