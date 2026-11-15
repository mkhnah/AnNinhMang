import base64
import hashlib
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException, status
from sqlalchemy import select, func, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from backend.app.crypto.jcs import canonicalize
from backend.app.models.document import Document, DocumentVersion, VersionState
from backend.app.models.enums import KeyStatus
from backend.app.models.key import PublicKey
from backend.app.models.signature import Signature, SigningSession
from backend.app.schemas.signature import (
    SignedManifest,
    PrepareSignRequest,
    PrepareSignResponse,
    SignatureSubmitRequest,
    SignatureResponse,
)
from backend.app.storage.local import LocalStorageService


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SignatureService:
    @staticmethod
    def prepare_sign(
        db: Session,
        user_id: str,
        document_id: str,
        version_id: str,
        req: PrepareSignRequest,
        storage: LocalStorageService,
    ) -> PrepareSignResponse:
        now = utc_now()

        # 1. Ownership & Document Existence Check (IDOR defense: return 404)
        doc = db.scalar(
            select(Document).where(Document.id == document_id, Document.owner_id == user_id)
        )
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tài liệu không tồn tại hoặc bạn không có quyền truy cập"
            )

        # 2. Version Existence Check
        version = db.scalar(
            select(DocumentVersion).where(
                DocumentVersion.id == version_id,
                DocumentVersion.document_id == document_id
            )
        )
        if not version:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Phiên bản tài liệu không tồn tại"
            )

        # 3. Version State Gate & Single-Signature Policy
        if version.state == VersionState.SIGNED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Phiên bản tài liệu này đã được ký số thành công trước đó (Chính sách mỗi phiên bản chỉ có tối đa một chữ ký số)."
            )

        # Check if an existing signature record exists
        existing_sig = db.scalar(select(Signature).where(Signature.version_id == version.id))
        if existing_sig:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Phiên bản này đã có bản ghi chữ ký trong hệ thống."
            )

        # 4. Public Key Verification
        key = db.scalar(select(PublicKey).where(PublicKey.id == req.key_id))
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Khóa công khai không tồn tại trong hệ thống"
            )

        if key.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Khóa công khai không thuộc quyền sở hữu của tài khoản hiện tại"
            )

        if key.status != KeyStatus.ACTIVE or key.revoked_at is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Khóa công khai đã bị thu hồi (REVOKED). Không thể sử dụng để ký tài liệu mới."
            )

        # 5. Verify PDF file existence and disk SHA-256 integrity
        if not storage.exists(version.storage_key):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tệp PDF gốc không tồn tại trong kho lưu trữ dữ liệu"
            )

        with storage.get_file(version.storage_key) as stream:
            hasher = hashlib.sha256()
            while chunk := stream.read(65536):
                hasher.update(chunk)
            actual_sha256 = hasher.hexdigest().lower()

        if actual_sha256 != version.file_sha256.lower():
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Tính toàn vẹn của tệp PDF bị vi phạm: SHA-256 thực tế trên đĩa không khớp với cơ sở dữ liệu"
            )

        # 6. State Transition: Lock version to READY_TO_SIGN if currently DRAFT
        if version.state == VersionState.DRAFT:
            version.state = VersionState.READY_TO_SIGN
            version.locked_at = now
            db.commit()
            db.refresh(version)

        # 7. Clean up expired signing sessions for this user/version
        db.query(SigningSession).filter(
            SigningSession.version_id == version.id,
            SigningSession.expires_at <= now
        ).delete(synchronize_session=False)

        # 8. Rate Limiting: Limit pending active sessions to 5
        pending_sessions = db.scalar(
            select(func.count(SigningSession.id)).where(
                SigningSession.version_id == version.id,
                SigningSession.user_id == user_id,
                SigningSession.is_used == False,
                SigningSession.expires_at > now
            )
        )
        if pending_sessions and pending_sessions >= 5:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Quá nhiều phiên chuẩn bị ký đang hoạt động. Vui lòng hoàn tất hoặc chờ các phiên trước hết hạn."
            )

        # 9. Generate CSPRNG Nonce and Signing Timestamp
        nonce = secrets.token_urlsafe(32)
        signing_timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        # 10. Construct Strict SignedManifest Schema v1.0
        manifest = SignedManifest(
            manifest_version=1,
            document_version_id=version.id,
            document_sha256=version.file_sha256.lower(),
            key_id=key.id,
            signer_fingerprint=key.fingerprint.lower(),
            algorithm=key.algorithm,
            signing_nonce=nonce,
            signing_timestamp=signing_timestamp,
            signing_context="DOCSIGN_DOCUMENT_SIGNATURE_V1"
        )

        # 11. Canonicalize Manifest via RFC 8785 JCS
        canonical_bytes = canonicalize(manifest.model_dump())
        manifest_sha256 = hashlib.sha256(canonical_bytes).hexdigest().lower()

        # 12. Persist SigningSession (TTL = 5 minutes)
        expires_at = now + timedelta(minutes=5)
        signing_session = SigningSession(
            id=str(uuid.uuid4()),
            version_id=version.id,
            user_id=user_id,
            key_id=key.id,
            signing_nonce=nonce,
            manifest_sha256=manifest_sha256,
            canonical_manifest_json=canonical_bytes.decode("utf-8"),
            is_used=False,
            expires_at=expires_at,
            created_at=now
        )
        db.add(signing_session)
        db.commit()

        return PrepareSignResponse(
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            expires_at=expires_at
        )

    @staticmethod
    def submit_signature(
        db: Session,
        user_id: str,
        req: SignatureSubmitRequest,
        storage: LocalStorageService
    ) -> SignatureResponse:
        now = utc_now()

        # 1. Fetch DocumentVersion and verify ownership (IDOR defense)
        version = db.scalar(
            select(DocumentVersion).where(DocumentVersion.id == req.version_id)
        )
        if not version:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Phiên bản tài liệu không tồn tại"
            )

        doc = db.scalar(
            select(Document).where(Document.id == version.document_id, Document.owner_id == user_id)
        )
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tài liệu không tồn tại hoặc bạn không có quyền truy cập"
            )

        # 2. Check Version State Gate
        if version.state == VersionState.SIGNED:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Phiên bản tài liệu đã được ký số thành công trước đó (Single signature policy)"
            )

        if version.state != VersionState.READY_TO_SIGN:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Phiên bản ở trạng thái '{version.state.value}', không thể tiếp nhận chữ ký"
            )

        existing_sig = db.scalar(select(Signature).where(Signature.version_id == version.id))
        if existing_sig:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Chữ ký cho phiên bản này đã tồn tại trong hệ thống"
            )

        # 3. Fetch and Validate Public Key
        key = db.scalar(select(PublicKey).where(PublicKey.id == req.key_id))
        if not key:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Khóa công khai không tồn tại trong hệ thống"
            )

        if key.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Khóa công khai không thuộc quyền sở hữu của người dùng hiện tại"
            )

        if key.status != KeyStatus.ACTIVE or key.revoked_at is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Khóa công khai đã bị thu hồi (REVOKED). Chữ ký bị từ chối."
            )

        # 4. Cross-verify Manifest Metadata with System Ground Truth
        if req.manifest.document_version_id != version.id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Manifest document_version_id không khớp với phiên bản cần ký"
            )

        if req.manifest.key_id != key.id:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Manifest key_id không khớp với khóa công khai được chỉ định"
            )

        if req.manifest.signer_fingerprint.lower() != key.fingerprint.lower():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Manifest signer_fingerprint không khớp với fingerprint của khóa trong cơ sở dữ liệu"
            )

        if req.manifest.algorithm != key.algorithm:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Thuật toán manifest '{req.manifest.algorithm}' không khớp với khóa '{key.algorithm}'"
            )

        if req.manifest.signing_context != "DOCSIGN_DOCUMENT_SIGNATURE_V1":
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Signing context không đúng quy định (Chống cross-purpose signature)"
            )

        # 5. Fetch and Validate Signing Session (Nonce Lifecycle & Replay Defense)
        session = db.scalar(
            select(SigningSession).where(
                SigningSession.signing_nonce == req.manifest.signing_nonce
            )
        )
        if not session:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signing nonce không tồn tại hoặc không hợp lệ"
            )

        if session.version_id != version.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signing nonce không thuộc về phiên bản tài liệu này (Cross-document replay attack prevented)"
            )

        if session.user_id != user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Signing nonce không thuộc về tài khoản hiện tại"
            )

        if session.key_id != key.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Signing nonce không thuộc về khóa này (Cross-key replay attack prevented)"
            )

        if session.is_used:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Signing nonce này đã được sử dụng trước đó (Replay attack prevented)"
            )

        exp = ensure_utc(session.expires_at)
        if exp is not None and exp <= now:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phiên ký đã hết hạn. Vui lòng chuẩn bị phiên ký mới."
            )

        # 6. Stream & Re-verify Actual PDF SHA-256 on Disk
        if not storage.exists(version.storage_key):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tệp PDF gốc không tồn tại trong kho lưu trữ dữ liệu"
            )

        with storage.get_file(version.storage_key) as stream:
            hasher = hashlib.sha256()
            while chunk := stream.read(65536):
                hasher.update(chunk)
            actual_sha256 = hasher.hexdigest().lower()

        if actual_sha256 != version.file_sha256.lower() or actual_sha256 != req.manifest.document_sha256.lower():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Tính toàn vẹn của tệp PDF bị vi phạm: SHA-256 của file thực tế không khớp với manifest hoặc DB"
            )

        # 7. Reconstruct RFC 8785 Canonical Bytes & Verify Hash
        canonical_bytes = canonicalize(req.manifest.model_dump())
        computed_manifest_sha256 = hashlib.sha256(canonical_bytes).hexdigest().lower()

        if computed_manifest_sha256 != session.manifest_sha256.lower():
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Manifest canonical hash không khớp với phiên ký được cấp"
            )

        # 8. Decode Base64 Digital Signature
        try:
            signature_bytes = base64.b64decode(req.signature_b64, validate=True)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Chữ ký không phải chuỗi Base64 hợp lệ"
            )

        # 9. Cryptographically Verify Signature (CPU-intensive, executed before DB lock)
        try:
            pub_key = serialization.load_pem_public_key(key.spki_pem.encode("utf-8"))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Không thể nạp Public Key từ cơ sở dữ liệu"
            )

        if key.algorithm == "RSA-PSS-3072":
            if not isinstance(pub_key, rsa.RSAPublicKey) or pub_key.key_size != 3072:
                raise HTTPException(status_code=400, detail="Khóa không phải là RSA Public Key")
            try:
                pub_key.verify(
                    signature_bytes,
                    canonical_bytes,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    hashes.SHA256()
                )
            except InvalidSignature:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Xác thực chữ ký số RSA-PSS thất bại: Chữ ký không hợp lệ với Public Key và Manifest này"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Thuật toán '{key.algorithm}' chưa được hỗ trợ"
            )

        # 10. Atomic DB Write Transaction: Consume Nonce -> Insert Signature -> Update State to SIGNED
        try:
            # 10.1. Atomic conditional consumption of signing session
            update_session_stmt = (
                update(SigningSession)
                .where(
                    SigningSession.id == session.id,
                    SigningSession.is_used == False,
                    SigningSession.version_id == version.id,
                    SigningSession.user_id == user_id,
                    SigningSession.key_id == key.id,
                    SigningSession.signing_nonce == req.manifest.signing_nonce,
                    SigningSession.manifest_sha256 == computed_manifest_sha256,
                    SigningSession.canonical_manifest_json == canonical_bytes.decode("utf-8"),
                    func.julianday(SigningSession.expires_at) > func.julianday("now"),
                    select(PublicKey.id).where(
                        PublicKey.id == key.id, PublicKey.user_id == user_id,
                        PublicKey.status == KeyStatus.ACTIVE, PublicKey.revoked_at.is_(None),
                        PublicKey.fingerprint == req.manifest.signer_fingerprint,
                        PublicKey.spki_pem == key.spki_pem,
                        PublicKey.algorithm == req.manifest.algorithm,
                    ).exists(),
                    select(DocumentVersion.id).join(Document, Document.id == DocumentVersion.document_id).where(
                        DocumentVersion.id == version.id, Document.owner_id == user_id,
                        DocumentVersion.state == VersionState.READY_TO_SIGN,
                        DocumentVersion.file_sha256 == actual_sha256,
                        ~select(Signature.id).where(Signature.version_id == version.id).exists(),
                    ).exists(),
                )
                .values(is_used=True, consumed_at=func.current_timestamp())
                .execution_options(synchronize_session=False)
            )
            sess_res = db.execute(update_session_stmt)
            if sess_res.rowcount != 1:
                db.rollback()
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Signing nonce đã bị tiêu thụ hoặc xảy ra tranh chấp phiên ký (Race condition prevented)"
                )

            now = utc_now()
            # 10.2. Insert Signature Record
            new_signature = Signature(
                id=str(uuid.uuid4()),
                version_id=version.id,
                signer_id=user_id,
                key_id=key.id,
                algorithm=key.algorithm,
                canonical_manifest_json=canonical_bytes.decode("utf-8"),
                manifest_sha256=computed_manifest_sha256,
                signature_b64=req.signature_b64,
                signature_format="DETACHED_JCS_V1",
                signed_at=now,
                created_at=now
            )
            db.add(new_signature)
            db.flush()  # Flush so the SQLite trigger sees EXISTS (SELECT 1 FROM signatures WHERE version_id = NEW.id)

            # 10.3. Update DocumentVersion state to SIGNED (validated by SQLite trigger)
            version.state = VersionState.SIGNED
            db.commit()
            db.refresh(new_signature)

            return SignatureResponse.model_validate(new_signature)
        except HTTPException:
            raise
        except IntegrityError as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Xung đột toàn vẹn dữ liệu khi ghi chữ ký"
            )
        except OperationalError as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Cơ sở dữ liệu đang bận; hãy kiểm tra kết quả trước khi thử lại"
            )
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Không thể xác nhận kết quả lưu chữ ký; hãy kiểm tra lại trạng thái"
            )

    @staticmethod
    def get_signature_for_version(
        db: Session,
        user_id: str,
        document_id: str,
        version_id: str
    ) -> SignatureResponse:
        doc = db.scalar(
            select(Document).where(Document.id == document_id, Document.owner_id == user_id)
        )
        if not doc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Tài liệu không tồn tại hoặc bạn không có quyền truy cập"
            )

        sig = db.scalar(
            select(Signature)
            .join(DocumentVersion, Signature.version_id == DocumentVersion.id)
            .join(Document, DocumentVersion.document_id == Document.id)
            .where(Document.id == document_id, Document.owner_id == user_id,
                   DocumentVersion.id == version_id)
        )
        if not sig:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Phiên bản tài liệu chưa có chữ ký số"
            )

        return SignatureResponse.model_validate(sig)
