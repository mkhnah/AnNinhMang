import base64
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import BinaryIO, Optional
import uuid
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from sqlalchemy import select, delete
from sqlalchemy.orm import Session
from backend.app.core.config import settings
from backend.app.crypto.jcs import canonicalize_jcs, parse_strict_json
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.enums import KeyStatus
from backend.app.models.key import PublicKey
from backend.app.models.user import User
from backend.app.models.signature import Signature
from backend.app.models.verification import VerificationEvent
from backend.app.schemas.signature import SignedManifest
from backend.app.schemas.verify import (
    CertificateTrust, CryptographicValidity, DocumentIntegrity, KeyOwnership,
    KeyRevocationStatus, SignaturePackage, SixDimensionalResults, TimestampTrustLevel,
    VerificationMode, VerificationReportResponse, VerificationReportResult, VerificationResultResponse, VerificationSummaryStatus,
)
from backend.app.services.pdf_validator import validate_pdf
from backend.app.services import verification_receipts
from backend.app.storage.local import LocalStorageService
from backend.app.core.verification_limits import check_rate_limit, _ip_request_history

logger = logging.getLogger("docsign.verification")

def compute_stream_sha256(stream: BinaryIO) -> str:
    stream.seek(0)
    digest = hashlib.sha256()
    while chunk := stream.read(65536):
        digest.update(chunk)
    stream.seek(0)
    return digest.hexdigest()

def compute_bytes_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def get_spki_fingerprint(public_key) -> str:
    return hashlib.sha256(public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()

def parse_profile(pem: str):
    if len(pem.encode("utf-8")) > 4096:
        raise ValueError("PEM too large")
    lines = pem.strip().splitlines()
    if len(lines) < 3 or lines[0] != "-----BEGIN PUBLIC KEY-----" or lines[-1] != "-----END PUBLIC KEY-----":
        raise ValueError("Expected SPKI PEM")
    der = base64.b64decode("".join(lines[1:-1]), validate=True)
    try:
        public = serialization.load_der_public_key(der)
    except UnsupportedAlgorithm:
        raise ValueError("Unsupported SPKI algorithm")
    if public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != der:
        raise ValueError("Expected canonical SPKI DER")
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 3072 or public.public_numbers().e != 65537:
        raise ValueError("Expected RSA-PSS-3072/e65537")
    return public

def verify_rsa_pss(public, signature, canonical):
    public.verify(signature, canonical, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())

class VerificationService:
    @staticmethod
    def _evaluate_six_dimensions(db, manifest_dict, signature_b64, public_key_pem,
                                 computed_pdf_sha256, verification_mode,
                                 server_signed_at=None, key_record=None):
        warnings = []
        expected = manifest_dict.get("document_sha256")
        integrity = DocumentIntegrity.UNKNOWN
        if computed_pdf_sha256 and expected:
            integrity = DocumentIntegrity.UNCHANGED if computed_pdf_sha256 == expected else DocumentIntegrity.TAMPERED
            if integrity == DocumentIntegrity.TAMPERED:
                warnings.append("DOCUMENT_HASH_MISMATCH: PDF bytes do not match the signed manifest hash")
        elif not computed_pdf_sha256:
            warnings.append("DOCUMENT_UNAVAILABLE: No readable PDF bytes available")
        key_id = manifest_dict.get("key_id")
        declared_fp = manifest_dict.get("signer_fingerprint")
        registry = key_record
        if registry is None and db is not None and key_id:
            registry = db.scalar(select(PublicKey).where(PublicKey.id == key_id))
        binding = "UNREGISTERED" if db is not None and key_id else "UNKNOWN"
        if registry is not None:
            try:
                registry_public = parse_profile(registry.spki_pem)
                owner_exists = db is not None and db.scalar(select(User.id).where(User.id == registry.user_id)) is not None
                if (registry.id == key_id and registry.fingerprint == declared_fp == get_spki_fingerprint(registry_public) and owner_exists and registry.algorithm == "RSA-PSS-3072"):
                    binding = "MATCHED"
                    if public_key_pem is None:
                        public_key_pem = registry.spki_pem
                else:
                    binding = "MISMATCH"
            except (ValueError, TypeError):
                binding = "MISMATCH"
        if binding == "MISMATCH":
            warnings.append("KEY_REGISTRY_MISMATCH: Signed key ID/fingerprint does not match registry evidence")
        crypto = CryptographicValidity.UNVERIFIABLE
        fingerprint = None
        parsed = None
        if public_key_pem:
            try:
                parsed = parse_profile(public_key_pem)
                fingerprint = get_spki_fingerprint(parsed)
                if fingerprint != declared_fp:
                    crypto = CryptographicValidity.INVALID
                    warnings.append("KEY_FINGERPRINT_MISMATCH: Attached SPKI differs from the signed fingerprint")
                elif manifest_dict.get("algorithm") != "RSA-PSS-3072":
                    crypto = CryptographicValidity.INVALID
                    warnings.append("KEY_PROFILE_INVALID: Unsupported algorithm")
                else:
                    signature = base64.b64decode(signature_b64, validate=True)
                    if len(signature) != 384 or base64.b64encode(signature).decode() != signature_b64:
                        raise ValueError("Invalid Base64 signature/profile")
                    verify_rsa_pss(parsed, signature, canonicalize_jcs(manifest_dict))
                    crypto = CryptographicValidity.VALID
            except InvalidSignature:
                crypto = CryptographicValidity.INVALID
                warnings.append("SIGNATURE_INVALID: RSA-PSS verification failed")
            except (ValueError, TypeError):
                crypto = CryptographicValidity.INVALID
                warnings.append("KEY_PROFILE_INVALID: Invalid SPKI, RSA profile or signature encoding")
        else:
            warnings.append("PUBLIC_KEY_UNAVAILABLE: No bound public key available")
        matched = binding == "MATCHED" and fingerprint == declared_fp and parsed is not None
        ownership = KeyOwnership.VERIFIED_POP if matched else (KeyOwnership.UNVERIFIED if parsed else KeyOwnership.UNKNOWN)
        trust = CertificateTrust.SELF_REGISTERED if parsed else CertificateTrust.UNKNOWN
        revocation = KeyRevocationStatus.UNKNOWN
        revoked_at = None
        source = "UNAVAILABLE"
        if matched:
            source = "DOCSIGN_INTERNAL_DATABASE"
            revoked_at = registry.revoked_at
            if revoked_at is not None:
                revoked_at = revoked_at.replace(tzinfo=timezone.utc) if revoked_at.tzinfo is None else revoked_at.astimezone(timezone.utc)
            revocation = KeyRevocationStatus.REVOKED if registry.status == KeyStatus.REVOKED or revoked_at is not None else KeyRevocationStatus.ACTIVE
            if revocation == KeyRevocationStatus.REVOKED:
                warnings.append("KEY_REVOKED: Current revocation does not establish when the signature was created")
        warnings.append("IDENTITY_NOT_CA_VERIFIED: Mathematical validity and registry PoP do not establish legal identity")
        warnings.append("NO_TRUSTED_TIMESTAMP: No TSA evidence; declared signing time is not proven creation time")
        declared = manifest_dict.get("signing_timestamp")
        declared_date = datetime.fromisoformat(declared.replace("Z", "+00:00")) if declared else None
        recorded = server_signed_at if verification_mode == VerificationMode.INTERNAL else None
        if recorded is not None:
            recorded = recorded.replace(tzinfo=timezone.utc) if recorded.tzinfo is None else recorded.astimezone(timezone.utc)
        dims = SixDimensionalResults(
            cryptographic_validity=crypto, document_integrity=integrity, key_ownership=ownership,
            certificate_trust=trust, key_revocation_status=revocation, revoked_at=revoked_at,
            revocation_checked_at=datetime.now(timezone.utc) if matched else None,
            revocation_source=source, declared_timestamp=declared_date, server_recorded_at=recorded,
            server_timestamp=recorded, verification_time=datetime.now(timezone.utc), trusted_timestamp=None,
            timestamp_trust_level=TimestampTrustLevel.SERVER_RECORDED if recorded else (TimestampTrustLevel.DECLARED if declared_date else TimestampTrustLevel.UNKNOWN),
            key_registry_binding=binding,
        )
        return dims, warnings, fingerprint, key_id

    @staticmethod
    def _determine_summary_status(dims):
        if dims.cryptographic_validity == CryptographicValidity.INVALID:
            return VerificationSummaryStatus.SIGNATURE_INVALID
        if dims.document_integrity == DocumentIntegrity.TAMPERED:
            return VerificationSummaryStatus.INTEGRITY_COMPROMISED
        if dims.key_registry_binding == "MISMATCH":
            return VerificationSummaryStatus.UNVERIFIABLE
        if dims.key_revocation_status == KeyRevocationStatus.REVOKED:
            return VerificationSummaryStatus.REVOKED_KEY
        if dims.cryptographic_validity == CryptographicValidity.VALID and dims.document_integrity == DocumentIntegrity.UNCHANGED:
            return VerificationSummaryStatus.VERIFIED
        return VerificationSummaryStatus.UNVERIFIABLE

    @staticmethod
    def _owned_evidence(db, user_id, document_id, version_id):
        version = db.scalar(select(DocumentVersion).join(Document).where(
            DocumentVersion.id == version_id, Document.id == document_id, Document.owner_id == user_id))
        if version is None:
            raise HTTPException(404, "Document/version unavailable")
        sig = db.scalar(select(Signature).where(Signature.version_id == version.id))
        if sig is None:
            raise HTTPException(404, "Version has no signature")
        key = db.scalar(select(PublicKey).where(PublicKey.id == sig.key_id))
        return version, sig, key

    @staticmethod
    def _consistent_manifest(version, sig, key, user_id):
        manifest = SignedManifest.model_validate(parse_strict_json(sig.canonical_manifest_json))
        canonical = canonicalize_jcs(manifest.model_dump())
        if canonical != sig.canonical_manifest_json.encode("utf-8"):
            raise ValueError("EVIDENCE_NONCANONICAL")
        if hashlib.sha256(canonical).hexdigest() != sig.manifest_sha256:
            raise ValueError("EVIDENCE_HASH_MISMATCH")
        if manifest.document_version_id != sig.version_id or sig.version_id != version.id:
            raise ValueError("EVIDENCE_VERSION_MISMATCH")
        if key is None or manifest.key_id != sig.key_id or key.id != sig.key_id:
            raise ValueError("EVIDENCE_KEY_MISMATCH")
        if key.user_id != sig.signer_id or sig.signer_id != user_id:
            raise ValueError("EVIDENCE_SIGNER_MISMATCH")
        public = parse_profile(key.spki_pem)
        if manifest.signer_fingerprint != key.fingerprint or key.fingerprint != get_spki_fingerprint(public):
            raise ValueError("EVIDENCE_FINGERPRINT_MISMATCH")
        if manifest.algorithm != sig.algorithm or sig.algorithm != key.algorithm or sig.signature_format != "DETACHED_JCS_V1":
            raise ValueError("EVIDENCE_PROFILE_MISMATCH")
        if manifest.document_sha256 != version.file_sha256:
            raise ValueError("EVIDENCE_DOCUMENT_HASH_MISMATCH")
        # Strict signature encoding/profile also applies to retained DB evidence.
        SignaturePackage(package_version=1, signature_format=sig.signature_format, manifest=manifest,
                         signature_b64=sig.signature_b64, public_key_spki_pem=key.spki_pem)
        return manifest

    @staticmethod
    def _finish(db, result, actor_id=None, document_id=None, issue_receipt=True):
        if db is not None:
            try:
                # Minimal events retained for 30 days; no manifest, PDF, IP or receipt token.
                db.execute(delete(VerificationEvent).where(VerificationEvent.created_at < datetime.now(timezone.utc) - timedelta(days=30)))
                d = result.results
                db.add(VerificationEvent(id=result.verification_id, actor_id=actor_id,
                    document_version_id=result.document_version_id if actor_id else None,
                    verification_mode=result.verification_mode.value, cryptographic_validity=d.cryptographic_validity.value,
                    document_integrity=d.document_integrity.value, key_ownership=d.key_ownership.value,
                    certificate_trust=d.certificate_trust.value, key_revocation_status=d.key_revocation_status.value,
                    summary_status=result.summary_status.value))
                db.commit()
            except Exception:
                db.rollback()
                raise HTTPException(503, "Verification storage unavailable; retry verification")
        if issue_receipt:
            return verification_receipts.issue(result, actor_id, document_id)
        return result

    @classmethod
    def verify_internal(cls, db, user_id, document_id, version_id, storage):
        version, sig, key = cls._owned_evidence(db, user_id, document_id, version_id)
        try:
            manifest = cls._consistent_manifest(version, sig, key, user_id).model_dump()
            consistent = True
        except (ValueError, TypeError, UnicodeError, RecursionError):
            manifest = {}
            consistent = False
        computed = ""
        try:
            if storage.exists(version.storage_key):
                with storage.get_file(version.storage_key) as stream:
                    computed = compute_stream_sha256(stream)
        except (OSError, HTTPException):
            pass
        dims, warnings, fp, key_id = cls._evaluate_six_dimensions(db if consistent else None, manifest,
            sig.signature_b64 if consistent else "", key.spki_pem if consistent else None, computed,
            VerificationMode.INTERNAL, sig.signed_at if consistent else None, key if consistent else None)
        if not consistent:
            warnings.insert(0, "EVIDENCE_INCONSISTENT: Stored evidence failed strict schema/canonical/hash/binding/profile validation")
        result = VerificationResultResponse(verification_id=str(uuid.uuid4()), verification_mode=VerificationMode.INTERNAL,
            summary_status=cls._determine_summary_status(dims), results=dims, document_version_id=version.id,
            document_hash_expected=manifest.get("document_sha256", ""), document_hash_computed=computed,
            signer_fingerprint=fp, key_id=key_id, signature_algorithm="RSA-PSS-3072", signature_format="DETACHED_JCS_V1",
            warnings=warnings, warning_codes=[w.split(":",1)[0] for w in warnings],
            evidence_consistency="CONSISTENT" if consistent else "INCONSISTENT")
        return cls._finish(db, result, user_id, document_id)

    @classmethod
    def verify_shared(cls, db, version, sig, storage):
        """Verify retained evidence without reading or exposing the private PDF."""
        key = db.scalar(select(PublicKey).where(PublicKey.id == sig.key_id))
        try:
            manifest = cls._consistent_manifest(version, sig, key, sig.signer_id).model_dump()
            consistent = True
        except (ValueError, TypeError, UnicodeError, RecursionError):
            manifest = {}
            consistent = False
        computed = ""
        pre_warnings = []
        try:
            with storage.get_file(version.storage_key) as stream:
                computed = compute_stream_sha256(stream)
        except (OSError, ValueError, FileNotFoundError):
            pre_warnings.append("DOCUMENT_UNAVAILABLE: Stored PDF could not be read")
        dims, warnings, fingerprint, key_id = cls._evaluate_six_dimensions(
            db if consistent else None,
            manifest,
            sig.signature_b64 if consistent else "",
            key.spki_pem if consistent and key else None,
            computed,
            VerificationMode.INDEPENDENT_DETACHED,
            None,
            key if consistent else None,
        )
        warnings = pre_warnings + warnings
        if not consistent:
            warnings.insert(0, "EVIDENCE_INCONSISTENT: Stored evidence failed strict validation")
        result = VerificationResultResponse(
            verification_id=str(uuid.uuid4()),
            verification_mode=VerificationMode.INDEPENDENT_DETACHED,
            summary_status=cls._determine_summary_status(dims),
            results=dims,
            document_version_id=None,
            document_hash_expected=manifest.get("document_sha256", ""),
            document_hash_computed=computed,
            signer_fingerprint=fingerprint,
            key_id=None,
            signature_algorithm="RSA-PSS-3072",
            signature_format="DETACHED_JCS_V1",
            warnings=warnings,
            warning_codes=[warning.split(":", 1)[0] for warning in warnings],
            evidence_consistency="CONSISTENT" if consistent else "INCONSISTENT",
        )
        result = cls._finish(db, result, issue_receipt=False)
        result.verification_receipt = None
        result.receipt_expires_at = None
        return result

    @classmethod
    def verify_independent_package(cls, db, pdf_stream, pdf_filename, package_json_str, client_ip=None):
        # HTTP rate/body/concurrency guards run in middleware before multipart parsing.
        if len(package_json_str.encode("utf-8")) > settings.VERIFY_MAX_PACKAGE_BYTES:
            raise HTTPException(413, "Signature package exceeds limit")
        try:
            raw = parse_strict_json(package_json_str)
        except (ValueError, RecursionError):
            raise HTTPException(400, "Invalid JSON syntax, values or duplicate keys (khóa trùng lặp)")
        try:
            pkg = SignaturePackage.model_validate(raw)
        except ValueError:
            raise HTTPException(422, "Invalid signature package schema/profile/encoding")
        # UploadFile is a SpooledTemporaryFile. fileno() rolls it to disk without reading it all into RAM.
        import tempfile
        temp = None
        try:
            try:
                pdf_stream.fileno()
            except (AttributeError, OSError):
                temp = tempfile.TemporaryFile()
                pdf_stream.seek(0)
                size = 0
                while chunk := pdf_stream.read(65536):
                    size += len(chunk)
                    if size > settings.MAX_UPLOAD_BYTES:
                        raise HTTPException(413, "PDF exceeds limit")
                    temp.write(chunk)
                temp.seek(0)
                pdf_stream = temp
            validate_pdf(pdf_stream, pdf_filename, "application/pdf")
            computed = compute_stream_sha256(pdf_stream)
        finally:
            if temp is not None:
                temp.close()
        manifest = pkg.manifest.model_dump()
        dims, warnings, fp, key_id = cls._evaluate_six_dimensions(db, manifest, pkg.signature_b64,
            pkg.public_key_spki_pem, computed, VerificationMode.INDEPENDENT_DETACHED)
        result = VerificationResultResponse(verification_id=str(uuid.uuid4()), verification_mode=VerificationMode.INDEPENDENT_DETACHED,
            summary_status=cls._determine_summary_status(dims), results=dims,
            document_version_id=manifest["document_version_id"], document_hash_expected=manifest["document_sha256"],
            document_hash_computed=computed, signer_fingerprint=fp or manifest["signer_fingerprint"],
            key_id=key_id, signature_algorithm=manifest["algorithm"], signature_format=pkg.signature_format,
            warnings=warnings, warning_codes=[w.split(":",1)[0] for w in warnings])
        return cls._finish(db, result)

    @classmethod
    def export_signature_package(cls, db, user_id, document_id, version_id):
        version, sig, key = cls._owned_evidence(db, user_id, document_id, version_id)
        try:
            manifest = cls._consistent_manifest(version, sig, key, user_id)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            raise HTTPException(409, "EVIDENCE_INCONSISTENT: Cannot export corrupted evidence")
        return SignaturePackage(package_version=1, signature_format="DETACHED_JCS_V1", manifest=manifest,
            signature_b64=sig.signature_b64, public_key_spki_pem=key.spki_pem, created_at=datetime.now(timezone.utc))

    @staticmethod
    def generate_verification_report(receipt_id, db=None, user_id=None):
        actor_id, document_id, result = verification_receipts.lookup(receipt_id)
        if actor_id is not None:
            if actor_id != user_id or db is None:
                raise HTTPException(404, "Receipt unavailable")
            version = db.scalar(select(DocumentVersion.id).join(Document).where(
                DocumentVersion.id == result.document_version_id, Document.id == document_id, Document.owner_id == user_id))
            if version is None:
                raise HTTPException(404, "Receipt unavailable")
        return VerificationReportResponse(report_id=str(uuid.uuid4()), generated_at=datetime.now(timezone.utc), verification_result=VerificationReportResult.model_validate(result.model_dump()))
