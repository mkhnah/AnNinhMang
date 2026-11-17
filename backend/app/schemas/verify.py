from datetime import datetime
from enum import Enum
from typing import List, Optional, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

from backend.app.schemas.signature import SignedManifest, SignedManifestV2, Manifest


class CryptographicValidity(str, Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"


class DocumentIntegrity(str, Enum):
    UNCHANGED = "UNCHANGED"
    TAMPERED = "TAMPERED"
    UNKNOWN = "UNKNOWN"


class KeyOwnership(str, Enum):
    VERIFIED_POP = "VERIFIED_POP"
    UNVERIFIED = "UNVERIFIED"
    UNKNOWN = "UNKNOWN"


class CertificateTrust(str, Enum):
    SELF_REGISTERED = "SELF_REGISTERED"
    TRUSTED_CA = "TRUSTED_CA"
    UNKNOWN = "UNKNOWN"


class KeyRevocationStatus(str, Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    UNKNOWN = "UNKNOWN"


class TimestampTrustLevel(str, Enum):
    UNKNOWN = "UNKNOWN"
    DECLARED = "DECLARED"
    SERVER_RECORDED = "SERVER_RECORDED"
    TRUSTED_TSA = "TRUSTED_TSA"


class VerificationMode(str, Enum):
    INTERNAL = "INTERNAL"
    INDEPENDENT_DETACHED = "INDEPENDENT_DETACHED"


class VerificationSummaryStatus(str, Enum):
    VERIFIED = "VERIFIED"
    INTEGRITY_COMPROMISED = "INTEGRITY_COMPROMISED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    UNVERIFIABLE = "UNVERIFIABLE"
    REVOKED_KEY = "REVOKED_KEY"


# --- Signature Package Schema ---

class SignaturePackage(BaseModel):
    """
    Standard Detached Signature Package (signature-package.json).
    Self-contained bundle enabling independent verification by any third-party.
    """
    model_config = ConfigDict(extra="forbid", strict=True)
    package_version: Literal[1]
    signature_format: Literal["DETACHED_JCS_V1"]
    manifest: SignedManifest
    signature_b64: str = Field(min_length=512, max_length=512)
    public_key_spki_pem: Optional[str] = Field(None, min_length=64, max_length=4096)
    created_at: Optional[datetime] = None
    timestamp_token_b64: str | None = Field(None, min_length=4, max_length=87384)

    @field_validator('timestamp_token_b64')
    @classmethod
    def timestamp_encoding(cls, value):
        if value is not None:
            from backend.app.services.timestamp_service import _decode
            _decode(value)
        return value

    @field_validator("package_version", mode="before")
    @classmethod
    def version_integer(cls, value):
        if type(value) is not int or value != 1:
            raise ValueError("package_version must be integer 1")
        return value

    @field_validator("signature_b64")
    @classmethod
    def canonical_signature(cls, value: str):
        import base64
        try:
            raw = base64.b64decode(value, validate=True)
        except ValueError:
            raise ValueError("Invalid signature Base64")
        if len(raw) != 384 or base64.b64encode(raw).decode() != value:
            raise ValueError("Expected canonical Base64 of a 3072-bit signature")
        return value

    @field_validator("created_at", mode="before")
    @classmethod
    def creation_date(cls, value):
        # Optional export metadata, never used as trusted timestamp evidence.
        if isinstance(value, str):
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value


# --- Multi-Dimensional Verification Result Schema ---

class SignaturePackageV2(SignaturePackage):
    package_version: Literal[2]
    signature_format: Literal["DETACHED_JCS_V2"]
    manifest: SignedManifestV2
    certificate_pem: str = Field(min_length=64, max_length=16384)
    issuer_chain_pem: list[str] = Field(min_length=1, max_length=1)

    @field_validator("package_version", mode="before")
    @classmethod
    def version_integer(cls, value):
        if type(value) is not int or value != 2:
            raise ValueError("package_version must be integer 2")
        return value

    @field_validator("issuer_chain_pem")
    @classmethod
    def chain_size(cls, value):
        if any(len(pem.encode()) > 16384 for pem in value):
            raise ValueError("Issuer certificate too large")
        return value


def parse_package(value):
    if not isinstance(value, dict) or type(value.get('package_version')) is not int:
        raise ValueError('Invalid package version')
    return (SignaturePackageV2 if value.get('package_version') == 2 else SignaturePackage).model_validate(value)


class SixDimensionalResults(BaseModel):
    timestamp_status: str = 'ABSENT'
    timestamp_authority: str | None = None
    timestamp_authority_fingerprint: str | None = None
    timestamp_serial: str | None = None
    timestamp_scope: str | None = None
    certificate_binding: str = "LEGACY_NO_CERTIFICATE_BINDING"
    certificate_chain: str = "UNKNOWN"
    certificate_validity: str = "UNKNOWN"
    certificate_revocation: str = "UNKNOWN"
    identity_binding: str = "UNKNOWN"
    identity_assurance: str = "UNKNOWN"
    trust_scope: str = "SELF_REGISTERED"
    certificate_sha256: str | None = None
    cryptographic_validity: CryptographicValidity = Field(
        ...,
        description="Toán học mật mã: VALID (chữ ký khớp), INVALID (chữ ký sai), UNVERIFIABLE (thiếu khóa)",
    )
    document_integrity: DocumentIntegrity = Field(
        ...,
        description="Toàn vẹn tệp: UNCHANGED (SHA-256 khớp), TAMPERED (bị sửa đổi), UNKNOWN (thiếu tệp)",
    )
    key_ownership: KeyOwnership = Field(
        ...,
        description="Bằng chứng sở hữu khóa: VERIFIED_POP (đã xác thực PoP trong hệ thống), UNVERIFIED, UNKNOWN",
    )
    certificate_trust: CertificateTrust = Field(
        ...,
        description="Mức độ tin cậy chứng thư: SELF_REGISTERED (tự đăng ký), TRUSTED_CA (chứng thực bởi CA), UNKNOWN",
    )
    key_revocation_status: KeyRevocationStatus = Field(
        ...,
        description="Trạng thái thu hồi khóa: ACTIVE, REVOKED, UNKNOWN",
    )
    revoked_at: Optional[datetime] = Field(None, description="Thời điểm khóa bị thu hồi nếu có")
    revocation_checked_at: Optional[datetime] = Field(None, description="Thời điểm kiểm tra trạng thái thu hồi")
    revocation_source: Optional[str] = Field(None, description="Nguồn kiểm tra thu hồi (DOCSIGN_INTERNAL_DB / UNKNOWN)")

    declared_timestamp: Optional[datetime] = None
    server_recorded_at: Optional[datetime] = None
    server_timestamp: Optional[datetime] = Field(None, description="Compatibility alias of server_recorded_at only")
    key_registry_binding: str = "UNKNOWN"
    verification_time: datetime = Field(..., description="Thời điểm thực hiện xác minh")
    trusted_timestamp: Optional[datetime] = Field(None, description="Thời gian chứng thực từ token RFC 3161 đã xác minh")
    timestamp_trust_level: TimestampTrustLevel = Field(
        ...,
        description="Mức độ tin cậy dấu thời gian: DECLARED, SERVER_RECORDED, TRUSTED_TSA",
    )


class VerificationResultResponse(BaseModel):
    """
    Multi-dimensional Verification Result Response.
    Never collapses the six dimensions into a single superficial valid status.
    """
    verification_id: str = Field(..., description="UUID định danh phiên xác minh")
    verification_mode: VerificationMode = Field(..., description="INTERNAL hoặc INDEPENDENT_DETACHED")
    verification_receipt: Optional[str] = None
    receipt_expires_at: Optional[datetime] = None
    evidence_consistency: Literal["CONSISTENT", "INCONSISTENT", "NOT_APPLICABLE"] = "NOT_APPLICABLE"
    warning_codes: List[str] = Field(default_factory=list)
    summary_status: VerificationSummaryStatus = Field(
        ...,
        description="Tóm tắt trạng thái kỹ thuật (Không thay thế 6 chiều xác minh)",
    )
    results: SixDimensionalResults = Field(..., description="Chi tiết 6 thành phần xác minh độc lập")

    # Cryptographic & File Metadata
    document_version_id: Optional[str] = None
    document_hash_expected: str = Field(..., description="SHA-256 khai báo trong manifest")
    document_hash_computed: str = Field(..., description="SHA-256 tính toán thực tế từ luồng byte tệp PDF")
    signer_fingerprint: Optional[str] = None
    key_id: Optional[str] = None
    signature_algorithm: str = Field("RSA-PSS-3072", description="Thuật toán chữ ký số")
    signature_format: str = Field("DETACHED_JCS_V1", description="Định dạng chữ ký số")

    warnings: List[str] = Field(default_factory=list, description="Danh sách cảnh báo an ninh và giới hạn tin cậy")

    model_config = ConfigDict(from_attributes=True)


# --- Verification Report JSON Export Schema ---

class VerificationReportResult(VerificationResultResponse):
    # Export the verification snapshot, never the bearer capability used to fetch it.
    verification_receipt: Optional[str] = Field(None, exclude=True)
    receipt_expires_at: Optional[datetime] = Field(None, exclude=True)


class VerificationReportResponse(BaseModel):
    """
    Standardized Verification Report (verification-report.json).
    Exportable audit report detailing the multi-dimensional verification evidence.
    """
    report_version: int = Field(1, description="Phiên bản schema báo cáo")
    report_id: str = Field(..., description="Mã định danh báo cáo")
    generated_at: datetime = Field(..., description="Thời gian tạo báo cáo")
    verification_result: VerificationReportResult = Field(..., description="Kết quả xác minh 6 chiều")
    evidence_source: str = Field(
        "DOCSIGN_INDEPENDENT_VERIFICATION_ENGINE_V1",
        description="Động cơ xác minh thực hiện",
    )
    disclaimer: str = (
        "Verification report generated by the application; not digitally signed or independently tamper-evident. "
        "Private CA trust is limited to the configured DocSign trust domain. "
        "ACCOUNT_BOUND identifies an account; ADMIN_REVIEWED reflects the operator review. "
        "RFC 3161 timestamp trust is limited to the configured internal TSA; declared time is not proven signing time."
    )

    model_config = ConfigDict(from_attributes=True)


class VerificationReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    receipt_id: str = Field(pattern=r"^[A-Za-z0-9_-]{43}$")
