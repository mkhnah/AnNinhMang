from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CertificateResponse(BaseModel):
    id: str
    key_id: str
    user_id: str
    ca_id: str
    serial: str
    fingerprint: str
    certificate_pem: str
    subject: str
    not_before: datetime
    not_after: datetime
    issued_at: datetime
    revoked_at: datetime | None
    revocation_reason: str | None
    status: str
    identity_assurance: Literal["ACCOUNT_BOUND", "ADMIN_REVIEWED"] = "ACCOUNT_BOUND"
    reviewed_at: datetime | None = None

    @field_validator("not_before", "not_after", "issued_at", "revoked_at", "reviewed_at")
    @classmethod
    def utc_dates(cls, value):
        if value is None:
            return value
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class CertificateChallengeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    key_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,36}$")
    purpose: Literal["ISSUE_CERT", "RENEW_CERT"]
    certificate_id: str | None = Field(None, pattern=r"^[A-Za-z0-9_-]{1,36}$")


class CertificatePage(BaseModel):
    items: list[CertificateResponse]
    total: int
    limit: int
    offset: int


class CertificateChallengeResponse(BaseModel):
    challenge_id: str
    payload: dict[str, str | int | None]
    expires_at: datetime


class CertificateProofRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    challenge_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,36}$")
    pop_signature_b64: str = Field(min_length=512, max_length=512)
    idempotency_key: str = Field(min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")


class CertificateRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: Literal["KEY_COMPROMISE", "SUPERSEDED", "CESSATION", "USER_REQUEST"] = "USER_REQUEST"


class IdentityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    full_name: str = Field(min_length=2, max_length=64, pattern=r"^[^\x00-\x1f\x7f]+$")
    evidence_reference: str = Field(min_length=3, max_length=200)

    @field_validator('full_name', mode='before')
    @classmethod
    def name_profile(cls, value):
        if not isinstance(value, str):
            raise ValueError('Expected name text')
        value = value.strip()
        if len(value.encode('utf-8')) > 64:
            raise ValueError('Certificate common name exceeds 64 UTF-8 bytes')
        return value


class IdentityDecision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    status: Literal["APPROVED", "REJECTED"]
    reason: str = Field(min_length=3, max_length=500)


class CertificateVerifyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    certificate_pem: str = Field(min_length=64, max_length=16384)


class DetachedVerifyRequest(CertificateVerifyRequest):
    message_b64: str = Field(max_length=1400000)
    signature_b64: str = Field(min_length=512, max_length=512)


class SignaturePackageVerifyRequest(CertificateVerifyRequest):
    signature_package: str = Field(min_length=2, max_length=524288)


class PossessionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    certificate_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,36}$")


class PossessionProof(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    challenge_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,36}$")
    signature_b64: str = Field(min_length=512, max_length=512)


class AuthorityUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    trust_status: Literal["TRUSTED", "RETIRED", "COMPROMISED"]
    issuance_enabled: bool = False
