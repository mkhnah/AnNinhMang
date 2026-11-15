from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field

from backend.app.core.config import settings


class ShareCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version_id: str
    expires_in_days: int = Field(default=settings.SHARE_DEFAULT_EXPIRY_DAYS, ge=1, le=settings.SHARE_MAX_EXPIRY_DAYS)
    label: str | None = Field(None, max_length=100)


class ShareCreateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    version_id: str
    share_url: str
    expires_at: datetime
    label: str | None = None


class ShareListItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    version_id: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    label: str | None = None
    status: str  # "ACTIVE", "EXPIRED", "REVOKED"


class PublicVerificationDimensions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cryptographic_validity: str
    document_integrity: str
    key_ownership: str
    certificate_trust: str
    key_revocation_status: str
    declared_timestamp: str | None = None
    verification_time: datetime
    timestamp_trust_level: str


class PublicVerificationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary_status: str
    evidence_consistency: str
    results: PublicVerificationDimensions
    warnings: list[str] = Field(default_factory=list)
    warning_codes: list[str] = Field(default_factory=list)


class PublicShareVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str
    version_no: int
    original_filename: str
    expires_at: datetime
    verified_at: datetime
    signer_fingerprint: str | None
    results: PublicVerificationSummary
