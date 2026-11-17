from datetime import datetime
from typing import Literal

from pydantic import BaseModel, field_validator
from datetime import timezone


class AuditLogResponse(BaseModel):
    id: str
    prev_hash: str
    entry_hash: str
    actor_id: str | None
    action: str
    target_type: str
    target_id: str | None
    client_ip: str | None
    user_agent: str | None
    status: str
    details: dict
    details_valid: bool
    created_at: datetime


class AuditLogPage(BaseModel):
    items: list[AuditLogResponse]
    total: int
    limit: int
    offset: int
    snapshot_id: str


class AuditChainResponse(BaseModel):
    valid: bool
    checked_entries: int
    error_id: str | None
    reason: str | None
    verified_at: datetime


class VerificationCount(BaseModel):
    status: str
    count: int


class VerificationDay(BaseModel):
    date: str
    verified: int
    unsuccessful: int


class SecurityAlert(BaseModel):
    code: Literal["REPEATED_VERIFICATION_FAILURE", "REPEATED_CERTIFICATE_FAILURE", "IDOR_ATTEMPT", "CA_UNTRUSTED", "CERTIFICATE_EXPIRING"]
    actor_id: str | None
    client_ip: str | None
    count: int
    first_at: datetime
    last_at: datetime

    @field_validator("first_at", "last_at")
    @classmethod
    def utc_timestamp(cls, value):
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class DashboardStats(BaseModel):
    pki_counts: dict[str, int] = {}
    generated_at: datetime
    total_documents: int
    total_versions: int
    signed_versions: int
    active_keys: int
    verification_since: datetime
    verification_total: int
    verification_success_rate: float | None
    verification_counts: list[VerificationCount]
    verification_daily: list[VerificationDay]
    alert_window_minutes: int
    verification_failure_threshold: int
    alerts: list[SecurityAlert]
    alert_total: int
