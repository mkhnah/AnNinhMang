import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator
from backend.app.schemas.certificate import CertificateResponse


class ChallengeCreateRequest(BaseModel):
    algorithm: str = Field(..., description="Mã thuật toán, ví dụ: RSA-PSS-3072")
    fingerprint: str = Field(..., description="SHA-256 fingerprint của SPKI DER (64 ký tự hex lowercase)")
    purpose: str = Field("REGISTER_KEY", description="Mục đích sinh challenge")

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        v = v.strip()
        if v not in ("RSA-PSS-3072", "ECDSA-P256"):
            raise ValueError("Thuật toán không được hỗ trợ. Chỉ chấp nhận RSA-PSS-3072 hoặc ECDSA-P256")
        return v

    @field_validator("fingerprint")
    @classmethod
    def validate_fingerprint(cls, v: str) -> str:
        v = v.strip().lower()
        if not re.match(r"^[a-f0-9]{64}$", v):
            raise ValueError("Fingerprint phải là chuỗi hex 64 ký tự SHA-256")
        return v

    @field_validator("purpose")
    @classmethod
    def validate_purpose(cls, v: str) -> str:
        if v != "REGISTER_KEY":
            raise ValueError("Mục đích challenge không hợp lệ. Phải là REGISTER_KEY")
        return v


class ChallengeResponse(BaseModel):
    challenge_id: str
    challenge_nonce: str
    expires_at: datetime
    purpose: str
    expected_algorithm: str
    expected_fingerprint: str


class KeyRegisterRequest(BaseModel):
    idempotency_key: str | None = Field(None, min_length=16, max_length=128, pattern=r"^[A-Za-z0-9_-]+$")
    public_key_pem: str = Field(..., description="Khóa công khai ở định dạng SPKI PEM")
    algorithm: str = Field(..., description="Thuật toán sử dụng")
    challenge_id: str = Field(..., description="ID của signing challenge đã được cấp")
    pop_signature_b64: str = Field(..., description="Chữ ký Proof-of-Possession định dạng Base64")

    @field_validator("public_key_pem")
    @classmethod
    def validate_pem(cls, v: str) -> str:
        v = v.strip()
        if not (v.startswith("-----BEGIN PUBLIC KEY-----") and v.endswith("-----END PUBLIC KEY-----")):
            raise ValueError("Định dạng PEM không hợp lệ: bắt buộc bắt đầu bằng BEGIN PUBLIC KEY và kết thúc bằng END PUBLIC KEY")
        return v

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        v = v.strip()
        if v not in ("RSA-PSS-3072", "ECDSA-P256"):
            raise ValueError("Thuật toán không được hỗ trợ")
        return v


class PublicKeyResponse(BaseModel):
    current_certificate_id: str | None = None
    certificate: CertificateResponse | None = None
    id: str
    algorithm: str
    fingerprint: str
    status: str
    created_at: datetime
    revoked_at: Optional[datetime] = None
    spki_pem: Optional[str] = None

    class Config:
        from_attributes = True


class KeyRevokeResponse(BaseModel):
    id: str
    status: str
    revoked_at: datetime
    message: str
