from datetime import datetime
from typing import Literal, Optional, Dict, Any, Annotated
from pydantic import BaseModel, Field, ConfigDict, field_validator
import re

UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", )
HEX64_REGEX = re.compile(r"^[0-9a-f]{64}$")


class SignedManifest(BaseModel):
    """
    RFC 8785 Canonicalized Document Signature Manifest Schema v1.0.
    Strictly forbids unknown fields.
    """
    model_config = ConfigDict(extra="forbid", strict=True)

    manifest_version: Literal[1] = Field(..., description="Integer version 1")
    document_version_id: str = Field(..., description="UUID of DocumentVersion")
    document_sha256: str = Field(..., description="64-character lowercase hex SHA-256 of raw PDF")
    key_id: str = Field(..., description="UUID of PublicKey in database")
    signer_fingerprint: str = Field(..., description="64-character lowercase hex SHA-256 fingerprint")
    algorithm: Literal["RSA-PSS-3072"] = Field(..., description="Cryptographic signing algorithm")
    signing_nonce: str = Field(..., min_length=32, max_length=64, description="CSPRNG random nonce")
    signing_timestamp: str = Field(..., description="Server-issued ISO 8601 UTC timestamp")
    signing_context: Literal["DOCSIGN_DOCUMENT_SIGNATURE_V1"] = Field(
        ...,
        description="Domain separation context string"
    )

    @field_validator("manifest_version", mode="before")
    @classmethod
    def integer_version(cls, v):
        if type(v) is not int or v != cls.model_fields['manifest_version'].annotation.__args__[0]:
            raise ValueError("Invalid integer manifest version")
        return v

    @field_validator("signing_nonce")
    @classmethod
    def nonce(cls, v: str) -> str:
        # token_urlsafe(32): exactly 32 random bytes, canonical unpadded base64url.
        import base64
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", v):
            raise ValueError("Invalid nonce encoding")
        raw = base64.urlsafe_b64decode(v + "=")
        if base64.urlsafe_b64encode(raw).decode().rstrip("=") != v:
            raise ValueError("Noncanonical nonce encoding")
        return v

    @field_validator("signing_timestamp")
    @classmethod
    def timestamp(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", v):
            raise ValueError("Expected UTC timestamp with milliseconds")
        datetime.strptime(v, "%Y-%m-%dT%H:%M:%S.%fZ")
        return v

    @field_validator("document_version_id", "key_id")
    @classmethod
    def validate_uuid(cls, v: str) -> str:
        if not UUID_REGEX.match(v):
            raise ValueError("Must be a valid UUID format")
        return v

    @field_validator("document_sha256", "signer_fingerprint")
    @classmethod
    def validate_hex64(cls, v: str) -> str:
        if not HEX64_REGEX.fullmatch(v):
            raise ValueError("Must be a 64-character lowercase hexadecimal string")
        return v


class SignedManifestV2(SignedManifest):
    manifest_version: Literal[2]
    signing_context: Literal["DOCSIGN_DOCUMENT_SIGNATURE_V2"]
    signer_user_id: str = Field(pattern=r"^[A-Za-z0-9_-]{1,36}$")
    certificate_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


Manifest = SignedManifest | SignedManifestV2


def parse_manifest(value):
    from pydantic import TypeAdapter
    return TypeAdapter(Manifest).validate_python(value)


class PrepareSignRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    key_id: str = Field(..., description="ID of active registered public key to sign with")
    certificate_id: str | None = Field(None, pattern=r"^[A-Za-z0-9_-]{1,36}$")

    @field_validator("key_id")
    @classmethod
    def validate_key_uuid(cls, v: str) -> str:
        if not UUID_REGEX.match(v):
            raise ValueError("key_id must be a valid UUID")
        return v


class PrepareSignResponse(BaseModel):
    manifest: Manifest
    manifest_sha256: str
    expires_at: datetime
    certificate_pem: str | None = None
    issuer_certificate_pem: str | None = None


class SignatureSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version_id: str = Field(..., description="ID of DocumentVersion being signed")
    key_id: str = Field(..., description="ID of PublicKey used for signing")
    manifest: Manifest = Field(..., description="Signed manifest object")
    signature_b64: str = Field(..., min_length=512, max_length=512, description="Base64 encoded digital signature")

    @field_validator("version_id", "key_id")
    @classmethod
    def uuid_field(cls, v: str) -> str:
        if not UUID_REGEX.fullmatch(v):
            raise ValueError("Invalid lowercase UUID")
        return v


class SignatureResponse(BaseModel):
    id: str
    version_id: str
    signer_id: str
    key_id: str
    algorithm: str
    manifest_sha256: str
    signature_b64: str
    signature_format: str
    signed_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
