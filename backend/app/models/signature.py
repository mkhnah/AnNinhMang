import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    UniqueConstraint,
    CheckConstraint,
)
from sqlalchemy.orm import relationship

from backend.app.core.database import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Signature(Base):
    __tablename__ = "signatures"
    __table_args__ = (
        UniqueConstraint("version_id", name="uq_signature_version"),
        CheckConstraint("length(manifest_sha256) = 64", name="check_sig_manifest_sha256_length"),
        CheckConstraint("algorithm IN ('RSA-PSS-3072', 'ECDSA-P256')", name="check_sig_algorithm"),
        CheckConstraint("signature_format IN ('DETACHED_JCS_V1', 'DETACHED_JCS_V2')", name="check_sig_format"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version_id = Column(String(36), ForeignKey("document_versions.id"), nullable=False, index=True)
    signer_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    key_id = Column(String(36), ForeignKey("public_keys.id"), nullable=False, index=True)

    algorithm = Column(String(32), nullable=False)
    canonical_manifest_json = Column(Text, nullable=False)
    manifest_sha256 = Column(String(64), nullable=False, index=True)
    signature_b64 = Column(Text, nullable=False)
    signature_format = Column(String(32), nullable=False, default="DETACHED_JCS_V1")

    signed_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    version = relationship("DocumentVersion", back_populates="signature")
    signer = relationship("User")
    key = relationship("PublicKey")


class SigningSession(Base):
    """
    Tracks ephemeral document signing challenges and nonces.
    Enforces TTL (5 minutes) and one-time consumption (atomic UPDATE)
    to protect against replay and concurrent signing race conditions.
    """
    __tablename__ = "signing_sessions"
    __table_args__ = (
        CheckConstraint("length(signing_nonce) >= 32", name="check_signing_nonce_length"),
        CheckConstraint("length(manifest_sha256) = 64", name="check_session_manifest_sha256_length"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version_id = Column(String(36), ForeignKey("document_versions.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    key_id = Column(String(36), ForeignKey("public_keys.id"), nullable=False, index=True)

    signing_nonce = Column(String(64), nullable=False, unique=True, index=True)
    manifest_sha256 = Column(String(64), nullable=False)
    canonical_manifest_json = Column(Text, nullable=False)

    is_used = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    consumed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    version = relationship("DocumentVersion")
    user = relationship("User")
    key = relationship("PublicKey")


# Retained evidence: ordinary DML cannot rewrite or delete signatures.
from sqlalchemy import DDL, event

SIGNATURE_GUARDS = (
    """CREATE TRIGGER signature_no_update BEFORE UPDATE ON signatures
BEGIN SELECT RAISE(ABORT, 'Signature evidence is immutable'); END;""",
    """CREATE TRIGGER signature_no_delete BEFORE DELETE ON signatures
BEGIN SELECT RAISE(ABORT, 'Signature evidence retention forbids deletion'); END;""",
)
for guard in SIGNATURE_GUARDS:
    event.listen(Signature.__table__, "after_create", DDL(guard).execute_if(dialect="sqlite"))
