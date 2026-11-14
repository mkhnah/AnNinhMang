import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Text, Boolean, DateTime, ForeignKey, Enum, CheckConstraint
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.models.enums import KeyStatus


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PublicKey(Base):
    __tablename__ = "public_keys"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    algorithm = Column(String(32), nullable=False)  # e.g., 'RSA-PSS-3072' or 'ECDSA-P256'
    spki_pem = Column(Text, nullable=False)
    fingerprint = Column(String(64), nullable=False, unique=True, index=True)
    status = Column(
        Enum(KeyStatus, native_enum=False, create_constraint=True),
        nullable=False,
        default=KeyStatus.ACTIVE
    )
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        CheckConstraint("length(fingerprint) = 64", name="check_fingerprint_length"),
        CheckConstraint("algorithm IN ('RSA-PSS-3072', 'ECDSA-P256')", name="check_allowed_algorithm"),
    )

    # Relationships
    user = relationship("User", back_populates="public_keys")


class SigningChallenge(Base):
    __tablename__ = "signing_challenges"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    challenge_nonce = Column(String(64), nullable=False, unique=True, index=True)
    purpose = Column(String(32), nullable=False, default="REGISTER_KEY")
    expected_algorithm = Column(String(32), nullable=False)
    expected_fingerprint = Column(String(64), nullable=True, index=True)
    is_used = Column(Boolean, default=False, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    __table_args__ = (
        CheckConstraint("purpose IN ('REGISTER_KEY')", name="check_challenge_purpose"),
    )

    # Relationships
    user = relationship("User", back_populates="signing_challenges")
