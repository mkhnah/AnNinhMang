import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey, Index
from backend.app.core.database import Base
from backend.app.models.user import utc_now


class VerificationEvent(Base):
    """
    Lightweight, privacy-conscious audit record for document verification attempts.
    Never stores sensitive PDF bytes or raw private data.
    """
    __tablename__ = "verification_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    actor_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    document_version_id = Column(String(36), ForeignKey("document_versions.id", ondelete="SET NULL"), nullable=True, index=True)
    verification_mode = Column(String(50), nullable=False)
    cryptographic_validity = Column(String(50), nullable=False)
    document_integrity = Column(String(50), nullable=False)
    key_ownership = Column(String(50), nullable=False)
    certificate_trust = Column(String(50), nullable=False)
    key_revocation_status = Column(String(50), nullable=False)
    summary_status = Column(String(50), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    __table_args__ = (
        Index("ix_ver_events_mode_created", "verification_mode", "created_at"),
    )
