import uuid

from sqlalchemy import CheckConstraint, Column, DateTime, DDL, ForeignKey, String, event
from sqlalchemy.orm import relationship

from backend.app.core.database import Base
from backend.app.models.user import utc_now


class ShareToken(Base):
    __tablename__ = "share_tokens"
    __table_args__ = (
        CheckConstraint("length(token_hash) = 64", name="share_token_hash_length"),
        CheckConstraint("revoked_at IS NULL OR revoked_at >= created_at", name="share_token_revoke_time"),
    )

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    version_id = Column(String(36), ForeignKey("document_versions.id"), nullable=False, index=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    token_hash = Column(String(64), nullable=False, unique=True, index=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    label = Column(String(100), nullable=True)

    version = relationship("DocumentVersion")
    creator = relationship("User")


SHARE_TOKEN_GUARDS = (
    """CREATE TRIGGER share_token_immutable BEFORE UPDATE ON share_tokens
    WHEN NEW.id IS NOT OLD.id OR NEW.version_id IS NOT OLD.version_id
      OR NEW.created_by IS NOT OLD.created_by OR NEW.token_hash IS NOT OLD.token_hash
      OR NEW.created_at IS NOT OLD.created_at
      OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
    BEGIN SELECT RAISE(ABORT, 'Share token evidence is immutable'); END;""",
)
for guard in SHARE_TOKEN_GUARDS:
    event.listen(ShareToken.__table__, "after_create", DDL(guard).execute_if(dialect="sqlite"))
