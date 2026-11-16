"""Retained security events and the serialized chain checkpoint."""
from sqlalchemy import BigInteger, CheckConstraint, Column, DateTime, ForeignKey, Integer, String, Text, event

from backend.app.core.database import Base


GENESIS_HASH = "GENESIS_CAPSTONE_SECURITY_LOG_2026"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True, autoincrement=False)
    prev_hash = Column(String(64), nullable=False)
    entry_hash = Column(String(64), nullable=False, unique=True)
    actor_id = Column(String(36), ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(40), nullable=False, index=True)
    target_type = Column(String(32), nullable=False)
    target_id = Column(String(36), nullable=True)
    client_ip = Column(String(45), nullable=True)
    user_agent = Column(String(32), nullable=True)
    status = Column(String(16), nullable=False)
    details_json = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, index=True)

    __table_args__ = (
        CheckConstraint("id > 0", name="audit_positive_id"),
        CheckConstraint("length(entry_hash) = 64", name="audit_entry_hash_length"),
    )


class AuditChainState(Base):
    __tablename__ = "audit_chain_state"

    id = Column(Integer, primary_key=True)
    last_id = Column(BigInteger, nullable=False)
    last_hash = Column(String(64), nullable=False)

    __table_args__ = (
        CheckConstraint("id = 1", name="audit_singleton"),
        CheckConstraint("last_id >= 0", name="audit_head_nonnegative"),
    )


@event.listens_for(AuditChainState.__table__, "after_create")
def initialize_audit_chain(table, connection, **kwargs):
    connection.execute(table.insert().values(id=1, last_id=0, last_hash=GENESIS_HASH))
