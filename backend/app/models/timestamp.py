from datetime import datetime, timezone
from sqlalchemy import Column, DateTime, ForeignKey, String, Text, DDL, event
from backend.app.core.database import Base


class SignatureTimestamp(Base):
    __tablename__ = 'signature_timestamps'
    signature_id = Column(String(36), ForeignKey('signatures.id'), primary_key=True)
    token_b64 = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))


TIMESTAMP_GUARDS = (
    "CREATE TRIGGER timestamp_no_update BEFORE UPDATE ON signature_timestamps BEGIN SELECT RAISE(ABORT, 'Timestamp evidence is immutable'); END",
    "CREATE TRIGGER timestamp_no_delete BEFORE DELETE ON signature_timestamps BEGIN SELECT RAISE(ABORT, 'Timestamp evidence retention'); END",
)
for guard in TIMESTAMP_GUARDS:
    event.listen(SignatureTimestamp.__table__, 'after_create', DDL(guard).execute_if(dialect='sqlite'))
