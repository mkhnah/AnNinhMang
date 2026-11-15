import uuid
from enum import Enum
from sqlalchemy import Column, String, Integer, BigInteger, DateTime, ForeignKey, Enum as SAEnum, UniqueConstraint, CheckConstraint, event, DDL
from sqlalchemy.orm import relationship
from backend.app.core.database import Base
from backend.app.models.user import utc_now


class Visibility(str, Enum):
    PRIVATE = 'PRIVATE'
    SHARED = 'SHARED'


class VersionState(str, Enum):
    DRAFT = 'DRAFT'
    READY_TO_SIGN = 'READY_TO_SIGN'
    SIGNED = 'SIGNED'


class Document(Base):
    __tablename__ = 'documents'
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(String(36), ForeignKey('users.id'), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    visibility = Column(SAEnum(Visibility, native_enum=False, create_constraint=True), nullable=False, default=Visibility.PRIVATE)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)
    owner = relationship('User')
    versions = relationship('DocumentVersion', back_populates='document', order_by='DocumentVersion.version_no')


class DocumentVersion(Base):
    __tablename__ = 'document_versions'
    __table_args__ = (
        UniqueConstraint('document_id', 'version_no', name='uq_document_version'),
        CheckConstraint('version_no > 0', name='positive_version'),
        CheckConstraint('file_size_bytes > 0', name='positive_file_size'),
        CheckConstraint('length(file_sha256) = 64', name='sha256_length'),
        CheckConstraint("(state = 'DRAFT' AND locked_at IS NULL) OR (state IN ('READY_TO_SIGN', 'SIGNED') AND locked_at IS NOT NULL)", name='version_lock'),
    )
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    document_id = Column(String(36), ForeignKey('documents.id'), nullable=False, index=True)
    version_no = Column(Integer, nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_sha256 = Column(String(64), nullable=False)
    storage_key = Column(String(200), nullable=False, unique=True)
    file_size_bytes = Column(BigInteger, nullable=False)
    state = Column(SAEnum(VersionState, native_enum=False, create_constraint=True), nullable=False, default=VersionState.DRAFT)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    document = relationship('Document', back_populates='versions')
    signature = relationship('Signature', back_populates='version', uselist=False)


# Also protect bulk/raw SQL updates. Phase 4 permits DRAFT -> READY_TO_SIGN, and READY_TO_SIGN -> SIGNED only if signature exists.
IMMUTABILITY_SQL = """CREATE TRIGGER version_immutable BEFORE UPDATE ON document_versions
WHEN NEW.id IS NOT OLD.id OR NEW.document_id IS NOT OLD.document_id
 OR NEW.version_no IS NOT OLD.version_no OR NEW.file_sha256 IS NOT OLD.file_sha256
 OR NEW.storage_key IS NOT OLD.storage_key OR NEW.file_size_bytes IS NOT OLD.file_size_bytes
 OR NEW.original_filename IS NOT OLD.original_filename OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.state != NEW.state AND NOT (
     (OLD.state = 'DRAFT' AND NEW.state = 'READY_TO_SIGN')
     OR (OLD.state = 'READY_TO_SIGN' AND NEW.state = 'SIGNED' AND EXISTS (SELECT 1 FROM signatures WHERE version_id = NEW.id))
 ))
 OR (OLD.locked_at IS NOT NULL AND NEW.locked_at IS NOT OLD.locked_at)
BEGIN SELECT RAISE(ABORT, 'Immutable version or invalid transition'); END"""
event.listen(DocumentVersion.__table__, 'after_create', DDL(IMMUTABILITY_SQL).execute_if(dialect='sqlite'))
