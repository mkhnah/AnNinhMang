"""Add immutable PDF documents; additive only, preserves Phase 1."""
from alembic import op
import sqlalchemy as sa

revision = 'a2d000000002'
down_revision = '063d00eeffb0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('documents',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('owner_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('title', sa.String(255), nullable=False),
        sa.Column('visibility', sa.Enum('PRIVATE', 'SHARED', name='visibility', native_enum=False, create_constraint=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_documents_owner_id', 'documents', ['owner_id'])
    op.create_table('document_versions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('document_id', sa.String(36), sa.ForeignKey('documents.id'), nullable=False),
        sa.Column('version_no', sa.Integer(), nullable=False),
        sa.Column('original_filename', sa.String(255), nullable=False),
        sa.Column('file_sha256', sa.String(64), nullable=False),
        sa.Column('storage_key', sa.String(200), nullable=False, unique=True),
        sa.Column('file_size_bytes', sa.BigInteger(), nullable=False),
        sa.Column('state', sa.Enum('DRAFT', 'READY_TO_SIGN', 'SIGNED', name='versionstate', native_enum=False, create_constraint=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('locked_at', sa.DateTime(timezone=True)),
        sa.UniqueConstraint('document_id', 'version_no', name='uq_document_version'),
        sa.CheckConstraint('version_no > 0', name='positive_version'),
        sa.CheckConstraint('file_size_bytes > 0', name='positive_file_size'),
        sa.CheckConstraint('length(file_sha256) = 64', name='sha256_length'),
        sa.CheckConstraint("(state = 'DRAFT' AND locked_at IS NULL) OR (state IN ('READY_TO_SIGN', 'SIGNED') AND locked_at IS NOT NULL)", name='version_lock'))
    op.create_index('ix_document_versions_document_id', 'document_versions', ['document_id'])
    op.execute("""CREATE TRIGGER version_immutable BEFORE UPDATE ON document_versions
WHEN NEW.id IS NOT OLD.id OR NEW.document_id IS NOT OLD.document_id
 OR NEW.version_no IS NOT OLD.version_no OR NEW.file_sha256 IS NOT OLD.file_sha256
 OR NEW.storage_key IS NOT OLD.storage_key OR NEW.file_size_bytes IS NOT OLD.file_size_bytes
 OR NEW.original_filename IS NOT OLD.original_filename OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.state != NEW.state AND NOT (OLD.state = 'DRAFT' AND NEW.state = 'READY_TO_SIGN'))
 OR (OLD.locked_at IS NOT NULL AND NEW.locked_at IS NOT OLD.locked_at)
BEGIN SELECT RAISE(ABORT, 'Immutable version or invalid transition'); END""")


def downgrade():
    # Explicitly refuse destructive rollback of retained user documents.
    raise RuntimeError('Document retention requires a reviewed backup/retention procedure')
