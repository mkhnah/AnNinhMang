"""Add signatures, signing_sessions tables and update version_immutable trigger for Phase 4."""
from alembic import op
import sqlalchemy as sa

revision = 'a4f000000004'
down_revision = 'a3e000000003'
branch_labels = None
depends_on = None


def upgrade():
    # Table: signatures
    op.create_table(
        'signatures',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('version_id', sa.String(36), sa.ForeignKey('document_versions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('signer_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('key_id', sa.String(36), sa.ForeignKey('public_keys.id', ondelete='CASCADE'), nullable=False),
        sa.Column('algorithm', sa.String(32), nullable=False),
        sa.Column('canonical_manifest_json', sa.Text(), nullable=False),
        sa.Column('manifest_sha256', sa.String(64), nullable=False),
        sa.Column('signature_b64', sa.Text(), nullable=False),
        sa.Column('signature_format', sa.String(32), nullable=False, server_default='DETACHED_JCS_V1'),
        sa.Column('signed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('version_id', name='uq_signature_version'),
        sa.CheckConstraint("length(manifest_sha256) = 64", name="check_sig_manifest_sha256_length"),
        sa.CheckConstraint("algorithm IN ('RSA-PSS-3072', 'ECDSA-P256')", name="check_sig_algorithm"),
        sa.CheckConstraint("signature_format = 'DETACHED_JCS_V1'", name="check_sig_format")
    )
    op.create_index('ix_signatures_version_id', 'signatures', ['version_id'])
    op.create_index('ix_signatures_signer_id', 'signatures', ['signer_id'])
    op.create_index('ix_signatures_key_id', 'signatures', ['key_id'])
    op.create_index('ix_signatures_manifest_sha256', 'signatures', ['manifest_sha256'])

    # Table: signing_sessions
    op.create_table(
        'signing_sessions',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('version_id', sa.String(36), sa.ForeignKey('document_versions.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('key_id', sa.String(36), sa.ForeignKey('public_keys.id', ondelete='CASCADE'), nullable=False),
        sa.Column('signing_nonce', sa.String(64), nullable=False),
        sa.Column('manifest_sha256', sa.String(64), nullable=False),
        sa.Column('canonical_manifest_json', sa.Text(), nullable=False),
        sa.Column('is_used', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("length(signing_nonce) >= 32", name="check_signing_nonce_length"),
        sa.CheckConstraint("length(manifest_sha256) = 64", name="check_session_manifest_sha256_length")
    )
    op.create_index('ix_signing_sessions_version_id', 'signing_sessions', ['version_id'])
    op.create_index('ix_signing_sessions_user_id', 'signing_sessions', ['user_id'])
    op.create_index('ix_signing_sessions_key_id', 'signing_sessions', ['key_id'])
    op.create_index('ix_signing_sessions_signing_nonce', 'signing_sessions', ['signing_nonce'], unique=True)

    # Recreate version_immutable trigger on SQLite with Phase 4 SIGNED gate
    conn = op.get_bind()
    if conn.dialect.name == 'sqlite':
        op.execute("DROP TRIGGER IF EXISTS version_immutable")
        op.execute("""CREATE TRIGGER version_immutable BEFORE UPDATE ON document_versions
WHEN NEW.id IS NOT OLD.id OR NEW.document_id IS NOT OLD.document_id
 OR NEW.version_no IS NOT OLD.version_no OR NEW.file_sha256 IS NOT OLD.file_sha256
 OR NEW.storage_key IS NOT OLD.storage_key OR NEW.file_size_bytes IS NOT OLD.file_size_bytes
 OR NEW.original_filename IS NOT OLD.original_filename OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.state != NEW.state AND NOT (
     (OLD.state = 'DRAFT' AND NEW.state = 'READY_TO_SIGN')
     OR (OLD.state = 'READY_TO_SIGN' AND NEW.state = 'SIGNED' AND EXISTS (SELECT 1 FROM signatures WHERE version_id = NEW.id))
 ))
 OR (OLD.locked_at IS NOT NULL AND NEW.locked_at IS NOT OLD.locked_at)
BEGIN SELECT RAISE(ABORT, 'Immutable version or invalid transition'); END;""")


def downgrade():
    raise RuntimeError('Signature retention policy forbids destructive downgrade')
