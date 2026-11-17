"""Retain manifest v1 evidence, admit v2 and add possession/review guards."""
from alembic import op
import sqlalchemy as sa

revision = 'b0f000000010'
down_revision = 'a9f000000009'
branch_labels = None
depends_on = None


def upgrade():
    connection = op.get_bind()
    if not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN IMMEDIATE')
    count = connection.exec_driver_sql('SELECT count(*) FROM signatures').scalar_one()
    guards = connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE type='trigger' AND name IN ('signature_no_update','signature_no_delete','version_immutable')").scalars().all()
    for name in ('signature_no_update', 'signature_no_delete', 'version_immutable'):
        op.execute(f'DROP TRIGGER IF EXISTS {name}')
    with op.batch_alter_table('signatures', recreate='always') as batch:
        batch.drop_constraint('check_sig_format', type_='check')
        batch.create_check_constraint('check_sig_format', "signature_format IN ('DETACHED_JCS_V1', 'DETACHED_JCS_V2')")
    for guard in guards:
        op.execute(guard)
    op.create_table('possession_challenges',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('certificate_id', sa.String(36), sa.ForeignKey('certificates.id'), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_used', sa.Boolean(), nullable=False))
    op.create_index('ix_possession_challenges_user_id', 'possession_challenges', ['user_id'])
    op.execute("""CREATE TRIGGER identity_review_immutable BEFORE UPDATE ON identity_reviews
    WHEN NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id OR NEW.claims_json IS NOT OLD.claims_json
      OR NEW.created_at IS NOT OLD.created_at OR OLD.status != 'PENDING'
      OR NEW.status NOT IN ('APPROVED','REJECTED') OR NEW.reviewer_id IS NULL OR NEW.reviewed_at IS NULL
    BEGIN SELECT RAISE(ABORT, 'Identity review snapshot is immutable'); END""")
    op.execute("""CREATE TRIGGER identity_review_no_delete BEFORE DELETE ON identity_reviews
    BEGIN SELECT RAISE(ABORT, 'Identity review retention'); END""")
    if connection.exec_driver_sql('SELECT count(*) FROM signatures').scalar_one() != count:
        raise RuntimeError('Signature evidence count changed')
    if connection.exec_driver_sql('PRAGMA foreign_key_check').first():
        raise RuntimeError('PKI migration foreign-key violation')


def downgrade():
    connection = op.get_bind()
    if not connection.connection.driver_connection.in_transaction:
        connection.exec_driver_sql('BEGIN IMMEDIATE')
    if (connection.exec_driver_sql("SELECT count(*) FROM signatures WHERE signature_format='DETACHED_JCS_V2'").scalar_one()
            or connection.exec_driver_sql('SELECT count(*) FROM identity_reviews').scalar_one()
            or connection.exec_driver_sql('SELECT count(*) FROM signature_certificate_bindings').scalar_one()):
        raise RuntimeError('PKI v2 retained evidence forbids downgrade')
    guards = connection.exec_driver_sql("SELECT sql FROM sqlite_master WHERE type='trigger' AND name IN ('signature_no_update','signature_no_delete','version_immutable')").scalars().all()
    for name in ('signature_no_update', 'signature_no_delete', 'version_immutable', 'identity_review_immutable', 'identity_review_no_delete'):
        op.execute(f'DROP TRIGGER IF EXISTS {name}')
    op.drop_table('possession_challenges')
    with op.batch_alter_table('signatures', recreate='always') as batch:
        batch.drop_constraint('check_sig_format', type_='check')
        batch.create_check_constraint('check_sig_format', "signature_format = 'DETACHED_JCS_V1'")
    for guard in guards:
        op.execute(guard)
    if connection.exec_driver_sql('PRAGMA foreign_key_check').first():
        raise RuntimeError('PKI downgrade foreign-key violation')
