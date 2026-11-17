"""Add immutable RFC 3161 evidence without rewriting historical signatures."""
from alembic import op
import sqlalchemy as sa

revision = 'b1f000000011'
down_revision = 'b0f000000010'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('signature_timestamps',
        sa.Column('signature_id', sa.String(36), sa.ForeignKey('signatures.id'), primary_key=True),
        sa.Column('token_b64', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False))
    from backend.app.models.timestamp import TIMESTAMP_GUARDS
    for guard in TIMESTAMP_GUARDS:
        op.execute(guard)


def downgrade():
    if op.get_bind().exec_driver_sql('SELECT count(*) FROM signature_timestamps').scalar_one():
        raise RuntimeError('Timestamp evidence retention forbids downgrade')
    op.drop_table('signature_timestamps')
