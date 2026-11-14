"""Add public_keys and signing_challenges tables; additive only, preserves Phase 1 and 2."""
from alembic import op
import sqlalchemy as sa

revision = 'a3e000000003'
down_revision = 'a2d000000002'
branch_labels = None
depends_on = None


def upgrade():
    # Table: public_keys
    op.create_table(
        'public_keys',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('algorithm', sa.String(32), nullable=False),
        sa.Column('spki_pem', sa.Text(), nullable=False),
        sa.Column('fingerprint', sa.String(64), nullable=False),
        sa.Column(
            'status',
            sa.Enum('ACTIVE', 'REVOKED', name='keystatus', native_enum=False, create_constraint=True),
            nullable=False,
            server_default='ACTIVE'
        ),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint("length(fingerprint) = 64", name="check_fingerprint_length"),
        sa.CheckConstraint("algorithm IN ('RSA-PSS-3072', 'ECDSA-P256')", name="check_allowed_algorithm")
    )
    op.create_index('ix_public_keys_user_id', 'public_keys', ['user_id'])
    op.create_index('ix_public_keys_fingerprint', 'public_keys', ['fingerprint'], unique=True)

    # Table: signing_challenges
    op.create_table(
        'signing_challenges',
        sa.Column('id', sa.String(36), primary_key=True),
        sa.Column('user_id', sa.String(36), sa.ForeignKey('users.id', ondelete='CASCADE'), nullable=False),
        sa.Column('challenge_nonce', sa.String(64), nullable=False),
        sa.Column('purpose', sa.String(32), nullable=False, server_default='REGISTER_KEY'),
        sa.Column('expected_algorithm', sa.String(32), nullable=False),
        sa.Column('expected_fingerprint', sa.String(64), nullable=True),
        sa.Column('is_used', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("purpose IN ('REGISTER_KEY')", name="check_challenge_purpose")
    )
    op.create_index('ix_signing_challenges_user_id', 'signing_challenges', ['user_id'])
    op.create_index('ix_signing_challenges_challenge_nonce', 'signing_challenges', ['challenge_nonce'], unique=True)
    op.create_index('ix_signing_challenges_expected_fingerprint', 'signing_challenges', ['expected_fingerprint'])


def downgrade():
    op.drop_table('signing_challenges')
    op.drop_table('public_keys')
