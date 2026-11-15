"""Add hashed bearer tokens for public signed-document verification."""
from alembic import op
import sqlalchemy as sa

revision = "a7f000000007"
down_revision = "a6f000000006"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "share_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("version_id", sa.String(36), sa.ForeignKey("document_versions.id"), nullable=False),
        sa.Column("created_by", sa.String(36), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("label", sa.String(100)),
        sa.CheckConstraint("length(token_hash) = 64", name="share_token_hash_length"),
        sa.CheckConstraint("revoked_at IS NULL OR revoked_at >= created_at", name="share_token_revoke_time"),
    )
    op.create_index("ix_share_tokens_version_id", "share_tokens", ["version_id"])
    op.create_index("ix_share_tokens_created_by", "share_tokens", ["created_by"])
    op.create_index("ix_share_tokens_token_hash", "share_tokens", ["token_hash"], unique=True)
    op.create_index("ix_share_tokens_expires_at", "share_tokens", ["expires_at"])
    op.execute("""CREATE TRIGGER share_token_immutable BEFORE UPDATE ON share_tokens
    WHEN NEW.id IS NOT OLD.id OR NEW.version_id IS NOT OLD.version_id
      OR NEW.created_by IS NOT OLD.created_by OR NEW.token_hash IS NOT OLD.token_hash
      OR NEW.created_at IS NOT OLD.created_at
      OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
    BEGIN SELECT RAISE(ABORT, 'Share token evidence is immutable'); END""")


def downgrade():
    op.drop_table("share_tokens")
