"""Add retained hash-chained audit events and their writer checkpoint."""
from alembic import op
import sqlalchemy as sa

revision = "a8f000000008"
down_revision = "a7f000000007"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("entry_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("actor_id", sa.String(36), sa.ForeignKey("users.id")),
        sa.Column("action", sa.String(40), nullable=False),
        sa.Column("target_type", sa.String(32), nullable=False),
        sa.Column("target_id", sa.String(36)),
        sa.Column("client_ip", sa.String(45)),
        sa.Column("user_agent", sa.String(32)),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("details_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("id > 0", name="audit_positive_id"),
        sa.CheckConstraint("length(entry_hash) = 64", name="audit_entry_hash_length"),
    )
    for column in ("actor_id", "action", "created_at"):
        op.create_index(f"ix_audit_logs_{column}", "audit_logs", [column])
    state = op.create_table(
        "audit_chain_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("last_id", sa.BigInteger(), nullable=False),
        sa.Column("last_hash", sa.String(64), nullable=False),
        sa.CheckConstraint("id = 1", name="audit_singleton"),
        sa.CheckConstraint("last_id >= 0", name="audit_head_nonnegative"),
    )
    op.bulk_insert(state, [{"id": 1, "last_id": 0, "last_hash": "GENESIS_CAPSTONE_SECURITY_LOG_2026"}])


def downgrade():
    op.drop_table("audit_logs")
    op.drop_table("audit_chain_state")
