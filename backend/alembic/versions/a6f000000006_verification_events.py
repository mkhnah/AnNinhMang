"""Create verification_events table for tracking multi-dimensional verification audits.

Revision ID: a6f000000006
Revises: a5f000000005
Create Date: 2026-11-15
"""
from alembic import op
import sqlalchemy as sa

revision = "a6f000000006"
down_revision = "a5f000000005"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "verification_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("actor_id", sa.String(length=36), nullable=True),
        sa.Column("document_version_id", sa.String(length=36), nullable=True),
        sa.Column("verification_mode", sa.String(length=50), nullable=False),
        sa.Column("cryptographic_validity", sa.String(length=50), nullable=False),
        sa.Column("document_integrity", sa.String(length=50), nullable=False),
        sa.Column("key_ownership", sa.String(length=50), nullable=False),
        sa.Column("certificate_trust", sa.String(length=50), nullable=False),
        sa.Column("key_revocation_status", sa.String(length=50), nullable=False),
        sa.Column("summary_status", sa.String(length=50), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["document_version_id"], ["document_versions.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_verification_events_actor_id", "verification_events", ["actor_id"])
    op.create_index("ix_verification_events_document_version_id", "verification_events", ["document_version_id"])
    op.create_index("ix_verification_events_created_at", "verification_events", ["created_at"])
    op.create_index("ix_ver_events_mode_created", "verification_events", ["verification_mode", "created_at"])


def downgrade():
    op.drop_index("ix_ver_events_mode_created", table_name="verification_events")
    op.drop_index("ix_verification_events_created_at", table_name="verification_events")
    op.drop_index("ix_verification_events_document_version_id", table_name="verification_events")
    op.drop_index("ix_verification_events_actor_id", table_name="verification_events")
    op.drop_table("verification_events")
