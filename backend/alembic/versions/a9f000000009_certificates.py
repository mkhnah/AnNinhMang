"""Add private CA public evidence and issuance state; frozen additive schema."""
from alembic import op
import sqlalchemy as sa

revision = "a9f000000009"
down_revision = "a8f000000008"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("public_keys", sa.Column("current_certificate_id", sa.String(36)))
    op.create_table(
        'certificate_authorities',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('certificate_pem', sa.Text(), nullable=False),
        sa.Column('subject', sa.Text(), nullable=False),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=False),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=False),
        sa.Column('issuance_enabled', sa.Boolean(), nullable=False),
        sa.Column('trust_status', sa.String(length=16), nullable=False),
        sa.Column('compromised_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('fingerprint', name=None),
        sa.CheckConstraint("trust_status IN ('TRUSTED','RETIRED','COMPROMISED')", name='ca_trust_status'),
    )
    op.create_table(
        'identity_reviews',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('claims_json', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=16), nullable=False),
        sa.Column('reviewer_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('PENDING','APPROVED','REJECTED')", name='identity_review_status'),
    )
    op.create_index('ix_identity_reviews_user_id', 'identity_reviews', ['user_id'], unique=False)
    op.create_table(
        'certificates',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('key_id', sa.String(length=36), sa.ForeignKey('public_keys.id'), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('ca_id', sa.String(length=36), sa.ForeignKey('certificate_authorities.id'), nullable=False),
        sa.Column('serial', sa.String(length=40), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('certificate_pem', sa.Text(), nullable=False),
        sa.Column('subject', sa.Text(), nullable=False),
        sa.Column('not_before', sa.DateTime(timezone=True), nullable=False),
        sa.Column('not_after', sa.DateTime(timezone=True), nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(length=32), nullable=True),
        sa.Column('identity_review_id', sa.String(length=36), sa.ForeignKey('identity_reviews.id'), nullable=True),
        sa.UniqueConstraint('fingerprint', name=None),
        sa.CheckConstraint('length(fingerprint) = 64', name='certificate_fingerprint_length'),
        sa.CheckConstraint('not_after > not_before', name='certificate_validity_order'),
        sa.UniqueConstraint('ca_id', 'serial', name='uq_certificate_issuer_serial'),
    )
    op.create_index('ix_certificates_key_id', 'certificates', ['key_id'], unique=False)
    op.create_index('ix_certificates_not_after', 'certificates', ['not_after'], unique=False)
    op.create_index('ix_certificates_user_id', 'certificates', ['user_id'], unique=False)
    op.create_table(
        'signature_certificate_bindings',
        sa.Column('signature_id', sa.String(length=36), sa.ForeignKey('signatures.id'), primary_key=True, nullable=False),
        sa.Column('certificate_id', sa.String(length=36), sa.ForeignKey('certificates.id'), nullable=False),
        sa.Column('certificate_sha256', sa.String(length=64), nullable=False),
    )
    op.create_table(
        'certificate_challenges',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('key_id', sa.String(length=36), sa.ForeignKey('public_keys.id'), nullable=False),
        sa.Column('certificate_id', sa.String(length=36), sa.ForeignKey('certificates.id'), nullable=True),
        sa.Column('purpose', sa.String(length=16), nullable=False),
        sa.Column('payload_json', sa.Text(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_used', sa.Boolean(), nullable=False),
        sa.CheckConstraint("purpose IN ('ISSUE_CERT','RENEW_CERT')", name='certificate_challenge_purpose'),
    )
    op.create_index('ix_certificate_challenges_user_id', 'certificate_challenges', ['user_id'], unique=False)
    op.create_table(
        'certificate_operations',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('idempotency_hash', sa.String(length=64), nullable=False),
        sa.Column('request_digest', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('key_id', sa.String(length=36), sa.ForeignKey('public_keys.id'), nullable=False),
        sa.Column('certificate_id', sa.String(length=36), sa.ForeignKey('certificates.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint('user_id', 'idempotency_hash', name='uq_certificate_operation'),
    )
    op.execute("""
    CREATE TRIGGER certificate_immutable BEFORE UPDATE ON certificates
        WHEN NEW.id IS NOT OLD.id OR NEW.key_id IS NOT OLD.key_id OR NEW.user_id IS NOT OLD.user_id
          OR NEW.ca_id IS NOT OLD.ca_id OR NEW.serial IS NOT OLD.serial OR NEW.fingerprint IS NOT OLD.fingerprint
          OR NEW.certificate_pem IS NOT OLD.certificate_pem OR NEW.subject IS NOT OLD.subject
          OR NEW.not_before IS NOT OLD.not_before OR NEW.not_after IS NOT OLD.not_after
          OR NEW.issued_at IS NOT OLD.issued_at OR NEW.identity_review_id IS NOT OLD.identity_review_id
          OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS NOT OLD.revoked_at OR NEW.revocation_reason IS NOT OLD.revocation_reason))
        BEGIN SELECT RAISE(ABORT, 'Certificate evidence is immutable'); END
    """)
    op.execute("""
    CREATE TRIGGER certificate_no_delete BEFORE DELETE ON certificates
        BEGIN SELECT RAISE(ABORT, 'Certificate evidence retention'); END
    """)
    op.execute("""
    CREATE TRIGGER certificate_owner_insert BEFORE INSERT ON certificates
        WHEN NOT EXISTS (SELECT 1 FROM public_keys WHERE id=NEW.key_id AND user_id=NEW.user_id)
        BEGIN SELECT RAISE(ABORT, 'Certificate owner mismatch'); END
    """)
    op.execute("""
    CREATE TRIGGER binding_no_update BEFORE UPDATE ON signature_certificate_bindings BEGIN SELECT RAISE(ABORT, 'Certificate binding evidence retention'); END
    """)
    op.execute("""
    CREATE TRIGGER binding_no_delete BEFORE DELETE ON signature_certificate_bindings BEGIN SELECT RAISE(ABORT, 'Certificate binding evidence retention'); END
    """)
    op.execute("""
    CREATE TRIGGER key_certificate_pointer BEFORE UPDATE OF current_certificate_id ON public_keys
    WHEN NEW.current_certificate_id IS NOT NULL AND NOT EXISTS
     (SELECT 1 FROM certificates WHERE id=NEW.current_certificate_id AND key_id=NEW.id AND user_id=NEW.user_id)
    BEGIN SELECT RAISE(ABORT, 'Certificate pointer mismatch'); END
    """)

    op.execute("""
    CREATE TRIGGER ca_evidence_immutable BEFORE UPDATE ON certificate_authorities
    WHEN NEW.id IS NOT OLD.id OR NEW.fingerprint IS NOT OLD.fingerprint
     OR NEW.certificate_pem IS NOT OLD.certificate_pem OR NEW.subject IS NOT OLD.subject
     OR NEW.not_before IS NOT OLD.not_before OR NEW.not_after IS NOT OLD.not_after OR NEW.created_at IS NOT OLD.created_at
     OR (OLD.compromised_at IS NOT NULL AND
         (NEW.compromised_at IS NOT OLD.compromised_at OR NEW.trust_status != 'COMPROMISED' OR NEW.issuance_enabled != 0))
    BEGIN SELECT RAISE(ABORT, 'CA public evidence is immutable'); END
    """)
    op.execute("""
    CREATE TRIGGER key_certificate_pointer_insert BEFORE INSERT ON public_keys
    WHEN NEW.current_certificate_id IS NOT NULL
    BEGIN SELECT RAISE(ABORT, 'Insert key before binding a certificate'); END
    """)


def downgrade():
    op.execute("DROP TRIGGER IF EXISTS key_certificate_pointer_insert")
    op.execute("DROP TRIGGER IF EXISTS key_certificate_pointer")
    for table in ("certificate_operations", "certificate_challenges", "signature_certificate_bindings",
                  "certificates", "identity_reviews", "certificate_authorities"):
        op.drop_table(table)
    op.drop_column("public_keys", "current_certificate_id")
