"""Public PKI evidence. Private CA keys are held outside the database."""
import uuid

from sqlalchemy import Boolean, CheckConstraint, Column, DateTime, DDL, ForeignKey, String, Text, UniqueConstraint, event

from backend.app.core.database import Base
from backend.app.models.user import utc_now


class PossessionChallenge(Base):
    __tablename__ = "possession_challenges"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    certificate_id = Column(String(36), ForeignKey("certificates.id"), nullable=False)
    payload_json = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, nullable=False, default=False)


class CertificateAuthority(Base):
    __tablename__ = "certificate_authorities"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    fingerprint = Column(String(64), nullable=False, unique=True)
    certificate_pem = Column(Text, nullable=False)
    subject = Column(Text, nullable=False)
    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False)
    issuance_enabled = Column(Boolean, nullable=False, default=True)
    trust_status = Column(String(16), nullable=False, default="TRUSTED")
    compromised_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    __table_args__ = (
        CheckConstraint("trust_status IN ('TRUSTED','RETIRED','COMPROMISED')", name="ca_trust_status"),
    )


class IdentityReview(Base):
    __tablename__ = "identity_reviews"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    claims_json = Column(Text, nullable=False)
    status = Column(String(16), nullable=False, default="PENDING")
    reviewer_id = Column(String(36), ForeignKey("users.id"))
    reviewed_at = Column(DateTime(timezone=True))
    reason = Column(Text)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    __table_args__ = (
        CheckConstraint("status IN ('PENDING','APPROVED','REJECTED')", name="identity_review_status"),
    )


class Certificate(Base):
    __tablename__ = "certificates"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    key_id = Column(String(36), ForeignKey("public_keys.id"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    ca_id = Column(String(36), ForeignKey("certificate_authorities.id"), nullable=False)
    serial = Column(String(40), nullable=False)
    fingerprint = Column(String(64), nullable=False, unique=True)
    certificate_pem = Column(Text, nullable=False)
    subject = Column(Text, nullable=False)
    not_before = Column(DateTime(timezone=True), nullable=False)
    not_after = Column(DateTime(timezone=True), nullable=False, index=True)
    issued_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    revoked_at = Column(DateTime(timezone=True))
    revocation_reason = Column(String(32))
    identity_review_id = Column(String(36), ForeignKey("identity_reviews.id"))
    __table_args__ = (
        UniqueConstraint("ca_id", "serial", name="uq_certificate_issuer_serial"),
        CheckConstraint("length(fingerprint) = 64", name="certificate_fingerprint_length"),
        CheckConstraint("not_after > not_before", name="certificate_validity_order"),
    )


class SignatureCertificateBinding(Base):
    __tablename__ = "signature_certificate_bindings"
    signature_id = Column(String(36), ForeignKey("signatures.id"), primary_key=True)
    certificate_id = Column(String(36), ForeignKey("certificates.id"), nullable=False)
    certificate_sha256 = Column(String(64), nullable=False)


class CertificateChallenge(Base):
    __tablename__ = "certificate_challenges"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    key_id = Column(String(36), ForeignKey("public_keys.id"), nullable=False)
    certificate_id = Column(String(36), ForeignKey("certificates.id"))
    purpose = Column(String(16), nullable=False)
    payload_json = Column(Text, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, nullable=False, default=False)
    __table_args__ = (
        CheckConstraint("purpose IN ('ISSUE_CERT','RENEW_CERT')", name="certificate_challenge_purpose"),
    )


class CertificateOperation(Base):
    __tablename__ = "certificate_operations"
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String(36), ForeignKey("users.id"), nullable=False)
    idempotency_hash = Column(String(64), nullable=False)
    request_digest = Column(String(64), nullable=False)
    kind = Column(String(16), nullable=False)
    key_id = Column(String(36), ForeignKey("public_keys.id"), nullable=False)
    certificate_id = Column(String(36), ForeignKey("certificates.id"), nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=utc_now)
    __table_args__ = (UniqueConstraint("user_id", "idempotency_hash", name="uq_certificate_operation"),)


CERTIFICATE_GUARDS = (
    """CREATE TRIGGER certificate_immutable BEFORE UPDATE ON certificates
    WHEN NEW.id IS NOT OLD.id OR NEW.key_id IS NOT OLD.key_id OR NEW.user_id IS NOT OLD.user_id
      OR NEW.ca_id IS NOT OLD.ca_id OR NEW.serial IS NOT OLD.serial OR NEW.fingerprint IS NOT OLD.fingerprint
      OR NEW.certificate_pem IS NOT OLD.certificate_pem OR NEW.subject IS NOT OLD.subject
      OR NEW.not_before IS NOT OLD.not_before OR NEW.not_after IS NOT OLD.not_after
      OR NEW.issued_at IS NOT OLD.issued_at OR NEW.identity_review_id IS NOT OLD.identity_review_id
      OR (OLD.revoked_at IS NOT NULL AND (NEW.revoked_at IS NOT OLD.revoked_at OR NEW.revocation_reason IS NOT OLD.revocation_reason))
    BEGIN SELECT RAISE(ABORT, 'Certificate evidence is immutable'); END""",
    """CREATE TRIGGER certificate_no_delete BEFORE DELETE ON certificates
    BEGIN SELECT RAISE(ABORT, 'Certificate evidence retention'); END""",
    """CREATE TRIGGER certificate_owner_insert BEFORE INSERT ON certificates
    WHEN NOT EXISTS (SELECT 1 FROM public_keys WHERE id=NEW.key_id AND user_id=NEW.user_id)
    BEGIN SELECT RAISE(ABORT, 'Certificate owner mismatch'); END""",
)
for guard in CERTIFICATE_GUARDS:
    event.listen(Certificate.__table__, "after_create", DDL(guard).execute_if(dialect="sqlite"))

BINDING_GUARDS = tuple(
    f"CREATE TRIGGER binding_no_{operation.lower()} BEFORE {operation} ON signature_certificate_bindings "
    "BEGIN SELECT RAISE(ABORT, 'Certificate binding evidence retention'); END"
    for operation in ("UPDATE", "DELETE")
)
for guard in BINDING_GUARDS:
    event.listen(SignatureCertificateBinding.__table__, "after_create", DDL(guard).execute_if(dialect="sqlite"))

POINTER_GUARD = """CREATE TRIGGER key_certificate_pointer BEFORE UPDATE OF current_certificate_id ON public_keys
WHEN NEW.current_certificate_id IS NOT NULL AND NOT EXISTS
 (SELECT 1 FROM certificates WHERE id=NEW.current_certificate_id AND key_id=NEW.id AND user_id=NEW.user_id)
BEGIN SELECT RAISE(ABORT, 'Certificate pointer mismatch'); END"""
from backend.app.models.key import PublicKey
event.listen(PublicKey.__table__, "after_create", DDL(POINTER_GUARD).execute_if(dialect="sqlite"))

CA_GUARD = """CREATE TRIGGER ca_evidence_immutable BEFORE UPDATE ON certificate_authorities
WHEN NEW.id IS NOT OLD.id OR NEW.fingerprint IS NOT OLD.fingerprint
 OR NEW.certificate_pem IS NOT OLD.certificate_pem OR NEW.subject IS NOT OLD.subject
 OR NEW.not_before IS NOT OLD.not_before OR NEW.not_after IS NOT OLD.not_after OR NEW.created_at IS NOT OLD.created_at
 OR (OLD.compromised_at IS NOT NULL AND
     (NEW.compromised_at IS NOT OLD.compromised_at OR NEW.trust_status != 'COMPROMISED' OR NEW.issuance_enabled != 0))
BEGIN SELECT RAISE(ABORT, 'CA public evidence is immutable'); END"""
event.listen(CertificateAuthority.__table__, "after_create", DDL(CA_GUARD).execute_if(dialect="sqlite"))

POINTER_INSERT_GUARD = """CREATE TRIGGER key_certificate_pointer_insert BEFORE INSERT ON public_keys
WHEN NEW.current_certificate_id IS NOT NULL
BEGIN SELECT RAISE(ABORT, 'Insert key before binding a certificate'); END"""
event.listen(PublicKey.__table__, "after_create", DDL(POINTER_INSERT_GUARD).execute_if(dialect="sqlite"))

IDENTITY_GUARDS = (
    """CREATE TRIGGER identity_review_immutable BEFORE UPDATE ON identity_reviews
    WHEN NEW.id IS NOT OLD.id OR NEW.user_id IS NOT OLD.user_id OR NEW.claims_json IS NOT OLD.claims_json
      OR NEW.created_at IS NOT OLD.created_at OR OLD.status != 'PENDING'
      OR NEW.status NOT IN ('APPROVED','REJECTED') OR NEW.reviewer_id IS NULL OR NEW.reviewed_at IS NULL
    BEGIN SELECT RAISE(ABORT, 'Identity review snapshot is immutable'); END""",
    """CREATE TRIGGER identity_review_no_delete BEFORE DELETE ON identity_reviews
    BEGIN SELECT RAISE(ABORT, 'Identity review retention'); END""",
)
for guard in IDENTITY_GUARDS:
    event.listen(IdentityReview.__table__, "after_create", DDL(guard).execute_if(dialect="sqlite"))
