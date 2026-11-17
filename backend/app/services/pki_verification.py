"""Direct-root application policy. Public verification never loads the CA private key."""
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from backend.app.core.config import settings
from backend.app.crypto.certificates import fingerprint, public_der, validate_leaf
from backend.app.crypto.jcs import parse_strict_json
from backend.app.models.certificate import Certificate, CertificateAuthority, IdentityReview
from backend.app.models.key import PublicKey
from backend.app.models.enums import KeyStatus
from backend.app.models.user import User
from backend.app.models.enums import UserStatus
from fastapi import HTTPException


def signing_certificate(db, user_id, key_id, certificate_id=None, certificate_sha256=None):
    key = db.get(PublicKey, key_id, populate_existing=True)
    if (key is None or key.user_id != user_id or key.status != KeyStatus.ACTIVE or key.revoked_at
            or db.scalar(select(User.status).where(User.id == user_id)) != UserStatus.ACTIVE):
        raise HTTPException(409, 'SIGNER_UNAVAILABLE')
    cert = (db.scalar(select(Certificate).where(Certificate.fingerprint == certificate_sha256)) if certificate_sha256
            else db.get(Certificate, certificate_id or key.current_certificate_id) if certificate_id or key.current_certificate_id else None)
    if cert is None or cert.user_id != user_id or cert.key_id != key_id:
        raise HTTPException(409, 'CERTIFICATE_REQUIRED_FOR_SIGNING')
    result = inspect_certificate(db, cert.certificate_pem, expected_user=user_id,
        expected_fingerprint=certificate_sha256, expected_spki=serialization.load_pem_public_key(key.spki_pem.encode()))
    if not result['verified']:
        raise HTTPException(409, 'CERTIFICATE_NOT_VALID_FOR_SIGNING')
    return cert


def trusted_pins():
    return {p.strip().lower() for p in (settings.CA_TRUSTED_ROOT_SHA256 + ',' +
            settings.CA_ADDITIONAL_TRUSTED_ROOT_SHA256).split(',') if p.strip()}


def account_id(cert):
    uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.UniformResourceIdentifier)
    if len(uris) != 1:
        raise ValueError('Expected single account SAN')
    uri = uris[0]
    if uri.startswith('urn:uuid:'):
        return uri[9:]
    if uri.startswith('https://docsign.invalid/accounts/'):
        return unquote(uri.split('/accounts/', 1)[1])
    raise ValueError('Unsupported account SAN')


def inspect_certificate(db, pem, *, roots=None, expected_user=None, expected_fingerprint=None, expected_spki=None):
    now = datetime.now(timezone.utc)
    result = dict(certificate_binding='UNKNOWN', certificate_chain='UNKNOWN', certificate_validity='UNKNOWN',
        certificate_revocation='UNKNOWN', identity_binding='UNKNOWN', identity_assurance='UNKNOWN',
        trust_scope='DOCSIGN_PRIVATE_CA', fingerprint=None, subject=None, issuer=None,
        not_before=None, not_after=None, serial=None, user_id=None, reviewed_at=None, verified=False,
        revocation_source='UNAVAILABLE', checked_at=now.isoformat())
    try:
        if len(pem.encode()) > 16384 or pem.count('-----BEGIN CERTIFICATE-----') != 1:
            raise ValueError('Certificate size/count')
        cert = x509.load_pem_x509_certificate(pem.encode())
        fp = fingerprint(cert)
        public = cert.public_key()
        result.update(fingerprint=fp, subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
            serial=format(cert.serial_number, 'X'),
            not_before=cert.not_valid_before_utc.isoformat(), not_after=cert.not_valid_after_utc.isoformat(),
            certificate_validity='VALID' if cert.not_valid_before_utc <= now < cert.not_valid_after_utc else 'INVALID')
        user_id = account_id(cert)
        result['user_id'] = user_id
        result['certificate_binding'] = 'MATCHED' if expected_fingerprint is None or fp == expected_fingerprint else 'MISMATCH'
        result['identity_binding'] = 'MATCHED' if expected_user is None or user_id == expected_user else 'MISMATCH'
        record = db.scalar(select(Certificate).where(Certificate.fingerprint == fp).execution_options(populate_existing=True)) if db is not None else None
        issuer = db.get(CertificateAuthority, record.ca_id, populate_existing=True) if record is not None else None
        candidates = list(roots or [])
        if issuer is not None:
            candidates.insert(0, issuer.certificate_pem)
        try:
            candidates.append(Path(settings.CA_CERTIFICATE_PATH).read_text())
        except (OSError, ValueError):
            pass
        result['certificate_chain'] = 'INVALID'
        for root_pem in candidates[:3]:
            try:
                root = x509.load_pem_x509_certificate(root_pem.encode())
                pin = fingerprint(root)
                if pin not in trusted_pins():
                    continue
                # Validate profile/signatures independently of current expiry, then report time separately.
                validation_time = max(root.not_valid_before_utc, cert.not_valid_before_utc)
                validate_leaf(cert, root, pin, user_id, public, validation_time)
                if expected_spki is not None and public_der(public) != public_der(expected_spki):
                    result['certificate_binding'] = 'MISMATCH'
                result['certificate_chain'] = 'VALID'
                result['certificate_validity'] = ('VALID' if root.not_valid_before_utc <= now < root.not_valid_after_utc
                    and cert.not_valid_before_utc <= now < cert.not_valid_after_utc else 'INVALID')
                break
            except Exception:
                continue
        if record is not None:
            key = db.get(PublicKey, record.key_id, populate_existing=True)
            evidence_matches = (fingerprint(x509.load_pem_x509_certificate(record.certificate_pem.encode())) == fp
                and record.user_id == user_id and key is not None and key.user_id == user_id
                and public_der(serialization.load_pem_public_key(key.spki_pem.encode())) == public_der(public)
                and key.fingerprint == hashlib.sha256(public_der(public)).hexdigest())
            if not evidence_matches:
                result['identity_binding'] = 'MISMATCH'
            else:
                result['revocation_source'] = 'DOCSIGN_INTERNAL_DATABASE'
                result['certificate_revocation'] = ('REVOKED' if record.revoked_at or key.revoked_at
                    or key.status == KeyStatus.REVOKED or issuer is None or issuer.trust_status != 'TRUSTED'
                    or issuer.compromised_at else 'ACTIVE')
                result['identity_assurance'] = 'ACCOUNT_BOUND'
                review = db.get(IdentityReview, record.identity_review_id) if record.identity_review_id else None
                if review is not None and review.status == 'APPROVED' and review.user_id == user_id:
                    name = parse_strict_json(review.claims_json)['full_name']
                    if cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == name:
                        result['identity_assurance'] = 'ADMIN_REVIEWED'
                        result['reviewed_at'] = review.reviewed_at.isoformat()
        result['verified'] = all((result['certificate_binding'] == 'MATCHED', result['identity_binding'] == 'MATCHED',
            result['certificate_chain'] == 'VALID', result['certificate_validity'] == 'VALID',
            result['certificate_revocation'] == 'ACTIVE'))
    except Exception:
        result['certificate_chain'] = 'INVALID'
        result['verified'] = False
    return result


def verify_signature_package(db, request):
    """Verify the signed manifest against an uploaded certificate without a PDF."""
    from backend.app.schemas.verify import parse_package, VerificationMode
    from backend.app.services.verification_service import VerificationService

    if len(request.signature_package.encode('utf-8')) > settings.VERIFY_MAX_PACKAGE_BYTES:
        raise HTTPException(413, 'Signature package exceeds 512KB limit')
    try:
        package = parse_package(parse_strict_json(request.signature_package))
    except (ValueError, RecursionError):
        raise HTTPException(422, 'Invalid signature package JSON/schema/profile/encoding') from None
    manifest = package.manifest.model_dump()
    result = inspect_certificate(db, request.certificate_pem,
        roots=getattr(package, 'issuer_chain_pem', None),
        expected_user=manifest.get('signer_user_id'), expected_fingerprint=manifest.get('certificate_sha256'))
    # Always use the explicitly supplied certificate for signature verification.
    # This also applies to legacy packages which have no signed certificate reference.
    try:
        cert = x509.load_pem_x509_certificate(request.certificate_pem.encode())
        public_pem = cert.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    except (ValueError, TypeError):
        public_pem = None
    dims, warnings, _, _ = VerificationService._evaluate_six_dimensions(
        db, manifest, package.signature_b64, public_pem, '', VerificationMode.INDEPENDENT_DETACHED,
        certificate_pem=request.certificate_pem, roots=getattr(package, 'issuer_chain_pem', None),
        timestamp_token_b64=package.timestamp_token_b64)
    # An invalid uploaded certificate must never fall back to a registry key.
    crypto = dims.cryptographic_validity.value if public_pem is not None else 'UNVERIFIABLE'
    result.update(cryptographic_validity=crypto, document_integrity='UNKNOWN',
        purpose='SIGNATURE_PACKAGE', timestamp_trust=dims.timestamp_trust_level.value,
        timestamp_status=dims.timestamp_status, trusted_timestamp=dims.trusted_timestamp,
        timestamp_authority=dims.timestamp_authority, timestamp_scope=dims.timestamp_scope, warnings=warnings,
        certificate_binding=dims.certificate_binding if package.package_version == 2 else result['certificate_binding'])
    result['verified'] = (result['verified'] and crypto == 'VALID'
        and result['certificate_binding'] == 'MATCHED' and dims.key_registry_binding != 'MISMATCH' and dims.timestamp_status != 'INVALID')
    return result


def verify_detached(db, request):
    result = inspect_certificate(db, request.certificate_pem)
    result['cryptographic_validity'] = 'INVALID'
    try:
        message = base64.b64decode(request.message_b64, validate=True)
        signature = base64.b64decode(request.signature_b64, validate=True)
        if len(message) > 1048576 or len(signature) != 384 or base64.b64encode(signature).decode() != request.signature_b64:
            raise ValueError('Invalid signature/message size')
        from backend.app.services.verification_service import verify_rsa_pss, parse_profile
        cert = x509.load_pem_x509_certificate(request.certificate_pem.encode())
        key = parse_profile(cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
        verify_rsa_pss(key, signature, message)
        result['cryptographic_validity'] = 'VALID'
    except Exception:
        pass
    result['verified'] = result['verified'] and result['cryptographic_validity'] == 'VALID'
    result['purpose'] = 'DETACHED_MESSAGE_SIGNATURE'
    result['message_sha256'] = hashlib.sha256(message).hexdigest() if 'message' in locals() else None
    result['timestamp_trust'] = 'UNKNOWN'
    return result
