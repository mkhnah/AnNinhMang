"""Private CA profile, atomic issuance, certificate lifecycle and migration gates."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import HTTPException
from pydantic import SecretStr
import pytest
from sqlalchemy import create_engine, delete, func, select, text, update
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from backend.app.core.config import settings
from backend.app.crypto.certificates import fingerprint, issue_leaf, load_ca, validate_leaf
from backend.app.crypto.jcs import canonicalize
from backend.app.models.certificate import Certificate, CertificateAuthority, CertificateChallenge, CertificateOperation
from backend.app.models.enums import KeyStatus, UserRole, UserStatus
from backend.app.models.key import PublicKey, SigningChallenge
from backend.app.models.user import User
from backend.app.services import certificate_service, key_service
from backend.app.services.audit_service import verify_audit_chain
from scripts.init_ca import initialize_ca
from tests.test_phase5_verification import register_and_login_user


@pytest.fixture(scope='module')
def ca_files():
    # ext4/APFS permissions are required for secrets, including when cwd is NTFS.
    with tempfile.TemporaryDirectory(prefix='docsign-ca-test-', dir='/tmp') as directory:
        root = Path(directory)
        password = b'isolated-test-password-2026'
        pin = initialize_ca(root / 'ca', password)
        secret = root / 'password'
        descriptor = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(password)
        yield root, pin


@pytest.fixture
def pki(ca_files, monkeypatch):
    root, pin = ca_files
    for field, value in {
        'PKI_ENABLED': True, 'CA_PRIVATE_KEY_PATH': str(root / 'ca/ca-key.pem'),
        'CA_CERTIFICATE_PATH': str(root / 'ca/ca-cert.pem'), 'CA_PRIVATE_KEY_PASSWORD_FILE': str(root / 'password'),
        'CA_PRIVATE_KEY_PASSWORD': None, 'CA_TRUSTED_ROOT_SHA256': pin,
    }.items():
        monkeypatch.setattr(settings, field, value)
    return root


@pytest.fixture(scope='module')
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


@pytest.fixture
def auth(client):
    return register_and_login_user(client, 'pki-owner@cyber.edu')


def sign(private, payload):
    raw = private.sign(canonicalize(payload), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    return base64.b64encode(raw).decode()


def registration_request(client, auth, private):
    public = private.public_key()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fp = hashlib.sha256(der).hexdigest()
    challenge = client.post('/api/v1/keys/challenge', json={'algorithm': 'RSA-PSS-3072', 'fingerprint': fp}, headers=auth['headers'])
    assert challenge.status_code == 201, challenge.text
    body = challenge.json()
    payload = dict(schema_version=1, purpose='REGISTER_KEY', challenge_id=body['challenge_id'],
        challenge_nonce=body['challenge_nonce'], user_id=auth['user_id'], algorithm='RSA-PSS-3072', fingerprint=fp)
    return dict(public_key_pem=public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
        algorithm='RSA-PSS-3072', challenge_id=body['challenge_id'], pop_signature_b64=sign(private, payload),
        idempotency_key=str(uuid.uuid4()))


def registered(client, auth, private):
    body = registration_request(client, auth, private)
    result = client.post('/api/v1/keys', json=body, headers=auth['headers'])
    assert result.status_code == 201, result.text
    return result.json(), body


def renewal_request(client, auth, private, key_id, certificate_id=None):
    payload = {'key_id': key_id, 'purpose': 'RENEW_CERT' if certificate_id else 'ISSUE_CERT', 'certificate_id': certificate_id}
    challenge = client.post('/api/v1/certificates/challenge', json=payload, headers=auth['headers'])
    assert challenge.status_code == 201, challenge.text
    body = challenge.json()
    return {'challenge_id': body['challenge_id'], 'pop_signature_b64': sign(private, body['payload']),
            'idempotency_key': str(uuid.uuid4())}


def test_root_leaf_profile_and_openssl_interoperability(pki, private_key):
    ca = load_ca()
    user_id = str(uuid.uuid4())
    leaf = issue_leaf(ca, user_id, private_key.public_key())
    validate_leaf(leaf, ca.certificate, settings.CA_TRUSTED_ROOT_SHA256, user_id, private_key.public_key())
    assert leaf.serial_number > 0 and leaf.serial_number.bit_length() <= 159
    assert leaf.not_valid_after_utc <= ca.certificate.not_valid_after_utc
    path = pki / 'leaf.pem'
    path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    result = subprocess.run(['openssl', 'verify', '-CAfile', str(pki / 'ca/ca-cert.pem'), str(path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'OK' in result.stdout


@pytest.mark.parametrize('field,value', [
    ('CA_TRUSTED_ROOT_SHA256', '0' * 64), ('CA_PRIVATE_KEY_PATH', '/missing/ca-key.pem'),
    ('CA_PRIVATE_KEY_PASSWORD', SecretStr('incorrect-password-2026')),
])
def test_ca_readiness_errors_are_redacted(pki, monkeypatch, field, value):
    monkeypatch.setattr(settings, field, value)
    with pytest.raises(HTTPException) as error:
        load_ca()
    assert error.value.status_code == 503 and error.value.detail == 'PKI_CA_CONFIGURATION_INVALID'


def test_ca_password_and_permissions(pki, monkeypatch):
    monkeypatch.setattr(settings, 'CA_PRIVATE_KEY_PASSWORD_FILE', '')
    monkeypatch.setattr(settings, 'CA_PRIVATE_KEY_PASSWORD', SecretStr('incorrect-password-2026'))
    with pytest.raises(HTTPException):
        load_ca()
    monkeypatch.setattr(settings, 'CA_PRIVATE_KEY_PASSWORD', SecretStr('isolated-test-password-2026'))
    assert load_ca().fingerprint == settings.CA_TRUSTED_ROOT_SHA256
    path = pki / 'ca/ca-key.pem'
    path.chmod(0o644)
    try:
        with pytest.raises(HTTPException):
            load_ca()
    finally:
        path.chmod(0o600)


def test_init_ca_refuses_overwrite(pki):
    original = (pki / 'ca/ca-key.pem').read_bytes()
    with pytest.raises(FileExistsError):
        initialize_ca(pki / 'ca', b'another-test-password-2026')
    assert (pki / 'ca/ca-key.pem').read_bytes() == original


def test_auto_certificate_matches_key_account_and_idempotent_response(client, db_session, pki, private_key, auth):
    key, body = registered(client, auth, private_key)
    cert = key['certificate']
    assert cert['id'] == key['current_certificate_id'] and cert['key_id'] == key['id']
    assert cert['user_id'] == auth['user_id'] and cert['identity_assurance'] == 'ACCOUNT_BOUND'
    assert cert['status'] == 'ACTIVE' and cert['not_after'].endswith('Z')
    leaf = x509.load_pem_x509_certificate(cert['certificate_pem'].encode())
    validate_leaf(leaf, load_ca().certificate, settings.CA_TRUSTED_ROOT_SHA256, auth['user_id'], private_key.public_key())
    assert cert['fingerprint'] == fingerprint(leaf)
    retry = client.post('/api/v1/keys', json=body, headers=auth['headers'])
    assert retry.status_code == 201 and retry.json()['certificate']['id'] == cert['id']
    assert db_session.scalar(select(func.count()).select_from(Certificate)) == 1
    assert verify_audit_chain(db_session).valid


def test_changed_request_conflicts_with_same_idempotency_key(client, pki, private_key, auth):
    _, body = registered(client, auth, private_key)
    body['pop_signature_b64'] = 'A' * 512
    response = client.post('/api/v1/keys', json=body, headers=auth['headers'])
    assert response.status_code == 409 and response.json()['detail'] == 'IDEMPOTENCY_CONFLICT'


def test_signing_failure_does_not_consume_challenge_or_create_key(client, db_session, pki, private_key, auth, monkeypatch):
    body = registration_request(client, auth, private_key)
    with monkeypatch.context() as patch:
        patch.setattr(certificate_service, 'issue_leaf', lambda *args: (_ for _ in ()).throw(ValueError('secret-should-not-escape')))
        response = client.post('/api/v1/keys', json=body, headers=auth['headers'])
    assert response.status_code == 503 and 'secret-should-not-escape' not in response.text
    assert not db_session.get(SigningChallenge, body['challenge_id']).is_used
    assert db_session.scalar(select(func.count()).select_from(PublicKey)) == 0
    assert client.post('/api/v1/keys', json=body, headers=auth['headers']).status_code == 201


def test_failed_commit_rolls_back_key_certificate_operation_and_audit(client, db_session, pki, private_key, auth, monkeypatch):
    body = registration_request(client, auth, private_key)
    with monkeypatch.context() as patch:
        patch.setattr(db_session, 'commit', lambda: (_ for _ in ()).throw(RuntimeError('test failure')))
        assert client.post('/api/v1/keys', json=body, headers=auth['headers']).status_code == 500
    for model in (PublicKey, Certificate, CertificateAuthority, CertificateOperation):
        assert db_session.scalar(select(func.count()).select_from(model)) == 0
    assert not db_session.get(SigningChallenge, body['challenge_id']).is_used
    assert verify_audit_chain(db_session).valid
    db_session.rollback()
    assert client.post('/api/v1/keys', json=body, headers=auth['headers']).status_code == 201


def test_renewal_revoke_key_cascades_and_certificate_retention(client, db_session, pki, private_key, auth):
    key, _ = registered(client, auth, private_key)
    first = key['certificate']
    body = renewal_request(client, auth, private_key, key['id'], first['id'])
    renewed = client.post(f"/api/v1/certificates/{first['id']}/renew", json=body, headers=auth['headers'])
    assert renewed.status_code == 201, renewed.text
    second = renewed.json()
    assert second['fingerprint'] != first['fingerprint'] and second['serial'] != first['serial']
    assert client.post(f"/api/v1/certificates/{first['id']}/renew", json=body, headers=auth['headers']).json()['id'] == second['id']
    assert client.get(f"/api/v1/certificates/{first['id']}", headers=auth['headers']).json()['status'] == 'ACTIVE'
    assert client.post(f"/api/v1/keys/{key['id']}/revoke", headers=auth['headers']).status_code == 200
    assert client.get('/api/v1/certificates/me', headers=auth['headers']).json()['total'] == 2
    assert all(row['status'] == 'REVOKED' for row in client.get('/api/v1/certificates/me', headers=auth['headers']).json()['items'])
    assert db_session.get(PublicKey, key['id']).current_certificate_id == second['id']
    with pytest.raises(IntegrityError):
        db_session.execute(delete(Certificate))
        db_session.commit()
    db_session.rollback()


def test_certificate_revoke_idempotent_and_rbac_csrf(client, db_session, pki, private_key, auth):
    key, _ = registered(client, auth, private_key)
    cert_id = key['certificate']['id']
    assert client.post(f'/api/v1/certificates/{cert_id}/revoke', json={}).status_code == 403
    other = register_and_login_user(client, 'pki-other@cyber.edu')
    for suffix in ('', '/download'):
        assert client.get(f'/api/v1/certificates/{cert_id}{suffix}', headers=other['headers']).status_code == 404
    assert client.post(f'/api/v1/certificates/{cert_id}/revoke', json={}, headers=other['headers']).status_code == 404
    assert client.get('/api/v1/admin/pki/status', headers=other['headers']).status_code == 403
    db_session.execute(update(User).where(User.id == other['user_id']).values(role=UserRole.ADMIN))
    db_session.commit()
    assert client.get('/api/v1/admin/pki/status', headers=other['headers']).json()['ready']
    assert client.get(f'/api/v1/certificates/{cert_id}/download', headers=other['headers']).status_code == 200
    first = client.post(f'/api/v1/certificates/{cert_id}/revoke', json={}, headers=other['headers']).json()
    second = client.post(f'/api/v1/certificates/{cert_id}/revoke', json={'reason': 'CESSATION'}, headers=other['headers']).json()
    assert first['revoked_at'] == second['revoked_at'] and second['revocation_reason'] == 'USER_REQUEST'


def test_old_key_gets_certificate_with_fresh_pop(client, db_session, pki, private_key, auth, monkeypatch):
    with monkeypatch.context() as patch:
        patch.setattr(settings, 'PKI_ENABLED', False)
        key, _ = registered(client, auth, private_key)
    assert key['certificate'] is None
    body = renewal_request(client, auth, private_key, key['id'])
    invalid = {**body, 'pop_signature_b64': 'A' * 512}
    assert client.post('/api/v1/certificates/issue-for-key', json=invalid, headers=auth['headers']).status_code == 422
    response = client.post('/api/v1/certificates/issue-for-key', json=body, headers=auth['headers'])
    assert response.status_code == 201, response.text
    assert response.json()['key_id'] == key['id']
    assert client.post('/api/v1/certificates/issue-for-key', json=body, headers=auth['headers']).json()['id'] == response.json()['id']


@pytest.mark.parametrize('change', ['key_revoke', 'certificate_revoke', 'ca_disable', 'account_disable'])
def test_final_issuance_rechecks_state_after_signing(client, db_session, pki, private_key, auth, monkeypatch, change):
    key, _ = registered(client, auth, private_key)
    cert_id = key['certificate']['id']
    body = renewal_request(client, auth, private_key, key['id'], cert_id)
    original = certificate_service.prepare_certificate
    def change_after_sign(*args):
        result = original(*args)
        with Session(db_session.get_bind()) as other:
            if change == 'key_revoke':
                other.execute(update(PublicKey).values(status=KeyStatus.REVOKED, revoked_at=datetime.now(timezone.utc)))
            elif change == 'certificate_revoke':
                other.execute(update(Certificate).values(revoked_at=datetime.now(timezone.utc), revocation_reason='USER_REQUEST'))
            elif change == 'ca_disable':
                other.execute(update(CertificateAuthority).values(issuance_enabled=False))
            else:
                other.execute(update(User).where(User.id == auth['user_id']).values(status=UserStatus.DISABLED))
            other.commit()
        return result
    monkeypatch.setattr(certificate_service, 'prepare_certificate', change_after_sign)
    response = client.post(f'/api/v1/certificates/{cert_id}/renew', json=body, headers=auth['headers'])
    assert response.status_code == 409, response.text
    assert db_session.scalar(select(func.count()).select_from(Certificate)) == 1
    assert not db_session.get(CertificateChallenge, body['challenge_id'], populate_existing=True).is_used


def test_certificate_profile_rejects_wrong_subject_key_pin_and_expiry(pki, private_key):
    ca = load_ca()
    user_id = str(uuid.uuid4())
    cert = issue_leaf(ca, user_id, private_key.public_key())
    for uid, key, pin, now in [
        (str(uuid.uuid4()), private_key.public_key(), ca.fingerprint, None),
        (user_id, rsa.generate_private_key(public_exponent=65537, key_size=3072).public_key(), ca.fingerprint, None),
        (user_id, private_key.public_key(), '0' * 64, None),
        (user_id, private_key.public_key(), ca.fingerprint, cert.not_valid_after_utc + timedelta(seconds=1)),
    ]:
        with pytest.raises(ValueError):
            validate_leaf(cert, ca.certificate, pin, uid, key, now)


def test_certificate_pending_challenge_and_issuance_quotas(client, pki, private_key, auth, monkeypatch):
    key, _ = registered(client, auth, private_key)
    cert_id = key['certificate']['id']
    requests = [renewal_request(client, auth, private_key, key['id'], cert_id) for _ in range(5)]
    assert client.post('/api/v1/certificates/challenge', json={'key_id': key['id'], 'purpose': 'RENEW_CERT',
        'certificate_id': cert_id}, headers=auth['headers']).status_code == 429
    monkeypatch.setattr(settings, 'PKI_CERTIFICATES_PER_DAY', 1)
    assert client.post(f'/api/v1/certificates/{cert_id}/renew', json=requests[0], headers=auth['headers']).status_code == 429


def test_pki_migration_preserves_existing_schema_and_data(tmp_path):
    path = tmp_path / 'pki-migration.db'
    env = {**os.environ, 'DATABASE_URL': f'sqlite:///{path}', 'DEBUG': 'false', 'PKI_ENABLED': 'false'}
    def migrate(*args):
        result = subprocess.run([sys.executable, '-m', 'alembic', *args], env=env, capture_output=True, text=True, timeout=40)
        assert result.returncode == 0, result.stdout + result.stderr
    migrate('upgrade', 'a8f000000008')
    engine = create_engine(f'sqlite:///{path}')
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (id,email,full_name,password_hash,role,status,failed_login_attempts,created_at,updated_at) VALUES ('legacy','legacy@cyber.edu','Keep','synthetic','USER','ACTIVE',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    migrate('upgrade', 'a9f000000009')
    with engine.connect() as conn:
        assert conn.scalar(text('SELECT full_name FROM users')) == 'Keep'
        assert conn.execute(text('PRAGMA foreign_key_check')).all() == []
        assert conn.scalar(text("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='signature_no_update'")) == 1
    migrate('downgrade', 'a8f000000008')
    with engine.connect() as conn:
        assert conn.scalar(text('SELECT full_name FROM users')) == 'Keep'
    engine.dispose()


def test_concurrent_same_registration_commits_one_certificate(client, db_session, pki, private_key, auth):
    from backend.app.schemas.key import KeyRegisterRequest
    body = registration_request(client, auth, private_key)
    engine = create_engine(db_session.get_bind().url)
    barrier = threading.Barrier(2)
    def register(_):
        with Session(engine) as session:
            barrier.wait(timeout=10)
            return key_service.KeyService.register_public_key(session, auth['user_id'], KeyRegisterRequest(**body))
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(register, range(2)))
        assert responses[0].certificate.id == responses[1].certificate.id
        assert db_session.scalar(select(func.count()).select_from(Certificate)) == 1
        assert db_session.scalar(select(func.count()).select_from(CertificateOperation)) == 1
    finally:
        engine.dispose()


def test_concurrent_same_renewal_is_idempotent(client, db_session, pki, private_key, auth):
    from backend.app.schemas.certificate import CertificateProofRequest
    key, _ = registered(client, auth, private_key)
    cert_id = key['certificate']['id']
    body = renewal_request(client, auth, private_key, key['id'], cert_id)
    engine = create_engine(db_session.get_bind().url)
    barrier = threading.Barrier(2)
    def renew(_):
        with Session(engine) as session:
            barrier.wait(timeout=10)
            return certificate_service.issue_for_existing_key(session, auth['user_id'], CertificateProofRequest(**body), 'RENEW_CERT', cert_id)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(renew, range(2)))
        assert responses[0].id == responses[1].id
        assert db_session.scalar(select(func.count()).select_from(Certificate)) == 2
    finally:
        engine.dispose()


def test_private_key_mismatch_readiness_and_disabled_mode(client, db_session, pki, auth, monkeypatch):
    path = pki / 'wrong-key.pem'
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                     serialization.BestAvailableEncryption(b'isolated-test-password-2026')))
    db_session.execute(update(User).where(User.id == auth['user_id']).values(role=UserRole.ADMIN))
    db_session.commit()
    monkeypatch.setattr(settings, 'CA_PRIVATE_KEY_PATH', str(path))
    response = client.get('/api/v1/admin/pki/status', headers=auth['headers'])
    assert response.status_code == 503 and str(path) not in response.text
    monkeypatch.setattr(settings, 'PKI_ENABLED', False)
    assert client.get('/api/v1/admin/pki/status', headers=auth['headers']).json()['code'] == 'PKI_DISABLED'


@pytest.mark.parametrize('alteration', ['ca_leaf', 'wrong_usage', 'unknown_critical'])
def test_invalid_leaf_profiles_are_rejected(pki, private_key, alteration):
    from cryptography.x509.oid import NameOID, ObjectIdentifier
    ca = load_ca()
    uid = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test')]))
        .issuer_name(ca.certificate.subject).public_key(private_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=alteration == 'ca_leaf', path_length=None), critical=True)
        .add_extension(x509.KeyUsage(alteration != 'wrong_usage', False, False, False, False, False, False, False, False), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier('urn:uuid:' + uid)]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.certificate.public_key()), critical=False))
    if alteration == 'unknown_critical':
        builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'), b'test-only'), critical=True)
    leaf = builder.sign(ca.private_key, hashes.SHA256())
    with pytest.raises(ValueError):
        validate_leaf(leaf, ca.certificate, ca.fingerprint, uid, private_key.public_key())


def test_certificate_challenge_expiry_and_cross_purpose(client, db_session, pki, private_key, auth):
    key, _ = registered(client, auth, private_key)
    cert_id = key['certificate']['id']
    body = renewal_request(client, auth, private_key, key['id'], cert_id)
    assert client.post('/api/v1/certificates/issue-for-key', json=body, headers=auth['headers']).status_code == 409
    db_session.execute(update(CertificateChallenge).values(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)))
    db_session.commit()
    assert client.post(f'/api/v1/certificates/{cert_id}/renew', json=body, headers=auth['headers']).status_code == 409
    assert db_session.scalar(select(func.count()).select_from(Certificate)) == 1


def test_metadata_guards_and_quota_before_signing(client, db_session, pki, private_key, auth, monkeypatch):
    key, _ = registered(client, auth, private_key)
    for statement in [update(Certificate).values(certificate_pem='changed'),
                      update(CertificateAuthority).values(fingerprint='0' * 64),
                      update(PublicKey).values(current_certificate_id='foreign')]:
        with pytest.raises(IntegrityError):
            db_session.execute(statement)
            db_session.commit()
        db_session.rollback()
    cert_id = key['certificate']['id']
    body = renewal_request(client, auth, private_key, key['id'], cert_id)
    monkeypatch.setattr(settings, 'PKI_CERTIFICATES_PER_DAY', 1)
    def unexpected(*args):
        pytest.fail('CA signing must not run after quota exhaustion')
    monkeypatch.setattr(certificate_service, 'prepare_certificate', unexpected)
    assert client.post(f'/api/v1/certificates/{cert_id}/renew', json=body, headers=auth['headers']).status_code == 429


@pytest.mark.parametrize('field,value', [('spki_pem', 'invalid-key-data'), ('algorithm', 'ECDSA-P256')])
def test_corrupted_legacy_key_is_rejected_without_consuming_challenge(client, db_session, pki, private_key, auth, monkeypatch, field, value):
    with monkeypatch.context() as patch:
        patch.setattr(settings, 'PKI_ENABLED', False)
        key, _ = registered(client, auth, private_key)
    body = renewal_request(client, auth, private_key, key['id'])
    db_session.execute(update(PublicKey).where(PublicKey.id == key['id']).values(**{field: value}))
    db_session.commit()
    response = client.post('/api/v1/certificates/issue-for-key', json=body, headers=auth['headers'])
    assert response.status_code == 409
    assert not db_session.get(CertificateChallenge, body['challenge_id']).is_used


def test_legacy_ec_key_mislabeled_as_rsa_is_rejected(client, db_session, pki, auth):
    from cryptography.hazmat.primitives.asymmetric import ec
    public = ec.generate_private_key(ec.SECP256R1()).public_key()
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key = PublicKey(id=str(uuid.uuid4()), user_id=auth['user_id'], algorithm='RSA-PSS-3072',
                    spki_pem=pem, fingerprint=hashlib.sha256(der).hexdigest())
    db_session.add(key)
    db_session.commit()
    response = client.post('/api/v1/certificates/challenge', json={'key_id': key.id, 'purpose': 'ISSUE_CERT'}, headers=auth['headers'])
    assert response.status_code == 201
    body = {'challenge_id': response.json()['challenge_id'], 'pop_signature_b64': 'A' * 512, 'idempotency_key': str(uuid.uuid4())}
    assert client.post('/api/v1/certificates/issue-for-key', json=body, headers=auth['headers']).status_code == 409


def test_admin_list_and_owner_pagination(client, db_session, pki, private_key, auth):
    key, _ = registered(client, auth, private_key)
    cert_id = key['certificate']['id']
    body = renewal_request(client, auth, private_key, key['id'], cert_id)
    assert client.post(f'/api/v1/certificates/{cert_id}/renew', json=body, headers=auth['headers']).status_code == 201
    page = client.get('/api/v1/certificates/me?limit=1&offset=1', headers=auth['headers']).json()
    assert page['total'] == 2 and len(page['items']) == 1
    assert client.get('/api/v1/admin/pki/certificates', headers=auth['headers']).status_code == 403
    db_session.execute(update(User).where(User.id == auth['user_id']).values(role=UserRole.ADMIN))
    db_session.commit()
    response = client.get('/api/v1/admin/pki/certificates', headers=auth['headers'])
    assert response.status_code == 200 and response.json()['total'] == 2
    assert 'no-store' in response.headers['Cache-Control'].split(', ')
    assert client.get('/api/v1/admin/pki/certificates?user_id=other', headers=auth['headers']).json()['total'] == 0
