"""Final Phase 3 regression gates; private fixtures and test DB only."""
import base64
import hashlib
import secrets
import uuid
import json
import subprocess
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from sqlalchemy import select, func
from sqlalchemy.exc import IntegrityError

from backend.app.models.key import PublicKey, SigningChallenge
from backend.app.schemas.key import ChallengeCreateRequest, KeyRegisterRequest
from backend.app.services import key_service
from tests.test_phase3_keys import auth_user_headers, generate_test_rsa_key, sign_pop

VECTORS = json.loads(Path('tests/fixtures/pop-v1.json').read_text())


def node_bridge(value):
    process = subprocess.run(['node', 'tests/helpers/pop_webcrypto.cjs'], input=json.dumps(value), capture_output=True, text=True, timeout=30)
    assert process.returncode == 0, process.stderr
    return json.loads(process.stdout)


def registration(db, user_id):
    private, _, pem, fingerprint = generate_test_rsa_key()
    challenge = key_service.KeyService.create_signing_challenge(db, user_id, ChallengeCreateRequest(algorithm='RSA-PSS-3072', fingerprint=fingerprint))
    payload = dict(VECTORS['valid'][0]['payload'], challenge_id=challenge.challenge_id, challenge_nonce=challenge.challenge_nonce, user_id=user_id, fingerprint=fingerprint)
    request = KeyRegisterRequest(public_key_pem=pem, algorithm='RSA-PSS-3072', challenge_id=challenge.challenge_id, pop_signature_b64=sign_pop(private, payload))
    return challenge, request


def test_expires_between_initial_check_and_atomic_update(db_session, auth_user_headers, monkeypatch):
    challenge, request = registration(db_session, auth_user_headers['user'].id)
    original = key_service.canonicalize_pop_payload
    reached = False

    def expire_after_initial_read(*args, **kwargs):
        nonlocal reached
        reached = True
        # Emulate expiry while verification is in progress, without a wall-clock sleep.
        # The identity-map already passed the initial check; UPDATE must check DB time.
        db_session.execute(SigningChallenge.__table__.update().where(SigningChallenge.id == challenge.challenge_id).values(expires_at=key_service.utc_now() - timedelta(seconds=1)))
        db_session.commit()
        return original(*args, **kwargs)

    monkeypatch.setattr(key_service, 'canonicalize_pop_payload', expire_after_initial_read)
    with pytest.raises(HTTPException) as error:
        key_service.KeyService.register_public_key(db_session, auth_user_headers['user'].id, request)
    assert reached and error.value.status_code == 400
    assert db_session.scalar(select(func.count()).select_from(PublicKey)) == 0
    assert db_session.get(SigningChallenge, challenge.challenge_id).is_used is False


def test_unique_conflict_rolls_back_consumed_challenge(db_session, auth_user_headers, monkeypatch):
    challenge, request = registration(db_session, auth_user_headers['user'].id)
    with monkeypatch.context() as patch:
        def conflict():
            raise IntegrityError('synthetic unique conflict', {}, Exception('test-only'))
        patch.setattr(db_session, 'commit', conflict)
        with pytest.raises(HTTPException) as error:
            key_service.KeyService.register_public_key(db_session, auth_user_headers['user'].id, request)
        assert error.value.status_code == 409
        assert 'INSERT' not in error.value.detail
    assert db_session.get(SigningChallenge, challenge.challenge_id).is_used is False
    assert db_session.scalar(select(func.count()).select_from(PublicKey)) == 0
    # Same challenge is still usable after the failed transaction.
    assert key_service.KeyService.register_public_key(db_session, auth_user_headers['user'].id, request).status == 'ACTIVE'


def test_golden_vectors_match_real_typescript_bytes():
    encoded = node_bridge(dict(action='canonical', payloads=[v['payload'] for v in VECTORS['valid']]))
    for vector, actual in zip(VECTORS['valid'], encoded, strict=True):
        python = key_service.canonicalize_pop_payload(**vector['payload'])
        assert python.decode() == vector['canonical_utf8']
        assert actual == vector['canonical_b64'] == base64.b64encode(python).decode()


@pytest.mark.parametrize('payload', VECTORS['invalid'])
def test_pop_rejects_out_of_contract_payload(payload):
    with pytest.raises((ValueError, TypeError)):
        key_service.canonicalize_pop_payload(**payload)


def test_node_webcrypto_pop_registers_through_authenticated_http(client, db_session, auth_user_headers):
    payload = dict(VECTORS['valid'][0]['payload'], user_id=auth_user_headers['user'].id, challenge_id=str(uuid.uuid4()), challenge_nonce=secrets.token_urlsafe(32))
    fingerprint_key = node_bridge(dict(action='sign', payload=payload))
    # First independently verify a real TypeScript signature in Python.
    payload = fingerprint_key['payload']
    public = serialization.load_pem_public_key(fingerprint_key['public_key_pem'].encode())
    public.verify(base64.b64decode(fingerprint_key['signature']), key_service.canonicalize_pop_payload(**payload), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    assert base64.b64encode(key_service.canonicalize_pop_payload(**payload)).decode() == fingerprint_key['canonical_b64']
    # Seed a fresh server challenge; only public material crosses the Node process boundary.
    db_session.add(SigningChallenge(id=payload['challenge_id'], user_id=payload['user_id'], challenge_nonce=payload['challenge_nonce'], purpose='REGISTER_KEY', expected_algorithm=payload['algorithm'], expected_fingerprint=payload['fingerprint'], is_used=False, expires_at=key_service.utc_now() + timedelta(minutes=5)))
    db_session.commit()
    request = dict(public_key_pem=fingerprint_key['public_key_pem'], algorithm=payload['algorithm'], challenge_id=payload['challenge_id'], pop_signature_b64=fingerprint_key['signature'])
    assert set(request) == {'public_key_pem', 'algorithm', 'challenge_id', 'pop_signature_b64'}
    assert 'PRIVATE KEY' not in json.dumps(request)
    response = client.post('/api/v1/keys', json=request, headers=auth_user_headers['headers'])
    assert response.status_code == 201, response.text
    assert response.json()['fingerprint'] == payload['fingerprint']



def test_python_pop_verifies_in_actual_frontend_module():
    private, public, _, fingerprint = generate_test_rsa_key()
    payload = dict(VECTORS['valid'][0]['payload'], fingerprint=fingerprint)
    result = node_bridge(dict(action='verify', payload=payload, signature=sign_pop(private, payload), spki_b64=base64.b64encode(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()))
    assert result == {'valid': True}
