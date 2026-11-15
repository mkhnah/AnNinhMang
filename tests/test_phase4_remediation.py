"""Regression coverage for actual Phase 4 audit failures (private database/storage)."""
import copy
import json
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.sql.dml import Update
from sqlalchemy.exc import IntegrityError, OperationalError

from tests.test_phase4_signatures import (
    client_p4, storage_p4, register_and_login_user, generate_test_rsa_3072,
    register_user_key, upload_and_ready_doc, sign_manifest_py,
)
from tests.conftest import TestingSessionLocal, test_engine
from backend.app.models.signature import Signature, SigningSession
from backend.app.models.document import DocumentVersion, VersionState


@pytest.fixture
def attempt(client_p4):
    auth = register_and_login_user(client_p4)
    private, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p4, auth, private, pem, fp)
    doc, version, _, _ = upload_and_ready_doc(client_p4, auth['headers'])
    prepared = client_p4.post(f'/api/v1/documents/{doc}/versions/{version}/prepare-sign', json={'key_id': key['id']}, headers=auth['headers'])
    assert prepared.status_code == 200, prepared.text
    manifest = prepared.json()['manifest']
    payload = dict(version_id=version, key_id=key['id'], manifest=manifest, signature_b64=sign_manifest_py(private, manifest))
    return auth, doc, payload, private


def post(client, attempt, payload=None):
    return client.post('/api/v1/signatures', json=payload or attempt[2], headers=attempt[0]['headers'])


def assert_uncommitted(db):
    db.expire_all()
    assert db.scalar(select(Signature.id)) is None
    assert not db.scalar(select(SigningSession.is_used))
    assert db.scalar(select(DocumentVersion.state)) != VersionState.SIGNED


def test_read_idor_relationship_chain(client_p4, attempt, db_session):
    auth, doc, payload, _ = attempt
    assert post(client_p4, attempt).status_code == 201
    other = register_and_login_user(client_p4, 'other@cyber.edu')
    other_doc, other_version, _, _ = upload_and_ready_doc(client_p4, other['headers'])
    path = lambda d, v: f'/api/v1/documents/{d}/versions/{v}/signature'
    assert client_p4.get(path(doc, payload['version_id']), headers=auth['headers']).status_code == 200
    for d, v in [(doc, payload['version_id']), (other_doc, payload['version_id']), (doc, other_version), (str(uuid.uuid4()), payload['version_id']), (other_doc, str(uuid.uuid4()))]:
        assert client_p4.get(path(d, v), headers=other['headers']).status_code == 404
    client_p4.cookies.clear()
    assert client_p4.get(path(doc, payload['version_id'])).status_code == 401
    assert client_p4.get(path('invalid', payload['version_id']), headers=auth['headers']).status_code == 422
    assert client_p4.get(path(doc, 'invalid'), headers=auth['headers']).status_code == 422
    db_session.execute(text("UPDATE users SET role='ADMIN' WHERE id=:id"), {'id': other['user_id']})
    db_session.commit()
    assert client_p4.get(path(other_doc, payload['version_id']), headers=other['headers']).status_code == 404
    assert client_p4.get(path(doc, payload['version_id']), headers=other['headers']).status_code == 404


@pytest.mark.parametrize('race', ['expiry', 'revoke', 'revoked_at', 'state', 'binding'])
def test_final_write_rechecks_after_crypto(client_p4, attempt, db_session, monkeypatch, race):
    original = db_session.execute
    raced = []
    def before_consume(statement, *args, **kwargs):
        if not isinstance(statement, Update) or statement.table.name != 'signing_sessions':
            return original(statement, *args, **kwargs)
        # Crypto verification has completed. Race immediately before the conditional write.
        raced.append(True)
        with TestingSessionLocal() as concurrent:
            if race == 'expiry':
                concurrent.execute(text("UPDATE signing_sessions SET expires_at=datetime('now','-1 second')"))
            elif race == 'revoke':
                concurrent.execute(text("UPDATE public_keys SET status='REVOKED', revoked_at=CURRENT_TIMESTAMP"))
            elif race == 'revoked_at':
                concurrent.execute(text("UPDATE public_keys SET revoked_at=CURRENT_TIMESTAMP"))
            elif race == 'binding':
                concurrent.execute(text("UPDATE signing_sessions SET manifest_sha256=:h"), {'h':'f'*64})
            else:
                # Simulate another valid writer changing state at the write boundary.
                concurrent.execute(text('DROP TRIGGER version_immutable'))
                concurrent.execute(text("UPDATE document_versions SET state='DRAFT', locked_at=NULL"))
            concurrent.commit()
        return original(statement, *args, **kwargs)
    monkeypatch.setattr(db_session, "execute", before_consume)
    assert post(client_p4, attempt).status_code == 409
    assert raced == [True]
    assert_uncommitted(db_session)


def test_write_rollback_after_nonce_consumed(client_p4, attempt, db_session, monkeypatch):
    original = db_session.flush
    def fail(*args, **kwargs):
        if any(isinstance(row, Signature) for row in db_session.new):
            raise IntegrityError('test insert', {}, Exception('injected failure'))
        return original(*args, **kwargs)
    monkeypatch.setattr(db_session, 'flush', fail)
    assert post(client_p4, attempt).status_code == 409
    monkeypatch.setattr(db_session, 'flush', original)
    assert_uncommitted(db_session)
    assert post(client_p4, attempt).status_code == 201


def test_busy_writer_returns_retryable_without_partial_state(client_p4, attempt, db_session):
    db_session.execute(text('PRAGMA busy_timeout=30'))
    blocker = test_engine.raw_connection()
    try:
        blocker.execute('BEGIN IMMEDIATE')
        assert post(client_p4, attempt).status_code == 503
    finally:
        blocker.rollback()
        blocker.close()
    assert_uncommitted(db_session)
    assert post(client_p4, attempt).status_code == 201


@pytest.mark.parametrize('field,value', [
    ('manifest_version', True), ('manifest_version', '1'), ('manifest_version', 1.0),
    ('algorithm', 'ECDSA-P256'), ('signing_context', 'OTHER'),
    ('document_version_id', 'not-uuid'), ('key_id', 'ABCDEFAB-1234-1234-1234-123456789abc'),
    ('document_sha256', 'A'*64), ('signer_fingerprint', 'x'*64),
    ('signing_nonce', 'a'*43), ('signing_timestamp', 'not-date'),
    ('signing_timestamp', '2026-02-30T01:00:00.000Z'), ('unknown', 'x'),
])
def test_strict_manifest_actual_api(client_p4, attempt, field, value):
    payload = copy.deepcopy(attempt[2]); payload['manifest'][field] = value
    assert post(client_p4, attempt, payload).status_code == 422


@pytest.mark.parametrize('field', ['manifest_version', 'algorithm', 'signing_context', 'key_id', 'document_sha256', 'document_version_id', 'signer_fingerprint', 'signing_timestamp', 'signing_nonce'])
def test_all_manifest_fields_required(client_p4, attempt, field):
    payload = copy.deepcopy(attempt[2]); del payload['manifest'][field]
    assert post(client_p4, attempt, payload).status_code == 422


@pytest.mark.parametrize('body,status', [
    ('{"manifest": {"manifest_version":1,"manifest_version":1}}', 422),
    ('{"manifest":{"key_id":"a","key_\\u0069d":"b"}}', 422),
    ('{"key_id":NaN}', 422), ('{"key_id":1e999}', 422),
    ('{"key_id":"\\ud800"}',422), ('{"manifest":',400),
])
def test_raw_json_rejection_before_fastapi_parser(client_p4, attempt, body, status):
    response = client_p4.post('/api/v1/signatures', content=body, headers={**attempt[0]['headers'], 'Content-Type':'application/json'})
    assert response.status_code == status


@pytest.mark.parametrize('statement', [
    "UPDATE signatures SET signature_b64='AA=='", "UPDATE signatures SET canonical_manifest_json='{}'",
    "UPDATE signatures SET manifest_sha256='"+'f'*64+"'", "UPDATE signatures SET signer_id=id",
    "UPDATE signatures SET key_id=id", "UPDATE signatures SET version_id=id", "DELETE FROM signatures",
])
def test_raw_signature_mutations_blocked(client_p4, attempt, db_session, statement):
    assert post(client_p4, attempt).status_code == 201
    with pytest.raises(IntegrityError):
        db_session.execute(text(statement)); db_session.commit()
    db_session.rollback()
    assert db_session.scalar(select(Signature.id))
    assert db_session.scalar(select(DocumentVersion.state)) == VersionState.SIGNED


def test_different_nonce_same_version_only_one_signature(client_p4, attempt, db_session):
    auth, doc, payload, private = attempt
    manifest2 = client_p4.post(f"/api/v1/documents/{doc}/versions/{payload['version_id']}/prepare-sign", json={'key_id':payload['key_id']}, headers=auth['headers']).json()['manifest']
    payload2 = dict(payload, manifest=manifest2, signature_b64=sign_manifest_py(private,manifest2))
    assert post(client_p4, attempt).status_code == 201
    assert post(client_p4, attempt, payload2).status_code == 409
    assert len(db_session.scalars(select(Signature)).all()) == 1


def test_additive_migration_preserves_populated_evidence(client_p4, attempt, db_session, tmp_path):
    """Build historical a4 schema, copy private fixture rows, upgrade and compare every row."""
    import os
    import sqlite3
    import subprocess
    from pathlib import Path
    assert post(client_p4, attempt).status_code == 201
    path = tmp_path / 'historical.db'
    env = {**os.environ, 'DEBUG':'false', 'DATABASE_URL':f'sqlite:///{path}'}
    command = [str(Path('venv/bin/alembic').resolve())]
    result = subprocess.run(command+['upgrade','a4f000000004'], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    source = test_engine.raw_connection()
    try:
        with sqlite3.connect(path) as target:
            target.execute('PRAGMA foreign_keys=OFF')
            tables = [row[0] for row in target.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name != 'alembic_version'")]
            # Auth fixtures include committed signature, used session, key, document and user.
            for table in tables:
                rows = source.execute(f'SELECT * FROM "{table}"').fetchall()
                if rows:
                    target.executemany(f'INSERT INTO "{table}" VALUES ({",".join("?" for _ in rows[0])})',rows)
            target.commit()
            before = {table:target.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall() for table in tables}
        result = subprocess.run(command+['upgrade','head'],env=env,capture_output=True,text=True,timeout=30)
        assert result.returncode == 0,result.stderr
        result = subprocess.run(command+['check'],env=env,capture_output=True,text=True,timeout=30)
        assert result.returncode == 0,result.stderr
        with sqlite3.connect(path) as target:
            for table in tables:
                assert target.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall() == before[table]
            assert not target.execute('PRAGMA foreign_key_check').fetchall()
            for table in ['signatures','signing_sessions']:
                assert all(row[6]=='NO ACTION' for row in target.execute(f'PRAGMA foreign_key_list({table})'))
            for sql in ['DELETE FROM signatures',"UPDATE signatures SET signature_b64='AA=='"]:
                with pytest.raises(sqlite3.IntegrityError): target.execute(sql)
    finally: source.close()


def test_signature_unique_and_fk_retention(client_p4, attempt, db_session):
    assert post(client_p4, attempt).status_code == 201
    for sql in [
        "INSERT INTO signatures SELECT 'duplicate',version_id,signer_id,key_id,algorithm,canonical_manifest_json,manifest_sha256,signature_b64,signature_format,signed_at,created_at FROM signatures",
        "INSERT INTO signatures SELECT 'bad-fk','missing',signer_id,key_id,algorithm,canonical_manifest_json,manifest_sha256,signature_b64,signature_format,signed_at,created_at FROM signatures",
        "DELETE FROM users", "DELETE FROM public_keys", "DELETE FROM document_versions", "DELETE FROM documents",
    ]:
        with pytest.raises(IntegrityError): db_session.execute(text(sql));db_session.commit()
        db_session.rollback()
    assert db_session.scalar(select(Signature.id))


def test_concurrent_distinct_nonces_same_version(client_p4, attempt, db_session):
    import concurrent.futures
    import threading
    from backend.app.main import app
    from backend.app.core.database import get_db
    auth,doc,payload,private=attempt
    prepared=client_p4.post(f"/api/v1/documents/{doc}/versions/{payload['version_id']}/prepare-sign",json={'key_id':payload['key_id']},headers=auth['headers'])
    assert prepared.status_code==200
    manifest2=prepared.json()['manifest'];payload2=dict(payload,manifest=manifest2,signature_b64=sign_manifest_py(private,manifest2))
    def own_session():
        with TestingSessionLocal() as session: yield session
    old=app.dependency_overrides[get_db];app.dependency_overrides[get_db]=own_session
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures=[pool.submit(client_p4.post,'/api/v1/signatures',json=item,headers=auth['headers']) for item in [payload,payload2]]
            statuses=sorted(f.result(timeout=15).status_code for f in futures)
        assert statuses==[201,409]
    finally: app.dependency_overrides[get_db]=old
    db_session.expire_all()
    assert len(db_session.scalars(select(Signature)).all())==1
    assert len(db_session.scalars(select(SigningSession).where(SigningSession.is_used.is_(True))).all())==1
