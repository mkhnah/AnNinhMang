import base64
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import secrets
import tempfile

from asn1crypto import cms
import pytest
from sqlalchemy import select, text

from backend.app.core.config import settings
from backend.app.models.signature import Signature, SigningSession
from backend.app.models.timestamp import SignatureTimestamp
from backend.app.services.timestamp_service import issue_timestamp, verify_timestamp
from backend.app.services import timestamp_service
from scripts.init_tsa import initialize_tsa
from tests.test_pki import ca_files, pki, private_key, auth, registered
from tests.test_pki_v2 import prepared
from tests.test_phase5_verification import create_and_sign_document


@pytest.fixture
def tsa(pki, monkeypatch):
    with tempfile.TemporaryDirectory(prefix='docsign-tsa-test-', dir='/tmp') as folder:
        values = initialize_tsa(Path(folder)/'tsa')
        for name,value in values.items():
            monkeypatch.setattr(settings,name,value=='true' if name=='TSA_ENABLED' else value)
        yield values


@pytest.fixture
def timestamped(client_p5, auth, tsa, private_key):
    key, _ = registered(client_p5, auth, private_key)
    doc, version, pdf, manifest, signature = create_and_sign_document(client_p5, auth, key, private_key)
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package', headers=auth['headers']).json()
    return key, doc, version, pdf, package


def test_real_rfc3161_token_and_binding(tsa):
    signature = base64.b64encode(secrets.token_bytes(384)).decode()
    token = issue_timestamp(signature)
    proof = verify_timestamp(token, signature)
    assert proof['time'] <= datetime.now(timezone.utc)
    assert proof['fingerprint'] == settings.TSA_SIGNER_SHA256
    assert proof['scope'] == 'DOCSIGN_PRIVATE_TSA'
    with pytest.raises(ValueError, match='different signature'):
        verify_timestamp(token, base64.b64encode(secrets.token_bytes(384)).decode())


def test_tsa_internal_pdf_signature_report_and_share(client_p5, auth, timestamped, db_session):
    key, doc, version, pdf, package = timestamped
    assert package['timestamp_token_b64']
    assert db_session.scalar(select(SignatureTimestamp.signature_id))
    internal = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/verify',headers=auth['headers'])
    assert internal.status_code == 200, internal.text
    body = internal.json()
    assert body['summary_status'] == 'VERIFIED', body
    for result in [body, client_p5.post('/api/v1/verify/upload', files={'file':('fixture.pdf',pdf,'application/pdf')},
            data={'package_json':json.dumps(package)}).json()]:
        dims = result['results']
        assert dims['timestamp_trust_level'] == 'TRUSTED_TSA' and dims['timestamp_status'] == 'VALID', result
        assert dims['trusted_timestamp'] and dims['timestamp_authority'] == 'CN=DocSign Internal TSA'
        assert dims['timestamp_scope'] == 'DOCSIGN_PRIVATE_TSA'
        assert 'NO_TRUSTED_TIMESTAMP' not in result['warning_codes']
    signature = client_p5.post('/api/v1/verify/signature',json={'certificate_pem':key['certificate']['certificate_pem'],
        'signature_package':json.dumps(package)}).json()
    assert signature['verified'] and signature['timestamp_trust'] == 'TRUSTED_TSA'
    report = client_p5.post('/api/v1/verify/report',json={'receipt_id':body['verification_receipt']},headers=auth['headers']).json()
    assert report['verification_result']['results']['trusted_timestamp'] == body['results']['trusted_timestamp']
    share = client_p5.post('/api/v1/shares',json={'version_id':version},headers=auth['headers'])
    assert share.status_code == 201, share.text
    token = share.json()['share_url'].rsplit('/',1)[1]
    public = client_p5.get('/api/v1/verify/share/'+token).json()
    assert public['results']['results']['timestamp_trust_level'] == 'TRUSTED_TSA'


@pytest.mark.parametrize('mutation',['token_signature','imprint','signer_pin','root_pin','future'])
def test_timestamp_tampering_or_trust_failures(client_p5, auth, timestamped, monkeypatch, mutation):
    key, doc, version, pdf, package = timestamped
    if mutation == 'token_signature':
        token = cms.ContentInfo.load(base64.b64decode(package['timestamp_token_b64']))
        signature = token['content']['signer_infos'][0]['signature'].native
        token['content']['signer_infos'][0]['signature'] = bytes([signature[0]^1])+signature[1:]
        package['timestamp_token_b64'] = base64.b64encode(token.dump()).decode()
    elif mutation == 'imprint':
        package['timestamp_token_b64'] = issue_timestamp(base64.b64encode(secrets.token_bytes(384)).decode())
    elif mutation == 'signer_pin':
        monkeypatch.setattr(settings, 'TSA_SIGNER_SHA256', '0'*64)
    elif mutation == 'root_pin':
        monkeypatch.setattr(settings, 'TSA_ROOT_SHA256', '0'*64)
    else:
        past = datetime.now(timezone.utc)-timedelta(days=1)
        class Clock(datetime):
            @classmethod
            def now(cls,tz=None): return past
        monkeypatch.setattr(timestamp_service,'datetime',Clock)
    response = client_p5.post('/api/v1/verify/upload', files={'file':('fixture.pdf',pdf,'application/pdf')},
        data={'package_json':json.dumps(package)})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['results']['cryptographic_validity'] == 'VALID'
    assert result['results']['timestamp_status'] == 'INVALID'
    assert result['results']['trusted_timestamp'] is None
    assert result['results']['timestamp_trust_level'] != 'TRUSTED_TSA'
    assert result['summary_status'] == 'UNVERIFIABLE'
    assert 'TIMESTAMP_INVALID' in result['warning_codes']


def test_tsa_failure_does_not_consume_nonce_or_store_signature(client_p5, auth, tsa, private_key, db_session, monkeypatch):
    key, _ = registered(client_p5,auth,private_key)
    doc, payload = prepared(client_p5,auth,key,private_key)
    monkeypatch.setattr(settings,'TSA_OPENSSL_BINARY','/nonexistent/docsign-openssl')
    response = client_p5.post('/api/v1/signatures',json=payload,headers=auth['headers'])
    assert response.status_code == 503, response.text
    assert db_session.scalar(select(Signature.id)) is None
    assert db_session.scalar(select(SignatureTimestamp.signature_id)) is None
    assert db_session.scalar(select(SigningSession.is_used)) is False
    monkeypatch.setattr(settings,'TSA_OPENSSL_BINARY','openssl')
    assert client_p5.post('/api/v1/signatures',json=payload,headers=auth['headers']).status_code == 201


def test_timestamp_evidence_is_immutable(client_p5, auth, timestamped, db_session):
    from sqlalchemy.exc import IntegrityError
    for sql in ['UPDATE signature_timestamps SET token_b64=token_b64', 'DELETE FROM signature_timestamps']:
        with pytest.raises(IntegrityError):
            db_session.execute(text(sql))
        db_session.rollback()


def test_legacy_signature_without_tsa_remains_declared(client_p5, auth, pki, private_key):
    key, _ = registered(client_p5,auth,private_key)
    doc, version, pdf, manifest, sig = create_and_sign_document(client_p5,auth,key,private_key)
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package',headers=auth['headers']).json()
    assert package['timestamp_token_b64'] is None
    result = client_p5.post('/api/v1/verify/upload',files={'file':('f.pdf',pdf,'application/pdf')},data={'package_json':json.dumps(package)}).json()
    assert result['summary_status'] == 'VERIFIED'
    assert result['results']['timestamp_trust_level'] == 'DECLARED'
    assert result['results']['timestamp_status'] == 'ABSENT'


def test_timestamp_migration_preserves_history_and_guards(tmp_path):
    import os
    import subprocess
    import sys
    import sqlite3
    database = tmp_path / 'timestamps.db'
    env = {**os.environ, 'DATABASE_URL':'sqlite:///'+str(database), 'PKI_ENABLED':'false', 'TSA_ENABLED':'false'}
    def migrate(*args, success=True):
        result = subprocess.run([sys.executable,'-m','alembic',*args],env=env,capture_output=True,text=True,timeout=40)
        assert (result.returncode==0) is success, result.stdout+result.stderr
    migrate('upgrade','b0f000000010')
    with sqlite3.connect(database) as connection:
        connection.execute("INSERT INTO users(id,email,full_name,password_hash,role,status,failed_login_attempts,created_at,updated_at) VALUES ('historical','history@cyber.edu','Retained','unused','USER','ACTIVE',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
    migrate('upgrade','head')
    with sqlite3.connect(database) as connection:
        assert connection.execute('SELECT full_name FROM users').fetchone()[0]=='Retained'
        assert connection.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name IN ('timestamp_no_update','timestamp_no_delete','signature_no_update','signature_no_delete')").fetchone()[0]==4
        assert connection.execute('PRAGMA foreign_key_check').fetchall()==[]
    migrate('downgrade','b0f000000010')
    migrate('upgrade','head')
