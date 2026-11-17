import base64
import copy
import json
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, update
from backend.app.core.config import settings
from backend.app.models.certificate import Certificate, CertificateAuthority, IdentityReview, PossessionChallenge
from backend.app.models.user import User
from backend.app.models.enums import UserRole
from backend.app.services.pki_verification import inspect_certificate
from tests.test_pki import ca_files, pki, private_key, auth, registered, renewal_request, sign
from tests.test_phase5_verification import create_and_sign_document, register_and_login_user
from tests.phase2.conftest import make_pdf
from backend.app.models.signature import Signature, SigningSession
from backend.app.services import pki_verification
from backend.app.models.enums import UserStatus
from sqlalchemy.orm import Session
from tests.test_phase4_interop import bridge


def prepared(client, auth, key, private_key):
    pdf = make_pdf()
    uploaded = client.post('/api/v1/documents', files={'file':('fixture.pdf', pdf, 'application/pdf')}, headers=auth['headers']).json()
    doc, version = uploaded['document_id'], uploaded['version_id']
    response = client.post(f'/api/v1/documents/{doc}/versions/{version}/prepare-sign', json={'key_id':key['id']}, headers=auth['headers'])
    assert response.status_code == 200, response.text
    manifest = response.json()['manifest']
    return doc, {'version_id':version, 'key_id':key['id'], 'manifest':manifest, 'signature_b64':sign(private_key,manifest)}


@pytest.fixture
def signed(client_p5, auth, pki, private_key):
    key, _ = registered(client_p5, auth, private_key)
    doc, version, pdf, manifest, signature = create_and_sign_document(client_p5, auth, key, private_key)
    return key, doc, version, manifest, signature, pdf


def test_v2_internal_export_upload_share_report(client_p5, auth, signed):
    key, doc, version, manifest, sig, pdf = signed
    assert manifest['manifest_version'] == 2
    assert manifest['certificate_sha256'] == key['certificate']['fingerprint']
    result = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/verify', headers=auth['headers'])
    assert result.status_code == 200, result.text
    body = result.json()
    assert body['summary_status'] == 'VERIFIED', body
    assert body['results']['certificate_chain'] == 'VALID'
    assert body['results']['identity_assurance'] == 'ACCOUNT_BOUND'
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package', headers=auth['headers'])
    assert package.status_code == 200, package.text
    assert package.json()['package_version'] == 2
    uploaded = client_p5.post('/api/v1/verify/upload', files={'file': ('report.pdf', pdf, 'application/pdf')},
        data={'package_json': json.dumps(package.json())})
    assert uploaded.status_code == 200, uploaded.text
    assert uploaded.json()['summary_status'] == 'VERIFIED', uploaded.text
    report = client_p5.post('/api/v1/verify/report', json={'receipt_id': body['verification_receipt']}, headers=auth['headers'])
    assert report.status_code == 200, report.text
    assert report.json()['verification_result']['results']['certificate_chain'] == 'VALID'
    share = client_p5.post('/api/v1/shares', json={'version_id': version}, headers=auth['headers'])
    assert share.status_code == 201, share.text


def test_certificate_public_and_detached_possession(client, auth, pki, private_key):
    key, _ = registered(client, auth, private_key)
    cert = key['certificate']
    result = client.post('/api/v1/verify/certificate', json={'certificate_pem': cert['certificate_pem']})
    assert result.status_code == 200 and result.json()['verified'], result.text
    challenge = client.post('/api/v1/pki/possession/challenge', json={'certificate_id': cert['id']}, headers=auth['headers'])
    assert challenge.status_code == 201, challenge.text
    body = challenge.json()
    proof = {'challenge_id': body['challenge_id'], 'signature_b64': sign(private_key, body['payload'])}
    verified = client.post('/api/v1/pki/possession/verify', json=proof, headers=auth['headers'])
    assert verified.status_code == 200 and verified.json()['possession'] == 'VERIFIED', verified.text
    assert client.post('/api/v1/pki/possession/verify', json=proof, headers=auth['headers']).status_code == 409
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    message = b'Identity signature test'
    sig = private_key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
    result = client.post('/api/v1/verify/signature', json={'certificate_pem': cert['certificate_pem'],
        'message_b64': base64.b64encode(message).decode(), 'signature_b64': base64.b64encode(sig).decode()})
    assert result.status_code == 200 and result.json()['verified'], result.text


def test_review_snapshot_and_renewed_certificate(client, auth, pki, private_key, db_session):
    key, _ = registered(client, auth, private_key)
    req = client.post('/api/v1/pki/identity-requests', json={'full_name': 'Reviewed Person', 'evidence_reference': 'in-person:case-42'}, headers=auth['headers'])
    assert req.status_code == 201, req.text
    review_id = req.json()['id']
    assert client.post('/api/v1/admin/pki/identity-requests/'+review_id+'/decision',
        json={'status': 'APPROVED', 'reason': 'Matched evidence'}, headers=auth['headers']).status_code == 403
    admin = register_and_login_user(client, 'pki-admin@cyber.edu')
    db_session.execute(update(User).where(User.id == admin['user_id']).values(role=UserRole.ADMIN))
    db_session.commit()
    decision = client.post('/api/v1/admin/pki/identity-requests/'+review_id+'/decision',
        json={'status': 'APPROVED', 'reason': 'Matched evidence'}, headers=admin['headers'])
    assert decision.status_code == 200, decision.text
    # Restore owner CSRF cookie after switching accounts in the same test client.
    auth = register_and_login_user(client, 'pki-owner@cyber.edu')
    proof = renewal_request(client, auth, private_key, key['id'], key['certificate']['id'])
    renewed = client.post('/api/v1/certificates/'+key['certificate']['id']+'/renew', json=proof, headers=auth['headers'])
    assert renewed.status_code == 201, renewed.text
    assert renewed.json()['identity_assurance'] == 'ADMIN_REVIEWED'
    assert 'Reviewed Person' in renewed.json()['subject']
    assert inspect_certificate(db_session, renewed.json()['certificate_pem'])['identity_assurance'] == 'ADMIN_REVIEWED'
    assert inspect_certificate(db_session, key['certificate']['certificate_pem'])['identity_assurance'] == 'ACCOUNT_BOUND'


@pytest.mark.parametrize('mutation', ['certificate', 'fingerprint', 'user', 'root', 'spki'])
def test_v2_package_substitution_fails(client_p5, auth, signed, private_key, mutation):
    key, doc, version, manifest, sig, pdf = signed
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package', headers=auth['headers']).json()
    if mutation == 'certificate':
        proof = renewal_request(client_p5, auth, private_key, key['id'], key['certificate']['id'])
        replacement = client_p5.post('/api/v1/certificates/'+key['certificate']['id']+'/renew', json=proof, headers=auth['headers']).json()
        package['certificate_pem'] = replacement['certificate_pem']
    elif mutation == 'fingerprint':
        package['manifest']['certificate_sha256'] = '0'*64
    elif mutation == 'user':
        package['manifest']['signer_user_id'] = 'another-user'
    elif mutation == 'root':
        package['issuer_chain_pem'] = ['bad certificate']
        # A bogus attached root cannot replace or override the server's pinned registry root.
        result = client_p5.post('/api/v1/verify/upload', files={'file': ('r.pdf', pdf, 'application/pdf')}, data={'package_json':json.dumps(package)})
        assert result.status_code == 200 and result.json()['results']['certificate_chain'] == 'VALID'
        return
    else:
        package['public_key_spki_pem'] = 'invalid key'*12
    result = client_p5.post('/api/v1/verify/upload', files={'file': ('r.pdf', pdf, 'application/pdf')}, data={'package_json':json.dumps(package)})
    assert result.status_code == 200 and result.json()['summary_status'] != 'VERIFIED', result.text


def test_offline_revocation_unknown_and_expired_rejected(client, auth, pki, private_key, db_session):
    key, _ = registered(client, auth, private_key)
    cert = key['certificate']
    result = inspect_certificate(None, cert['certificate_pem'])
    assert result['certificate_chain'] == 'VALID'
    assert result['certificate_revocation'] == 'UNKNOWN' and not result['verified']
    client.post('/api/v1/certificates/'+cert['id']+'/revoke', json={}, headers=auth['headers'])
    result = client.post('/api/v1/verify/certificate', json={'certificate_pem': cert['certificate_pem']}).json()
    assert result['certificate_revocation'] == 'REVOKED' and not result['verified']


@pytest.mark.parametrize('change', ['certificate', 'authority', 'account', 'pin', 'expiry'])
def test_submit_final_gate_rechecks_certificate_policy(client_p5, auth, pki, private_key, db_session, monkeypatch, change):
    key, _ = registered(client_p5, auth, private_key)
    doc, payload = prepared(client_p5, auth, key, private_key)
    original = db_session.execute
    raced = []
    def before_consume(statement, *args, **kwargs):
        if getattr(statement, 'is_update', False) and getattr(statement, 'table', None).name == 'signing_sessions' and not raced:
            raced.append(True)
            if change == 'pin':
                monkeypatch.setattr(settings, 'CA_TRUSTED_ROOT_SHA256', '0'*64)
            elif change == 'expiry':
                cert = db_session.get(Certificate, key['certificate']['id'])
                future = cert.not_after.replace(tzinfo=timezone.utc)+timedelta(seconds=1)
                class Clock(datetime):
                    @classmethod
                    def now(cls, tz=None): return future
                monkeypatch.setattr(pki_verification, 'datetime', Clock)
            else:
                with Session(db_session.get_bind()) as other:
                    if change == 'certificate':
                        other.execute(update(Certificate).where(Certificate.id==key['certificate']['id']).values(revoked_at=datetime.now(timezone.utc),revocation_reason='KEY_COMPROMISE'))
                    elif change == 'authority':
                        other.execute(update(CertificateAuthority).values(trust_status='COMPROMISED',issuance_enabled=False,compromised_at=datetime.now(timezone.utc)))
                    else:
                        other.execute(update(User).where(User.id==auth['user_id']).values(status=UserStatus.DISABLED))
                    other.commit()
        return original(statement,*args,**kwargs)
    monkeypatch.setattr(db_session,'execute',before_consume)
    response = client_p5.post('/api/v1/signatures',json=payload,headers=auth['headers'])
    assert response.status_code == 409, response.text
    assert raced == [True]
    assert db_session.scalar(select(Signature.id)) is None
    assert db_session.scalar(select(SigningSession.is_used)) is False


def test_share_gate_rechecks_revocation_and_public_output(client_p5, auth, signed, db_session, monkeypatch):
    from backend.app.services.verification_service import VerificationService
    key, doc, version, manifest, sig, pdf = signed
    original = VerificationService.verify_shared
    def race(db, version, signature, storage):
        result = original(db,version,signature,storage)
        with Session(db_session.get_bind()) as other:
            other.execute(update(Certificate).where(Certificate.id==key['certificate']['id']).values(revoked_at=datetime.now(timezone.utc),revocation_reason='KEY_COMPROMISE'))
            other.commit()
        return result
    monkeypatch.setattr(VerificationService,'verify_shared',race)
    response = client_p5.post('/api/v1/shares',json={'version_id':version},headers=auth['headers'])
    assert response.status_code in (409,422), response.text


def test_signature_package_and_certificate_without_pdf(client_p5, auth, signed):
    key, doc, version, manifest, sig, pdf = signed
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package', headers=auth['headers']).json()
    response = client_p5.post('/api/v1/verify/signature', json={
        'certificate_pem': key['certificate']['certificate_pem'], 'signature_package': json.dumps(package)})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['verified'] and result['cryptographic_validity'] == 'VALID', result
    assert result['purpose'] == 'SIGNATURE_PACKAGE' and result['document_integrity'] == 'UNKNOWN'
    assert 'message_sha256' not in result


def test_certificate_information_without_account_san(client, pki):
    from cryptography import x509
    pem = (pki / 'ca/ca-cert.pem').read_text()
    cert = x509.load_pem_x509_certificate(pem.encode())
    response = client.post('/api/v1/verify/certificate', json={'certificate_pem': pem})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['subject'] == cert.subject.rfc4514_string()
    assert result['issuer'] == cert.issuer.rfc4514_string()
    assert result['not_before'] and result['not_after'] and result['fingerprint']
    assert result['serial'] == format(cert.serial_number, 'X')
    assert result['certificate_validity'] == 'VALID'
    assert not result['verified'] and result['user_id'] is None
    assert 'cryptographic_validity' not in result


def test_signature_package_legacy_uses_uploaded_certificate_key(client_p5, auth, signed, private_key):
    key, doc, version, manifest, sig, pdf = signed
    legacy_manifest = {name: value for name, value in manifest.items() if name not in {'signer_user_id', 'certificate_sha256'}}
    legacy_manifest.update(manifest_version=1, signing_context='DOCSIGN_DOCUMENT_SIGNATURE_V1')
    package = {'package_version': 1, 'signature_format': 'DETACHED_JCS_V1',
        'manifest': legacy_manifest, 'signature_b64': sign(private_key, legacy_manifest)}
    response = client_p5.post('/api/v1/verify/signature', json={
        'certificate_pem': key['certificate']['certificate_pem'], 'signature_package': json.dumps(package)})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['cryptographic_validity'] == 'VALID' and result['document_integrity'] == 'UNKNOWN'
    assert any(warning.startswith('LEGACY_NO_CERTIFICATE_BINDING') for warning in result['warnings'])
    invalid = client_p5.post('/api/v1/verify/signature', json={
        'certificate_pem': 'invalid-certificate' * 4, 'signature_package': json.dumps(package)})
    assert invalid.status_code == 200 and not invalid.json()['verified']
    assert invalid.json()['cryptographic_validity'] == 'UNVERIFIABLE'


@pytest.mark.parametrize('mutation', ['manifest', 'signature', 'certificate_hash', 'identity', 'wrong_key', 'invalid_certificate', 'revoked'])
def test_signature_package_failures(client_p5, auth, signed, private_key, mutation):
    key, doc, version, manifest, sig, pdf = signed
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package', headers=auth['headers']).json()
    pem = key['certificate']['certificate_pem']
    if mutation == 'manifest':
        package['manifest']['document_sha256'] = '0' * 64
    elif mutation == 'signature':
        package['signature_b64'] = base64.b64encode(b'\0' * 384).decode()
    elif mutation == 'certificate_hash':
        package['manifest']['certificate_sha256'] = '0' * 64
        package['signature_b64'] = sign(private_key, package['manifest'])
    elif mutation == 'identity':
        package['manifest']['signer_user_id'] = 'another-user'
        package['signature_b64'] = sign(private_key, package['manifest'])
    elif mutation == 'wrong_key':
        from cryptography.hazmat.primitives.asymmetric import rsa
        other_key, _ = registered(client_p5, auth, rsa.generate_private_key(public_exponent=65537, key_size=3072))
        pem = other_key['certificate']['certificate_pem']
    elif mutation == 'invalid_certificate':
        pem = 'invalid-certificate' * 4
    else:
        response = client_p5.post('/api/v1/certificates/' + key['certificate']['id'] + '/revoke', json={}, headers=auth['headers'])
        assert response.status_code == 200, response.text
    response = client_p5.post('/api/v1/verify/signature', json={'certificate_pem': pem, 'signature_package': json.dumps(package)})
    assert response.status_code == 200 and not response.json()['verified'], response.text
    assert response.json()['document_integrity'] == 'UNKNOWN'


def test_signature_package_renewal_substitution(client_p5, auth, signed, private_key):
    key, doc, version, manifest, sig, pdf = signed
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package', headers=auth['headers']).json()
    proof = renewal_request(client_p5, auth, private_key, key['id'], key['certificate']['id'])
    renewed = client_p5.post('/api/v1/certificates/' + key['certificate']['id'] + '/renew', json=proof, headers=auth['headers']).json()
    response = client_p5.post('/api/v1/verify/signature', json={
        'certificate_pem': renewed['certificate_pem'], 'signature_package': json.dumps(package)})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['cryptographic_validity'] == 'VALID'
    assert result['certificate_binding'] == 'MISMATCH' and not result['verified']


@pytest.mark.parametrize('raw', ['{}', '{"package_version":2,"package_version":2}', 'not-json'])
def test_signature_package_rejects_invalid_json(client, pki, raw):
    response = client.post('/api/v1/verify/signature', json={'certificate_pem':'x' * 64, 'signature_package':raw})
    assert response.status_code == 422, response.text


def test_v2_three_file_verification_and_renewal_substitution(client_p5, auth, signed, private_key):
    key, doc, version, manifest, sig, pdf = signed
    package = client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package',headers=auth['headers']).json()
    def verify(pem):
        return client_p5.post('/api/v1/verify/upload',files={'file':('f.pdf',pdf,'application/pdf'),
            'certificate_file':('c.pem',pem,'application/x-pem-file')},data={'package_json':json.dumps(package)})
    assert verify(key['certificate']['certificate_pem']).json()['summary_status'] == 'VERIFIED'
    proof = renewal_request(client_p5,auth,private_key,key['id'],key['certificate']['id'])
    renewed = client_p5.post('/api/v1/certificates/'+key['certificate']['id']+'/renew',json=proof,headers=auth['headers']).json()
    result = verify(renewed['certificate_pem'])
    assert result.status_code == 200 and result.json()['results']['certificate_binding'] == 'MISMATCH', result.text
    assert result.json()['summary_status'] != 'VERIFIED'


def test_current_ca_pin_and_compromise_irreversible(client, auth, pki, private_key, db_session):
    key, _ = registered(client,auth,private_key)
    db_session.execute(update(User).where(User.id==auth['user_id']).values(role=UserRole.ADMIN));db_session.commit()
    roots=client.get('/api/v1/admin/pki/authorities',headers=auth['headers']).json()
    root=roots[0]
    path='/api/v1/admin/pki/authorities/'+root['id']
    assert client.post(path,json={'trust_status':'COMPROMISED','issuance_enabled':False},headers=auth['headers']).status_code == 200
    assert client.post(path,json={'trust_status':'TRUSTED','issuance_enabled':True},headers=auth['headers']).status_code == 409
    result=client.post('/api/v1/verify/certificate',json={'certificate_pem':key['certificate']['certificate_pem']}).json()
    assert result['certificate_revocation']=='REVOKED' and not result['verified']
    readiness=client.get('/api/v1/admin/pki/status',headers=auth['headers']).json()
    assert not readiness['ready']


def test_identity_and_possession_permissions(client, auth, pki, private_key, db_session):
    key,_=registered(client,auth,private_key)
    other=register_and_login_user(client,'pki-other@cyber.edu')
    assert client.post('/api/v1/pki/possession/challenge',json={'certificate_id':key['certificate']['id']},headers=other['headers']).status_code==404
    assert client.get('/api/v1/admin/pki/identity-requests',headers=other['headers']).status_code==403
    assert client.post('/api/v1/pki/identity-requests',json={'full_name':'Other User','evidence_reference':'private'},headers={}).status_code==403
    db_session.execute(update(User).where(User.id==other['user_id']).values(role=UserRole.ADMIN));db_session.commit()
    req=client.post('/api/v1/pki/identity-requests',json={'full_name':'Other User','evidence_reference':'private'},headers=other['headers']).json()
    assert client.post('/api/v1/admin/pki/identity-requests/'+req['id']+'/decision',json={'status':'APPROVED','reason':'self'},headers=other['headers']).status_code==409


def test_pki_public_limits_and_duplicate_json(client, pki):
    assert client.post('/api/v1/verify/certificate',json={'certificate_pem':'X'*16385}).status_code==422
    assert client.post('/api/v1/verify/signature',content=b'x'*1500001,headers={'Content-Type':'application/json'}).status_code==413
    raw='{"certificate_pem":"'+('x'*64)+'","certificate_pem":"'+('y'*64)+'"}'
    assert client.post('/api/v1/verify/certificate',content=raw,headers={'Content-Type':'application/json'}).status_code==422


def test_certificate_failures_alerts_and_no_identity_claims_in_audit(client, auth, pki, private_key, db_session):
    from backend.app.services.dashboard_service import dashboard_stats
    from backend.app.models.audit import AuditLog
    key,_=registered(client,auth,private_key)
    client.post('/api/v1/pki/identity-requests',json={'full_name':'Private Name','evidence_reference':'SECRET_REFERENCE'},headers=auth['headers'])
    db_session.info['audit_context'] = {'client_ip':'127.0.0.1'}
    for _ in range(3):
        assert client.post('/api/v1/verify/certificate',json={'certificate_pem':'X'*64}).status_code==200
    stats=dashboard_stats(db_session)
    assert any(a['code']=='REPEATED_CERTIFICATE_FAILURE' for a in stats['alerts']), [
        (a.action,a.status,a.client_ip,str(a.created_at)) for a in db_session.scalars(select(AuditLog))]
    assert stats['pki_counts']['certificates']==1 and stats['pki_counts']['pending_reviews']==1
    details=' '.join(db_session.scalars(select(AuditLog.details_json)))
    assert 'SECRET_REFERENCE' not in details and 'Private Name' not in details


def test_actual_frontend_certificate_binding_and_v2_signer(client_p5, auth, pki, bridge):
    public=bridge('keygen')
    challenge=client_p5.post('/api/v1/keys/challenge',json={'algorithm':'RSA-PSS-3072','fingerprint':public['fingerprint']},headers=auth['headers']).json()
    payload=dict(schema_version=1,purpose='REGISTER_KEY',challenge_id=challenge['challenge_id'],
        challenge_nonce=challenge['challenge_nonce'],user_id=auth['user_id'],algorithm='RSA-PSS-3072',fingerprint=public['fingerprint'])
    response=client_p5.post('/api/v1/keys',json={'public_key_pem':public['public_key_pem'],'algorithm':'RSA-PSS-3072',
        'challenge_id':challenge['challenge_id'],'pop_signature_b64':bridge('pop',payload)['signature']},headers=auth['headers'])
    assert response.status_code==201,response.text
    key=response.json()
    uploaded=client_p5.post('/api/v1/documents',files={'file':('f.pdf',make_pdf(),'application/pdf')},headers=auth['headers']).json()
    doc,version=uploaded['document_id'],uploaded['version_id']
    prepared=client_p5.post(f'/api/v1/documents/{doc}/versions/{version}/prepare-sign',json={'key_id':key['id']},headers=auth['headers']).json()
    certificate_request={**prepared,'user_id':auth['user_id']}
    assert bridge('certificate',certificate_request)=={'valid':True}
    substituted=copy.deepcopy(certificate_request)
    substituted['manifest']['certificate_sha256']='0'*64
    assert 'error' in bridge('certificate',substituted)
    signed=bridge('sign',prepared['manifest'])
    assert 'signature' in signed,signed
    response=client_p5.post('/api/v1/signatures',json={'version_id':version,'key_id':key['id'],
        'manifest':prepared['manifest'],'signature_b64':signed['signature']},headers=auth['headers'])
    assert response.status_code==201,response.text
