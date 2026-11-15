"""Full real TypeScript/WebCrypto→Python persistence→export→independent HTTP verification."""
from tests.test_phase4_interop import bridge
from tests.test_phase4_signatures import client_p4, storage_p4, register_and_login_user, upload_and_ready_doc
from backend.app.core.database import get_db
from backend.app.main import app
from backend.app.services.verification_service import _ip_request_history
import json

def test_webcrypto_package_and_verifier_without_original_db(client_p4,bridge):
    _ip_request_history.clear()
    auth=register_and_login_user(client_p4,'interop_p5@cyber.edu');h=auth['headers'];public=bridge('keygen')
    response=client_p4.post('/api/v1/keys/challenge',json={'algorithm':'RSA-PSS-3072','fingerprint':public['fingerprint'],'purpose':'REGISTER_KEY'},headers=h)
    assert response.status_code==201
    challenge=response.json();pop=dict(algorithm='RSA-PSS-3072',challenge_id=challenge['challenge_id'],challenge_nonce=challenge['challenge_nonce'],fingerprint=public['fingerprint'],purpose='REGISTER_KEY',schema_version=1,user_id=auth['user_id'])
    response=client_p4.post('/api/v1/keys',json={'algorithm':'RSA-PSS-3072','public_key_pem':public['public_key_pem'],'challenge_id':challenge['challenge_id'],'pop_signature_b64':bridge('pop',pop)['signature']},headers=h)
    assert response.status_code==201;key=response.json()
    doc,version,digest,pdf=upload_and_ready_doc(client_p4,h)
    prepared=client_p4.post(f'/api/v1/documents/{doc}/versions/{version}/prepare-sign',json={'key_id':key['id']},headers=h)
    assert prepared.status_code==200;manifest=prepared.json()['manifest']
    signature=bridge('sign',manifest)['signature']
    signed=client_p4.post('/api/v1/signatures',json=dict(version_id=version,key_id=key['id'],manifest=manifest,signature_b64=signature),headers=h)
    assert signed.status_code==201
    exported=client_p4.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package',headers=h)
    assert exported.status_code==200;package=exported.json()
    assert package['manifest']==manifest and package['signature_b64']==signature
    client_p4.cookies.clear()
    def verify():
        return client_p4.post('/api/v1/verify/upload',files={'file':('fixture.pdf',pdf,'application/pdf'),'package':('signature-package.json',json.dumps(package).encode(),'application/json')})
    response=verify();assert response.status_code==200,response.text
    assert response.json()['results']['cryptographic_validity']=='VALID'
    assert response.json()['results']['document_integrity']=='UNCHANGED'
    assert response.json()['results']['key_ownership']=='VERIFIED_POP'
    # Same real HTTP route in an environment with NO database object/access at all.
    # Any query/add/commit against the source DB is impossible through this dependency.
    original=app.dependency_overrides[get_db]
    def no_database():yield None
    app.dependency_overrides[get_db]=no_database
    try:
        response=verify();assert response.status_code==200,response.text
        data=response.json();d=data['results']
        assert d['cryptographic_validity']=='VALID' and d['document_integrity']=='UNCHANGED'
        assert d['key_ownership']=='UNVERIFIED' and d['certificate_trust']=='SELF_REGISTERED'
        assert d['key_revocation_status']=='UNKNOWN' and d['server_recorded_at'] is None
        assert d['trusted_timestamp'] is None and d['timestamp_trust_level']=='DECLARED'
        report=client_p4.post('/api/v1/verify/report',json={'receipt_id':data['verification_receipt']})
        assert report.status_code==200
        assert report.json()['verification_result']=={k:v for k,v in data.items() if k not in ('verification_receipt','receipt_expires_at')}
    finally:app.dependency_overrides[get_db]=original
