"""Security-audit regressions. Every test uses the private pytest database/storage."""
import copy
import json
import base64
import hashlib
import uuid
import pytest
from sqlalchemy import text
from tests.test_phase5_verification import (client_p5, storage_p5, register_and_login_user,
    generate_test_rsa_3072, register_user_key, create_and_sign_document, sign_manifest_py)

@pytest.fixture
def evidence(client_p5):
    auth=register_and_login_user(client_p5)
    private,_,pem,fp=generate_test_rsa_3072()
    key=register_user_key(client_p5,auth,private,pem,fp)
    doc,version,pdf,manifest,signature=create_and_sign_document(client_p5,auth,key,private)
    package=client_p5.get(f'/api/v1/documents/{doc}/versions/{version}/signature-package',headers=auth['headers']).json()
    return dict(auth=auth,private=private,key=key,doc=doc,version=version,pdf=pdf,manifest=manifest,package=package)

def internal(client,e):
    return client.get(f"/api/v1/documents/{e['doc']}/versions/{e['version']}/verify",headers=e['auth']['headers'])

def upload(client,e,package=None):
    return client.post('/api/v1/verify/upload',files={'file':('audit.pdf',e['pdf'],'application/pdf')},data={'package_json':json.dumps(e['package'] if package is None else package)})

@pytest.mark.parametrize('corruption',['hash','duplicate','version','key','signer','format','noncanonical','context','fingerprint'])
def test_internal_evidence_never_false_verified(client_p5,evidence,db_session,corruption):
    e=evidence;m=copy.deepcopy(e['manifest']);values={}
    if corruption=='hash':values['manifest_sha256']='0'*64
    elif corruption=='duplicate':values['canonical_manifest_json']='{"manifest_version":2,'+json.dumps(m)[1:]
    elif corruption=='version':m['document_version_id']=str(uuid.uuid4())
    elif corruption=='key':m['key_id']=str(uuid.uuid4())
    elif corruption=='signer':
        other=register_and_login_user(client_p5,'other_signer@cyber.edu');values['signer_id']=other['user_id']
    elif corruption=='format':
        # Existing CHECK rejects invalid format. Test the engine with a corrupted ORM view instead.
        from backend.app.models.signature import Signature
        from sqlalchemy.orm.attributes import set_committed_value
        row=db_session.query(Signature).first();set_committed_value(row,'signature_format','OTHER')
    elif corruption=='noncanonical':values['canonical_manifest_json']=json.dumps(m,indent=2)
    elif corruption=='context':m['signing_context']='OTHER'
    elif corruption=='fingerprint':m['signer_fingerprint']='0'*64
    if corruption in ['version','key','context','fingerprint']:
        from backend.app.crypto.jcs import canonicalize_jcs
        canonical=canonicalize_jcs(m);values.update(canonical_manifest_json=canonical.decode(),manifest_sha256=hashlib.sha256(canonical).hexdigest(),signature_b64=sign_manifest_py(e['private'],m))
    if values:
        db_session.execute(text('DROP TRIGGER signature_no_update'))
        for field,value in values.items():db_session.execute(text(f'UPDATE signatures SET {field}=:value'),{'value':value})
        db_session.commit()
    result=internal(client_p5,e)
    assert result.status_code==200,result.text
    assert result.json()['summary_status']!='VERIFIED'
    assert result.json()['evidence_consistency']=='INCONSISTENT'
    assert result.json()['results']['key_ownership']!='VERIFIED_POP'
    if corruption=='format':db_session.rollback()

@pytest.mark.parametrize('change',[
    {'package_version':999},{'package_version':True},{'package_version':1.0},{'signature_format':'OTHER'},
    {'signature_b64':'!'*512},{'signature_b64':'A'*508},{'extra':'field'},
])
def test_strict_package_actual_api(client_p5,evidence,change):
    p=copy.deepcopy(evidence['package']);p.update(change)
    assert upload(client_p5,evidence,p).status_code==422

@pytest.mark.parametrize('field',['package_version','signature_format'])
def test_package_fields_required(client_p5,evidence,field):
    p=copy.deepcopy(evidence['package']);del p[field]
    assert upload(client_p5,evidence,p).status_code==422

def test_missing_key_and_timestamp_semantics(client_p5,evidence):
    p=copy.deepcopy(evidence['package']);p.pop('public_key_spki_pem')
    # Different registry ID avoids trusted DB evidence; no attached key is a supported contract.
    p['manifest']['key_id']=str(uuid.uuid4());p['signature_b64']=sign_manifest_py(evidence['private'],p['manifest'])
    r=upload(client_p5,evidence,p);assert r.status_code==200,r.text
    d=r.json()['results']
    assert d['cryptographic_validity']=='UNVERIFIABLE'
    assert d['certificate_trust']==d['key_revocation_status']==d['key_ownership']=='UNKNOWN'
    assert d['server_recorded_at'] is None and d['server_timestamp'] is None
    assert d['declared_timestamp'] and d['trusted_timestamp'] is None

def test_registry_id_not_replaced_by_fingerprint(client_p5,evidence):
    p=copy.deepcopy(evidence['package']);p['manifest']['key_id']=str(uuid.uuid4());p['signature_b64']=sign_manifest_py(evidence['private'],p['manifest'])
    r=upload(client_p5,evidence,p);assert r.status_code==200
    data=r.json();assert data['results']['cryptographic_validity']=='VALID'
    assert data['results']['key_ownership']!='VERIFIED_POP'
    assert data['key_id']==p['manifest']['key_id']

def test_missing_pdf_is_unknown(client_p5,evidence,storage_p5,monkeypatch):
    monkeypatch.setattr(storage_p5,'exists',lambda _:False)
    r=internal(client_p5,evidence);assert r.status_code==200
    assert r.json()['results']['document_integrity']=='UNKNOWN'
    assert 'DOCUMENT_UNAVAILABLE' in r.json()['warning_codes']
    assert r.json()['summary_status']!='VERIFIED'

def test_client_cannot_forge_server_report(client_p5,evidence):
    data=internal(client_p5,evidence).json()
    data['results']['certificate_trust']='TRUSTED_CA'
    assert client_p5.post('/api/v1/verify/report',json=data,headers=evidence['auth']['headers']).status_code==422

@pytest.mark.parametrize('bits,exponent',[(2048,65537),(4096,65537),(3072,3),(0,0)])
def test_rsa_profile_actual_api(client_p5,evidence,bits,exponent):
    from cryptography.hazmat.primitives.asymmetric import rsa,ec
    from cryptography.hazmat.primitives import serialization
    private=rsa.generate_private_key(public_exponent=exponent,key_size=bits) if bits else ec.generate_private_key(ec.SECP256R1())
    public=private.public_key();pem=public.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    der=public.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    p=copy.deepcopy(evidence['package']);p['public_key_spki_pem']=pem;p['manifest']['signer_fingerprint']=hashlib.sha256(der).hexdigest();p['manifest']['key_id']=str(uuid.uuid4())
    if bits:p['signature_b64']=sign_manifest_py(private,p['manifest'])
    # Package contract requires 384 bytes. For profile-sized signatures test actual key validation.
    p['signature_b64']=base64.b64encode(base64.b64decode(p['signature_b64']).ljust(384,b'\0')[:384]).decode()
    r=upload(client_p5,evidence,p);assert r.status_code==200,r.text
    assert r.json()['results']['cryptographic_validity']=='INVALID'
    assert 'KEY_PROFILE_INVALID' in r.json()['warning_codes']

@pytest.mark.parametrize('fake',[
    {'summary_status':'VERIFIED'}, {'certificate_trust':'TRUSTED_CA'},
    {'timestamp_trust_level':'TRUSTED_TSA'}, {'server_recorded_at':'1999-01-01T00:00:00Z'},
])
def test_report_rejects_client_trust_fields(client_p5,evidence,fake):
    result=internal(client_p5,evidence).json()
    body={'receipt_id':result['verification_receipt'],**fake}
    assert client_p5.post('/api/v1/verify/report',json=body,headers=evidence['auth']['headers']).status_code==422

def test_report_receipt_owner_ttl_and_exact_result(client_p5,evidence):
    from backend.app.services import verification_receipts as receipts
    result=internal(client_p5,evidence).json();token=result['verification_receipt'];body={'receipt_id':token}
    r=client_p5.post('/api/v1/verify/report',json=body,headers=evidence['auth']['headers']);assert r.status_code==200
    assert r.json()['verification_result']=={k:v for k,v in result.items() if k not in ('verification_receipt','receipt_expires_at')}
    assert 'not digitally signed or independently tamper-evident' in r.json()['disclaimer']
    assert token not in r.text
    other=register_and_login_user(client_p5,'receipt_other@cyber.edu')
    assert client_p5.post('/api/v1/verify/report',json=body,headers=other['headers']).status_code==404
    client_p5.cookies.clear()
    assert client_p5.post('/api/v1/verify/report',json=body).status_code==404
    assert client_p5.post('/api/v1/verify/report',json={'receipt_id':'B'*43}).status_code==404
    expires,actor,doc,payload=receipts._RECEIPTS[token]
    receipts._RECEIPTS[token]=(0,actor,doc,payload)
    assert client_p5.post('/api/v1/verify/report',json=body,headers=evidence['auth']['headers']).status_code==404

def test_anonymous_report_capability(client_p5,evidence):
    client_p5.cookies.clear();result=upload(client_p5,evidence).json()
    r=client_p5.post('/api/v1/verify/report',json={'receipt_id':result['verification_receipt']})
    assert r.status_code==200 and r.json()['verification_result']=={k:v for k,v in result.items() if k not in ('verification_receipt','receipt_expires_at')}

def test_unreadable_file_does_not_fake_tampering(client_p5,evidence,storage_p5,monkeypatch):
    def denied(_):raise PermissionError('private path must not leak')
    monkeypatch.setattr(storage_p5,'get_file',denied)
    r=internal(client_p5,evidence);assert r.status_code==200
    assert r.json()['results']['document_integrity']=='UNKNOWN'
    assert 'private path' not in r.text

def test_registry_existing_wrong_key_is_explicit_mismatch(client_p5,evidence):
    e=evidence;private,_,pem,fp=generate_test_rsa_3072()
    p=copy.deepcopy(e['package']);p['public_key_spki_pem']=pem;p['manifest']['signer_fingerprint']=fp;p['signature_b64']=sign_manifest_py(private,p['manifest'])
    r=upload(client_p5,e,p);assert r.status_code==200
    d=r.json();assert d['results']['cryptographic_validity']=='VALID'
    assert d['results']['key_registry_binding']=='MISMATCH'
    assert d['results']['key_ownership']!='VERIFIED_POP'
    assert d['summary_status']!='VERIFIED'

def test_revoked_at_even_with_active_status(client_p5,evidence,db_session):
    db_session.execute(text('UPDATE public_keys SET revoked_at=CURRENT_TIMESTAMP'));db_session.commit()
    data=upload(client_p5,evidence).json()
    assert data['results']['cryptographic_validity']=='VALID'
    assert data['results']['key_revocation_status']=='REVOKED'
    assert data['results']['trusted_timestamp'] is None

def test_internal_report_requires_csrf_and_current_ownership(client_p5,evidence,db_session):
    e=evidence;data=internal(client_p5,e).json();body={'receipt_id':data['verification_receipt']}
    assert client_p5.post('/api/v1/verify/report',json=body).status_code==403
    other=register_and_login_user(client_p5,'new_owner@cyber.edu')
    db_session.execute(text('UPDATE documents SET owner_id=:owner'),{'owner':other['user_id']});db_session.commit()
    assert client_p5.post('/api/v1/verify/report',json=body,headers=e['auth']['headers']).status_code==404

def test_server_timestamps_are_utc_not_local_naive_strings(client_p5,evidence):
    data=internal(client_p5,evidence).json()['results']
    assert data['server_recorded_at'].endswith('Z')
    assert data['server_timestamp']==data['server_recorded_at']
    assert data['declared_timestamp'] and data['trusted_timestamp'] is None
    assert data['timestamp_trust_level']=='SERVER_RECORDED'
