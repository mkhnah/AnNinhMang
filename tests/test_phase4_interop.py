import base64
import json
import subprocess
import selectors
from pathlib import Path

import pytest
from sqlalchemy import select
from tests.test_phase4_signatures import client_p4, storage_p4, register_and_login_user, upload_and_ready_doc
from backend.app.crypto.jcs import canonicalize_from_json
from backend.app.models.signature import Signature
from backend.app.models.document import DocumentVersion, VersionState


@pytest.fixture
def bridge():
    process = subprocess.Popen(['node','tests/helpers/signing_webcrypto.cjs'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    def request(action, payload=None):
        process.stdin.write(json.dumps(dict(action=action,payload=payload))+'\n');process.stdin.flush()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            assert selector.select(20), 'Node bridge timed out'
        line=process.stdout.readline()
        assert line, 'Node bridge terminated'
        return json.loads(line)
    yield request
    process.stdin.close()
    try: process.wait(timeout=5)
    except subprocess.TimeoutExpired: process.kill();process.wait()
    process.stdout.close();process.stderr.close()


def test_t22_actual_ts_python_byte_bridge(bridge):
    vectors=json.loads(Path('tests/fixtures/jcs-v1/vectors.json').read_text())
    inputs=[v['input'] for v in vectors]+[
        {'\u20ac':'Euro','\r':'CR','\ufb33':'Hebrew','1':'one','\U0001f600':'emoji','\u0080':'control','\u00f6':'o'},
        {'numbers':[333333333.33333329,1e30,4.50,2e-3,1e-27,-0.0,1e-7,1e-6,1e20,1e21]},
        {'unicode':'Tiếng Việt 😀 e\u0301 é','array':[None,True,False,{'b':2,'a':1}]},
    ]
    for value in inputs:
        js=bridge('canonical',value)
        assert base64.b64decode(js['bytes'])==canonicalize_from_json(json.dumps(value,ensure_ascii=True))
    for value in [{'invalid':'\ud800'}, {'invalid':float('inf')}, {'invalid':float('nan')}]:
        assert 'error' in bridge('canonical',value)
        with pytest.raises(ValueError): canonicalize_from_json(json.dumps(value))


def test_real_webcrypto_frontend_signer_to_python_db(client_p4, db_session, bridge):
    auth=register_and_login_user(client_p4,'webcrypto@cyber.edu');headers=auth['headers']
    public=bridge('keygen')
    challenge=client_p4.post('/api/v1/keys/challenge',json={'algorithm':'RSA-PSS-3072','fingerprint':public['fingerprint'],'purpose':'REGISTER_KEY'},headers=headers).json()
    pop=dict(algorithm='RSA-PSS-3072',challenge_id=challenge['challenge_id'],challenge_nonce=challenge['challenge_nonce'],fingerprint=public['fingerprint'],purpose='REGISTER_KEY',schema_version=1,user_id=auth['user_id'])
    proof=bridge('pop',pop)['signature']
    response=client_p4.post('/api/v1/keys',json={'algorithm':'RSA-PSS-3072','public_key_pem':public['public_key_pem'],'challenge_id':challenge['challenge_id'],'pop_signature_b64':proof},headers=headers)
    assert response.status_code==201,response.text
    key=response.json();doc,version,_,_=upload_and_ready_doc(client_p4,headers)
    response=client_p4.post(f'/api/v1/documents/{doc}/versions/{version}/prepare-sign',json={'key_id':key['id']},headers=headers)
    assert response.status_code==200,response.text
    manifest=response.json()['manifest'];signature=bridge('sign',manifest)['signature']
    canonical=base64.b64decode(bridge('canonical',manifest)['bytes'])
    response=client_p4.post('/api/v1/signatures',json=dict(version_id=version,key_id=key['id'],manifest=manifest,signature_b64=signature),headers=headers)
    assert response.status_code==201,response.text
    db_session.expire_all()
    saved=db_session.scalar(select(Signature).where(Signature.version_id==version))
    assert saved.signature_b64==signature
    assert saved.canonical_manifest_json.encode()==canonical
    assert db_session.get(DocumentVersion,version).state==VersionState.SIGNED
