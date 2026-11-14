import hashlib
import uuid
import pytest
from sqlalchemy import select, update, text
from sqlalchemy.exc import IntegrityError, OperationalError
from backend.app.models.document import Document, DocumentVersion
from backend.app.core.config import settings


def upload(client, pdf, doc=None, filename='test.pdf'):
    url = '/api/v1/documents' + (f'/{doc}/versions' if doc else '')
    return client.post(url, files={'file': (filename, pdf, 'application/pdf')})


def test_unauthenticated(documents_client, pdf):
    assert upload(documents_client, pdf).status_code == 401
    assert documents_client.get(f'/api/v1/documents/{uuid.uuid4()}/versions/{uuid.uuid4()}/download').status_code == 401


def test_lifecycle(auth_user, pdf, storage, db_session):
    client = auth_user
    assert client.get('/api/v1/documents/limits').json()['max_upload_bytes'] == settings.MAX_UPLOAD_BYTES
    response = upload(client,pdf); assert response.status_code == 201, response.text
    a = response.json(); doc = a['document_id']; v = a['version_id']
    assert a['file_sha256'] == hashlib.sha256(pdf).hexdigest()
    assert 'storage' not in response.text
    assert a['state'] == 'DRAFT'
    assert client.get('/api/v1/documents').json()['total'] == 1
    assert client.get(f'/api/v1/documents/{doc}').status_code == 200
    assert client.get(f'/api/v1/documents/{doc}/versions/{v}').status_code == 200
    b = upload(client,pdf,doc).json(); assert b['version_no'] == 2
    assert b['version_id'] != v
    assert len(client.get(f'/api/v1/documents/{doc}/versions').json()) == 2
    for version in [v,b['version_id']]:
        download = client.get(f'/api/v1/documents/{doc}/versions/{version}/download')
        assert download.content == pdf
        assert download.headers['x-content-type-options'] == 'nosniff'
        assert download.headers['content-type'] == 'application/pdf'
        assert 'attachment;' in download.headers['content-disposition']
    ready = client.post(f'/api/v1/documents/{doc}/versions/{v}/ready')
    assert ready.status_code == 200
    assert ready.json()['state'] == 'READY_TO_SIGN' and ready.json()['locked_at']
    assert client.post(f'/api/v1/documents/{doc}/versions/{v}/ready').status_code == 409
    assert client.get(f'/api/v1/documents/{doc}/versions/{v}/download').content == pdf


def test_idor_cross_document(auth_user, pdf):
    client=auth_user; a=upload(client,pdf).json(); b=upload(client,pdf).json()
    prefix=f"/api/v1/documents/{a['document_id']}"
    assert client.get(f"{prefix}/versions/{b['version_id']}").status_code == 404
    assert client.get(f"{prefix}/versions/{b['version_id']}/download").status_code == 404
    client.post('/api/v1/auth/logout')
    payload={'email':'other@cyber.edu','full_name':'Other','password':'SecurePassword123!','confirm_password':'SecurePassword123!'}
    client.post('/api/v1/auth/register',json=payload); client.post('/api/v1/auth/login',json=payload)
    assert client.get('/api/v1/documents').json()['total'] == 0
    for suffix in ['', '/versions',f"/versions/{a['version_id']}",f"/versions/{a['version_id']}/download"]:
        assert client.get(prefix+suffix).status_code == 404
    assert upload(client,pdf,a['document_id']).status_code == 404
    assert client.post(f"{prefix}/versions/{a['version_id']}/ready").status_code == 404


def test_uuid_and_csrf(auth_user,pdf):
    assert auth_user.get('/api/v1/documents/not-a-uuid').status_code == 422
    del auth_user.headers['X-Requested-With']
    assert upload(auth_user,pdf).status_code == 403


def test_integrity_missing(auth_user,pdf,storage,db_session):
    a=upload(auth_user,pdf).json()
    version=db_session.get(DocumentVersion,a['version_id'])
    path=storage.root/version.storage_key
    path.write_bytes(b'tampered synthetic content')
    url=f"/api/v1/documents/{a['document_id']}/versions/{a['version_id']}"
    assert auth_user.get(url+'/download').status_code == 409
    assert auth_user.post(url+'/ready').status_code == 409
    path.unlink()
    assert auth_user.get(url+'/download').status_code == 409


def test_db_failure_rollback(auth_user,pdf,storage,db_session,monkeypatch):
    def fail(): raise OperationalError('synthetic',{},Exception('failure'))
    with monkeypatch.context() as m:
        m.setattr(db_session,'commit',fail)
        assert upload(auth_user,pdf).status_code == 503
    assert not list(storage.root.rglob('*.pdf'))
    assert auth_user.get('/api/v1/documents').json()['total'] == 0


def test_disk_full(auth_user,pdf,storage,monkeypatch):
    import errno
    def fail(*args): raise OSError(errno.ENOSPC,'test')
    monkeypatch.setattr(storage,'save_file',fail)
    assert upload(auth_user,pdf).status_code == 507
    assert auth_user.get('/api/v1/documents').json()['total'] == 0


def test_request_limit(auth_user,monkeypatch):
    monkeypatch.setattr(settings,'MAX_UPLOAD_BYTES',100)
    assert upload(auth_user,b'X'*70000).status_code == 413
    # No Content-Length: enforce actual received bytes too.
    response=auth_user.post('/api/v1/documents', content=iter([b'X'*70000]),headers={'Content-Type':'multipart/form-data; boundary=test'})
    assert response.status_code == 413, response.text


def test_duplicate_display_name(auth_user,pdf,storage):
    a=upload(auth_user,pdf,filename='../trùng.pdf').json()
    b=upload(auth_user,pdf,filename='../trùng.pdf').json()
    assert a['document_id'] != b['document_id']
    assert a['original_filename'] == 'trùng.pdf'
    assert len(list(storage.root.rglob('*.pdf'))) == 2


@pytest.mark.parametrize('column,value',[('file_sha256','a'*64),('storage_key','other'),('version_no',99),('state','SIGNED')])
def test_db_immutability(auth_user,pdf,db_session,column,value):
    a=upload(auth_user,pdf).json()
    with pytest.raises(IntegrityError):
        db_session.execute(update(DocumentVersion).where(DocumentVersion.id==a['version_id']).values(**{column:value}))
    db_session.rollback()


@pytest.mark.parametrize('field', ['version_no','storage_key'])
def test_unique_constraints(auth_user,pdf,db_session,field):
    a=upload(auth_user,pdf).json(); original=db_session.get(DocumentVersion,a['version_id'])
    clone=DocumentVersion(id=str(uuid.uuid4()),document_id=original.document_id,
        version_no=original.version_no if field=='version_no' else 2,
        storage_key=original.storage_key if field=='storage_key' else 'new-unique',
        file_sha256=original.file_sha256,file_size_bytes=original.file_size_bytes,original_filename='clone.pdf')
    db_session.add(clone)
    with pytest.raises(IntegrityError): db_session.flush()
    db_session.rollback()
