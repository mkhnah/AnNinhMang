from fastapi.testclient import TestClient
from backend.app.public_demo import app
from backend.app.core.database import get_db


def test_demo_serves_only_public_routes_and_no_private_operations(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        with TestClient(app) as client:
            for method, path in [('GET','/api/v1/documents'), ('POST','/api/v1/documents'),
                                 ('GET','/api/v1/shares'), ('POST','/api/v1/shares'),
                                 ('POST','/api/v1/auth/login'), ('GET','/docs'), ('GET','/openapi.json')]:
                response = client.request(method, path)
                assert response.status_code == 404
                assert response.headers['Referrer-Policy'] == 'no-referrer'
            invalid = client.get('/api/v1/verify/share/invalid')
            assert invalid.status_code == 404
            assert 'no-store' in invalid.headers['Cache-Control']
    finally:
        app.dependency_overrides.clear()


def test_public_demo_verifies_real_signed_fixture_without_login(client_p5, storage_p5, db_session, tmp_path, monkeypatch):
    from backend.app import public_demo
    from backend.app.api.v1.documents import get_storage
    from tests.test_phase5_verification import (generate_test_rsa_3072, register_and_login_user,
        register_user_key, create_and_sign_document)
    user = register_and_login_user(client_p5, 'public-demo@cyber.edu')
    private, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, private, pem, fp)
    _, version, _, _, _ = create_and_sign_document(client_p5, user, key, private)
    created = client_p5.post('/api/v1/shares', json={'version_id':version}, headers=user['headers']).json()
    token = created['share_url'].rsplit('/', 1)[1]
    (tmp_path / 'index.html').write_text('<html><meta name="referrer" content="no-referrer"></html>')
    monkeypatch.setattr(public_demo, 'DIST', tmp_path)
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_storage] = lambda: storage_p5
    try:
        with TestClient(app) as public:
            result = public.get('/api/v1/verify/share/' + token)
            assert result.status_code == 200
            assert result.json()['results']['summary_status'] == 'VERIFIED'
            assert 'storage_key' not in result.text
            page = public.get('/verify/share/' + token)
            assert page.status_code == 200
            assert page.headers['Referrer-Policy'] == 'no-referrer'
            assert public.get('/api/v1/documents', headers=user['headers']).status_code == 404
    finally:
        app.dependency_overrides.clear()
