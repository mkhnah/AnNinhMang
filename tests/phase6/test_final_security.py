import logging
import secrets
from sqlalchemy import update
from backend.app.models.user import User
from backend.app.models.enums import UserRole
from backend.app.core.verification_limits import PUBLIC_SLOTS
from tests.phase6.test_final_issuance import signed
from tests.test_phase5_verification import register_and_login_user


def test_admin_without_ownership_cannot_issue_or_revoke(client_p5, db_session, signed):
    owner, _, version = signed
    created = client_p5.post('/api/v1/shares', json={'version_id': version}, headers=owner['headers']).json()
    admin = register_and_login_user(client_p5, 'share-admin@cyber.edu')
    db_session.execute(update(User).where(User.id == admin['user_id']).values(role=UserRole.ADMIN))
    db_session.commit()
    assert client_p5.post('/api/v1/shares', json={'version_id': version}, headers=admin['headers']).status_code == 404
    assert client_p5.post(f"/api/v1/shares/{created['id']}/revoke", headers=admin['headers']).status_code == 404
    assert client_p5.get('/api/v1/shares', headers=admin['headers']).json() == []


def test_share_capability_cannot_download_pdf_or_package(client_p5, db_session, signed):
    from backend.app.models.document import DocumentVersion
    owner, _, version = signed
    created = client_p5.post('/api/v1/shares', json={'version_id': version}, headers=owner['headers']).json()
    token = created['share_url'].rsplit('/', 1)[1]
    document = db_session.get(DocumentVersion, version).document_id
    client_p5.cookies.clear()
    for suffix in ['download', 'signature-package']:
        response = client_p5.get(f'/api/v1/documents/{document}/versions/{version}/{suffix}',
                                 headers={'Authorization': f'Bearer {token}'})
        assert response.status_code == 401
    assert client_p5.post('/api/v1/shares', json={'version_id':version}).status_code == 401


def test_public_share_slot_cap_and_error_headers(client_p5):
    permits = 0
    try:
        while PUBLIC_SLOTS.acquire(False):
            permits += 1
        response = client_p5.get('/api/v1/verify/share/' + 'A' * 43)
        assert response.status_code == 503
        assert 'no-store' in response.headers['Cache-Control']
        assert response.headers['Referrer-Policy'] == 'no-referrer'
        assert response.headers['X-Content-Type-Options'] == 'nosniff'
    finally:
        for _ in range(permits): PUBLIC_SLOTS.release()


def test_access_logger_redacts_real_token_format(caplog):
    token = secrets.token_urlsafe(32)
    with caplog.at_level(logging.INFO, logger='uvicorn.access'):
        logging.getLogger('uvicorn.access').info('GET %s', '/api/v1/verify/share/' + token)
    assert token not in caplog.text
    assert '<redacted>' in caplog.text
