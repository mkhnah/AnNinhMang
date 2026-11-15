"""Real SQLite writer ordering; fixtures never use the live database."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading

import pytest
from sqlalchemy import select, update, func, event
from sqlalchemy.orm import Session
from backend.app.models.key import PublicKey
from backend.app.models.enums import KeyStatus
from backend.app.models.share import ShareToken
from backend.app.services.verification_service import VerificationService
from tests.test_phase5_verification import (generate_test_rsa_3072, register_and_login_user,
    register_user_key, create_and_sign_document)

@pytest.fixture
def signed(client_p5):
    user = register_and_login_user(client_p5, 'atomic@cyber.edu')
    private, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, private, pem, fp)
    _, version, _, _, _ = create_and_sign_document(client_p5, user, key, private)
    return user, key, version


def test_revoke_commits_between_verification_and_final_gate(client_p5, db_session, signed, monkeypatch):
    user, key, version = signed
    evaluated, resume = threading.Event(), threading.Event()
    original = VerificationService.verify_shared
    def pause(*args):
        result = original(*args)
        evaluated.set()
        assert resume.wait(5)
        return result
    monkeypatch.setattr(VerificationService, 'verify_shared', pause)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client_p5.post, '/api/v1/shares', json={'version_id': version}, headers=user['headers'])
        try:
            assert evaluated.wait(5)
            with Session(db_session.get_bind()) as revoker:
                revoker.execute(update(PublicKey).where(PublicKey.id == key['id']).values(
                    status=KeyStatus.REVOKED, revoked_at=datetime.now(timezone.utc)))
                revoker.commit()
        finally:
            resume.set()
        response = pending.result(5)
    assert response.status_code == 422, response.text
    with Session(db_session.get_bind()) as fresh:
        assert fresh.scalar(select(func.count()).select_from(ShareToken)) == 0


def test_writer_lock_orders_issue_before_later_revoke(client_p5, db_session, signed):
    from sqlalchemy.exc import OperationalError
    user, key, version = signed
    writing, resume = threading.Event(), threading.Event()
    engine = db_session.get_bind()
    def during_insert(conn, cursor, statement, parameters, context, many):
        if statement.lower().startswith('insert into share_tokens'):
            writing.set()
            assert resume.wait(5)
    event.listen(engine, 'before_cursor_execute', during_insert)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(client_p5.post, '/api/v1/shares', json={'version_id': version}, headers=user['headers'])
            try:
                assert writing.wait(5)
                with engine.connect() as other:
                    other.exec_driver_sql('PRAGMA busy_timeout=50')
                    try:
                        with pytest.raises(OperationalError, match='locked'):
                            other.execute(update(PublicKey).where(PublicKey.id == key['id']).values(
                                status=KeyStatus.REVOKED, revoked_at=datetime.now(timezone.utc)))
                        other.rollback()
                    finally:
                        other.exec_driver_sql('PRAGMA busy_timeout=5000')
            finally:
                resume.set()
            response = pending.result(5)
        assert response.status_code == 201, response.text
    finally:
        event.remove(engine, 'before_cursor_execute', during_insert)
    with Session(engine) as other:
        other.execute(update(PublicKey).where(PublicKey.id == key['id']).values(
            status=KeyStatus.REVOKED, revoked_at=datetime.now(timezone.utc)))
        other.commit()
    token = response.json()['share_url'].rsplit('/', 1)[1]
    public = client_p5.get('/api/v1/verify/share/' + token)
    assert public.json()['results']['summary_status'] == 'REVOKED_KEY'


def test_failed_insert_rolls_back_without_orphan(client_p5, db_session, signed, monkeypatch):
    from backend.app.services import share_service
    user, key, version = signed
    token = share_service.generate_share_token()
    monkeypatch.setattr(share_service, 'generate_share_token', lambda: token)
    first = client_p5.post('/api/v1/shares', json={'version_id': version}, headers=user['headers'])
    assert first.status_code == 201
    duplicate = client_p5.post('/api/v1/shares', json={'version_id': version}, headers=user['headers'])
    assert duplicate.status_code == 503
    with Session(db_session.get_bind()) as fresh:
        assert fresh.scalar(select(func.count()).select_from(ShareToken)) == 1
        assert fresh.execute(__import__('sqlalchemy').text('PRAGMA foreign_key_check')).all() == []
    assert client_p5.get('/api/v1/verify/share/' + token).status_code == 200


def test_two_sessions_revoke_same_share_concurrently(client_p5, db_session, signed):
    from backend.app.services.share_service import revoke_share
    user, _, version = signed
    created = client_p5.post('/api/v1/shares', json={'version_id': version}, headers=user['headers']).json()
    engine = db_session.get_bind()
    barrier = threading.Barrier(2)
    def before_update(conn, cursor, statement, parameters, context, many):
        if statement.lower().startswith('update share_tokens'):
            barrier.wait(timeout=5)
    def worker():
        with Session(engine) as session:
            revoke_share(session, user['user_id'], created['id'])
    event.listen(engine, 'before_cursor_execute', before_update)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(worker) for _ in range(2)]
            for future in futures:
                future.result(8)
    finally:
        event.remove(engine, 'before_cursor_execute', before_update)
    with Session(engine) as fresh:
        assert fresh.scalar(select(ShareToken.revoked_at).where(ShareToken.id == created['id'])) is not None


def test_public_verification_rechecks_concurrently_revoked_share(client_p5, db_session, signed, monkeypatch):
    from backend.app.services.share_service import revoke_share
    user, _, version = signed
    created = client_p5.post('/api/v1/shares', json={'version_id': version}, headers=user['headers']).json()
    evaluated, resume = threading.Event(), threading.Event()
    original = VerificationService.verify_shared
    def pause(*args):
        result = original(*args)
        # Keep a loaded ACTIVE identity through the other Session's commit.
        retained = args[0].get(ShareToken, created['id'])
        assert retained.revoked_at is None
        evaluated.set()
        assert resume.wait(5)
        return result
    monkeypatch.setattr(VerificationService, 'verify_shared', pause)
    token = created['share_url'].rsplit('/', 1)[1]
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(client_p5.get, '/api/v1/verify/share/' + token)
        try:
            assert evaluated.wait(5)
            with Session(db_session.get_bind()) as other:
                revoke_share(other, user['user_id'], created['id'])
        finally:
            resume.set()
        assert pending.result(5).status_code == 404
