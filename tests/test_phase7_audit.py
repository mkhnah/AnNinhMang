"""Audit integrity, atomicity, privacy, migration and real API integration."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import subprocess
import sys
import threading

import pytest
from fastapi import HTTPException
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.orm import Session

from backend.app.crypto.jcs import canonicalize
from backend.app.models.audit import AuditChainState, AuditLog, GENESIS_HASH
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.user import User
from backend.app.services.audit_service import (
    append_audit, compute_entry_hash, log_access_denied, request_context, verify_audit_chain,
)
from tests.test_phase5_verification import (
    create_and_sign_document, generate_test_rsa_3072, register_and_login_user, register_user_key,
)


def add_entries(db, count=3):
    for _ in range(count):
        append_audit(db, "USER_LOGIN", target_type="USER")
    db.commit()


def test_empty_and_valid_chain(db_session):
    assert verify_audit_chain(db_session).valid
    db_session.rollback()
    add_entries(db_session)
    result = verify_audit_chain(db_session)
    assert result.valid and result.checked_entries == 3
    entries = db_session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    assert entries[0].prev_hash == GENESIS_HASH
    assert entries[1].prev_hash == entries[0].entry_hash


def test_canonical_hash_covers_all_fields_and_timezone(db_session):
    entry = append_audit(db_session, "KEY_GENERATE", target_type="KEY", details={
        "fingerprint": "a" * 64, "algorithm": "RSA-PSS-3072",
    })
    expected_payload = {
        "schema_version": 1, "id": "1", "prev_hash": GENESIS_HASH, "actor_id": None,
        "action": "KEY_GENERATE", "target_type": "KEY", "target_id": None,
        "client_ip": None, "user_agent": None, "status": "SUCCESS",
        "created_at": entry.created_at.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        "details_hash": hashlib.sha256(canonicalize({"algorithm": "RSA-PSS-3072", "fingerprint": "a" * 64})).hexdigest(),
    }
    assert entry.entry_hash == hashlib.sha256(b"DOCSIGN_AUDIT_V1\x00" + canonicalize(expected_payload)).hexdigest()
    entry.created_at = entry.created_at.astimezone(timezone(timedelta(hours=7)))
    assert compute_entry_hash(entry) == entry.entry_hash
    db_session.rollback()


@pytest.mark.parametrize("field,value", [
    ("actor_id", "changed"), ("action", "KEY_REVOKE"), ("target_type", "KEY"),
    ("target_id", "changed"), ("client_ip", "127.0.0.2"), ("user_agent", "Firefox"),
    ("status", "FAILURE"), ("details_json", '{"http_status":401}'),
    ("created_at", datetime(2020, 1, 1)), ("entry_hash", "0" * 64),
])
def test_t17_detects_modified_field_with_cached_orm(db_session, field, value):
    add_entries(db_session)
    cached = db_session.get(AuditLog, 2)
    if field == "actor_id":
        db_session.add(User(id="changed", email="tamper@cyber.edu", full_name="Tamper", password_hash="synthetic"))
        db_session.flush()
    # Direct database tampering bypasses the ORM identity map.
    db_session.execute(update(AuditLog).where(AuditLog.id == 2).values(**{field: value})
                       .execution_options(synchronize_session=False))
    db_session.commit()
    assert cached.id == 2
    result = verify_audit_chain(db_session)
    assert not result.valid and result.error_id == 2


@pytest.mark.parametrize("ids,error_id", [([1], 1), ([2], 2), ([3], 3), ([1, 2, 3], 1)])
def test_t17_detects_deleted_first_middle_tail_or_all(db_session, ids, error_id):
    add_entries(db_session)
    db_session.execute(delete(AuditLog).where(AuditLog.id.in_(ids)))
    db_session.commit()
    result = verify_audit_chain(db_session)
    assert not result.valid and result.error_id == error_id


def test_detects_relinked_suffix_and_missing_checkpoint(db_session):
    add_entries(db_session)
    db_session.execute(update(AuditLog).where(AuditLog.id == 2).values(prev_hash="0" * 64))
    db_session.commit()
    assert verify_audit_chain(db_session).reason == "PREVIOUS_HASH_MISMATCH"
    db_session.rollback()
    db_session.execute(delete(AuditChainState))
    db_session.commit()
    assert verify_audit_chain(db_session).reason == "CHECKPOINT_MISSING"
    db_session.rollback()
    with pytest.raises(HTTPException, match="503"):
        append_audit(db_session, "USER_LOGIN", target_type="USER")
    db_session.rollback()


def test_secret_allowlist_and_untrusted_headers(db_session):
    secret = "do-not-retain-this-private-value"
    context = request_context("127.0.0.1", "Chrome/100 Bearer " + secret)
    entry = append_audit(db_session, "KEY_GENERATE", target_type="KEY", details={
        "algorithm": "RSA-PSS-3072", "fingerprint": "a" * 64,
        "private_key": secret, "passphrase": secret, "access_token": secret,
        "nested": {"password": secret}, "label": secret, "key_id": secret,
    }, context=context)
    assert json.loads(entry.details_json) == {"algorithm": "RSA-PSS-3072", "fingerprint": "a" * 64}
    assert entry.user_agent == "Chrome" and entry.client_ip == "127.0.0.1"
    entry2 = append_audit(db_session, "USER_LOGIN", target_type="USER",
                          details={"reason": secret, "http_status": secret},
                          context={"client_ip": secret, "user_agent": secret})
    assert entry2.details_json == "{}" and entry2.client_ip is None and entry2.user_agent is None


def test_rollback_preserves_checkpoint_and_business_state(db_session):
    user = User(email="rollback@cyber.edu", full_name="Original", password_hash="synthetic")
    db_session.add(user)
    db_session.commit()
    user_id = user.id
    user.full_name = "Pending"
    append_audit(db_session, "USER_LOGIN", actor_id=user_id, target_type="USER", target_id=user_id)
    db_session.rollback()
    assert db_session.get(User, user_id).full_name == "Original"
    assert db_session.scalar(select(func.count()).select_from(AuditLog)) == 0
    assert db_session.get(AuditChainState, 1).last_id == 0
    entry = append_audit(db_session, "USER_LOGIN", actor_id=user_id, target_type="USER", target_id=user_id)
    db_session.commit()
    assert entry.id == 1 and verify_audit_chain(db_session).valid


def test_denial_survives_outer_rollback_without_committing_pending_work(db_session):
    user = User(email="denied@cyber.edu", full_name="Original", password_hash="synthetic")
    db_session.add(user)
    db_session.commit()
    user_id = user.id
    user.full_name = "Pending"
    log_access_denied(db_session, user_id, "DOCUMENT", "missing")
    db_session.rollback()
    assert db_session.get(User, user_id).full_name == "Original"
    assert db_session.scalar(select(AuditLog.action)) == "ACCESS_DENIED_IDOR"
    assert verify_audit_chain(db_session).valid


def test_concurrent_appends_have_one_chain(tmp_path):
    from sqlalchemy import create_engine
    from backend.app.core.database import Base
    # Other legacy tests change PRAGMA busy_timeout on their pooled connection.
    # Use an independent database to exercise the application's normal timeout.
    engine = create_engine(f"sqlite:///{tmp_path / 'concurrent-audit.db'}")
    Base.metadata.create_all(engine)
    barrier = threading.Barrier(4)

    def write_batch(_):
        with Session(engine) as worker:
            barrier.wait(timeout=10)
            for _ in range(5):
                append_audit(worker, "USER_LOGIN", target_type="USER")
                worker.commit()

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(write_batch, range(4)))
        with Session(engine) as session:
            result = verify_audit_chain(session)
            assert result.valid and result.checked_entries == 20
    finally:
        engine.dispose()


def test_login_failure_does_not_retain_credentials(client, db_session):
    for email in ("unknown@cyber.edu", "another@cyber.edu"):
        response = client.post("/api/v1/auth/login", json={"email": email, "password": "SecretPassword123!"})
        assert response.status_code == 401
    entries = db_session.scalars(select(AuditLog)).all()
    assert len(entries) == 2
    assert all(entry.action == "USER_LOGIN" and entry.status == "FAILURE" and entry.actor_id is None for entry in entries)
    assert "SecretPassword" not in repr([entry.details_json for entry in entries])


def test_untrusted_target_ids_preserve_404_and_are_discarded(client, db_session):
    auth = register_and_login_user(client, "invalid-id@cyber.edu")
    secret = "private-value-with-spaces " * 10
    response = client.post("/api/v1/shares", json={"version_id": secret}, headers=auth["headers"])
    assert response.status_code == 404
    response = client.post("/api/v1/keys/unknown%20private%20value/revoke", headers=auth["headers"])
    assert response.status_code == 404
    denied = db_session.scalars(select(AuditLog).where(AuditLog.action == "ACCESS_DENIED_IDOR")).all()
    assert len(denied) == 2 and all(entry.target_id is None for entry in denied)


@pytest.mark.parametrize("details", ['{"http_status": 401}', '{"a":1,"a":2}', '{"value":NaN}'])
def test_noncanonical_or_invalid_details_are_detected(db_session, details):
    add_entries(db_session, 1)
    db_session.execute(update(AuditLog).values(details_json=details))
    db_session.commit()
    result = verify_audit_chain(db_session)
    assert not result.valid and result.error_id == 1 and result.reason == "INVALID_ENTRY"


def test_api_lifecycle_records_events_and_idor(client_p5, db_session):
    auth = register_and_login_user(client_p5, "audit@cyber.edu")
    private, _, pem, fingerprint = generate_test_rsa_3072()
    key = register_user_key(client_p5, auth, private, pem, fingerprint)
    doc_id, version_id, pdf, _, _ = create_and_sign_document(client_p5, auth, key, private)
    response = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{version_id}/verify", headers=auth["headers"])
    assert response.status_code == 200
    share = client_p5.post("/api/v1/shares", json={"version_id": version_id, "label": "Private label"}, headers=auth["headers"])
    assert share.status_code == 201
    token = share.json()["share_url"].rsplit("/", 1)[1]
    assert client_p5.get("/api/v1/verify/share/" + token).status_code == 200
    package = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{version_id}/signature-package", headers=auth["headers"])
    assert package.status_code == 200
    independent = client_p5.post("/api/v1/verify/upload", files={"file": ("test.pdf", pdf, "application/pdf")},
                                  data={"package_json": json.dumps(package.json())})
    assert independent.status_code == 200
    other = register_and_login_user(client_p5, "audit-other@cyber.edu")
    assert client_p5.get(f"/api/v1/documents/{doc_id}", headers=other["headers"]).status_code == 404
    assert client_p5.post(f"/api/v1/keys/{key['id']}/revoke", headers=other["headers"]).status_code == 403
    assert client_p5.post(f"/api/v1/keys/{key['id']}/revoke", headers=auth["headers"]).status_code == 200
    assert client_p5.post(f"/api/v1/keys/{key['id']}/revoke", headers=auth["headers"]).status_code == 200
    entries = db_session.scalars(select(AuditLog).order_by(AuditLog.id)).all()
    actions = [entry.action for entry in entries]
    assert set(actions) >= {"USER_LOGIN", "KEY_GENERATE", "KEY_REVOKE", "DOCUMENT_UPLOAD", "DOCUMENT_SIGN", "DOCUMENT_VERIFY", "SHARE_QR", "ACCESS_DENIED_IDOR"}
    assert actions.count("KEY_REVOKE") == 1
    assert actions.count("ACCESS_DENIED_IDOR") == 2
    verification_entries = [json.loads(entry.details_json) for entry in entries if entry.action == "DOCUMENT_VERIFY"]
    assert {entry["verification_mode"] for entry in verification_entries} >= {"INTERNAL", "INDEPENDENT_DETACHED"}
    assert all(entry["summary_status"] == "VERIFIED" for entry in verification_entries)
    retained = " ".join(entry.details_json for entry in entries)
    assert token not in retained and "Private label" not in retained and auth["headers"]["Authorization"] not in retained
    assert verify_audit_chain(db_session).valid


def test_failed_audit_rolls_back_upload_and_storage(client_p5, db_session, storage_p5, monkeypatch):
    from backend.app.services import document_service
    from tests.phase2.conftest import make_pdf
    auth = register_and_login_user(client_p5, "audit-fail@cyber.edu")
    original = document_service.append_audit

    def interrupt(*args, **kwargs):
        original(*args, **kwargs)
        raise HTTPException(503, "Simulated audit failure")

    monkeypatch.setattr(document_service, "append_audit", interrupt)
    response = client_p5.post("/api/v1/documents", files={"file": ("test.pdf", make_pdf(), "application/pdf")}, headers=auth["headers"])
    assert response.status_code == 503
    assert db_session.scalar(select(func.count()).select_from(Document)) == 0
    assert db_session.scalar(select(func.count()).select_from(DocumentVersion)) == 0
    assert list(storage_p5.root.rglob("*.pdf")) == []
    assert db_session.scalar(select(func.count()).select_from(AuditLog)) == 1
    assert verify_audit_chain(db_session).valid


def test_audit_migration_preserves_existing_users_and_matches_metadata(tmp_path):
    from sqlalchemy import create_engine
    path = tmp_path / "migration.db"
    env = {**os.environ, "DATABASE_URL": f"sqlite:///{path}", "DEBUG": "false"}

    def migrate(*args):
        result = subprocess.run([sys.executable, "-m", "alembic", *args], env=env, capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr + result.stdout

    migrate("upgrade", "a7f000000007")
    engine = create_engine(f"sqlite:///{path}")
    with engine.begin() as connection:
        connection.execute(text("INSERT INTO users (id,email,full_name,password_hash,role,status,failed_login_attempts,created_at,updated_at) VALUES ('legacy','legacy@cyber.edu','Keep','synthetic','USER','ACTIVE',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    migrate("upgrade", "head")
    migrate("check")
    with Session(engine) as session:
        assert session.get(User, "legacy").full_name == "Keep"
        append_audit(session, "USER_LOGIN", actor_id="legacy", target_type="USER", target_id="legacy")
        session.commit()
        assert verify_audit_chain(session).valid
    migrate("downgrade", "a7f000000007")
    with engine.connect() as connection:
        assert connection.scalar(text("SELECT count(*) FROM users")) == 1
    engine.dispose()
