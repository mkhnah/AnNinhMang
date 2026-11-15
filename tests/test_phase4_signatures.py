import base64
import concurrent.futures
import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.app.api.v1.documents import get_storage
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.crypto.jcs import canonicalize_jcs, canonicalize_from_json, compute_manifest_sha256
from backend.app.main import app
from backend.app.models.document import Document, DocumentVersion, VersionState
from backend.app.models.enums import KeyStatus
from backend.app.models.key import PublicKey, SigningChallenge
from backend.app.models.signature import Signature, SigningSession
from backend.app.models.user import User
from backend.app.services.key_service import canonicalize_pop_payload
from backend.app.storage.local import LocalStorageService
from tests.phase2.conftest import make_pdf


# --- Cryptographic Helpers ---

def generate_test_rsa_3072():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    spki_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    fingerprint = hashlib.sha256(spki_der).hexdigest().lower()
    return private_key, public_key, spki_pem, fingerprint


def sign_manifest_py(private_key, manifest_dict: dict) -> str:
    canonical_bytes = canonicalize_jcs(manifest_dict)
    sig_raw = private_key.sign(
        canonical_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return base64.b64encode(sig_raw).decode("utf-8")


def sign_pop_py(private_key, payload_dict: dict) -> str:
    canonical_bytes = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig_raw = private_key.sign(
        canonical_bytes,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    return base64.b64encode(sig_raw).decode("utf-8")


# --- Test Fixtures ---

@pytest.fixture
def storage_p4():
    with tempfile.TemporaryDirectory(prefix="p4-test-storage-", dir="data") as root:
        yield LocalStorageService(Path(root).resolve())


@pytest.fixture
def client_p4(client, storage_p4):
    app.dependency_overrides[get_storage] = lambda: storage_p4
    yield client
    app.dependency_overrides.pop(get_storage, None)


def register_and_login_user(client: TestClient, email: str = "signer@cyber.edu"):
    payload = {
        "email": email,
        "full_name": "Digital Signer",
        "password": "Password@123456",
        "confirm_password": "Password@123456",
    }
    client.post("/api/v1/auth/register", json=payload)
    login_res = client.post("/api/v1/auth/login", json={
        "email": email,
        "password": "Password@123456",
    })
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    user_id = login_res.json()["user"]["id"]
    csrf = login_res.cookies.get("csrf_token", "")
    return {
        "headers": {
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": csrf,
            "X-Requested-With": "XMLHttpRequest",
        },
        "user_id": user_id,
    }


def register_user_key(client: TestClient, auth_info: dict, private_key, spki_pem: str, fingerprint: str):
    headers = auth_info["headers"]
    user_id = auth_info["user_id"]
    chal_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fingerprint, "purpose": "REGISTER_KEY"},
        headers=headers,
    )
    assert chal_res.status_code in (200, 201), chal_res.text
    chal_data = chal_res.json()
    challenge_id = chal_data["challenge_id"]
    challenge_nonce = chal_data["challenge_nonce"]

    # Build PoP payload
    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": challenge_id,
        "challenge_nonce": challenge_nonce,
        "fingerprint": fingerprint,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": user_id,
    }
    pop_sig = sign_pop_py(private_key, pop_payload)

    reg_res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": spki_pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": challenge_id,
            "pop_signature_b64": pop_sig,
        },
        headers=headers,
    )
    assert reg_res.status_code == 201, reg_res.text
    return reg_res.json()


def upload_and_ready_doc(client: TestClient, headers: dict, pdf_bytes: bytes = None):
    if pdf_bytes is None:
        pdf_bytes = make_pdf()
    up_res = client.post(
        "/api/v1/documents",
        files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
        headers=headers,
    )
    assert up_res.status_code == 201, up_res.text
    doc_info = up_res.json()
    doc_id = doc_info["document_id"]
    ver_id = doc_info["version_id"]

    ready_res = client.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/ready",
        headers=headers,
    )
    assert ready_res.status_code == 200, ready_res.text
    return doc_id, ver_id, doc_info["file_sha256"], pdf_bytes


# ==============================================================================
# 1. RFC 8785 JCS Cross-Platform Determinism (Test T-22)
# ==============================================================================

def test_t22_rfc8785_jcs_golden_vectors():
    fixtures_path = Path("tests/fixtures/jcs-v1/vectors.json")
    assert fixtures_path.exists(), "RFC 8785 test vectors fixture missing"

    with open(fixtures_path, "r", encoding="utf-8") as f:
        vectors = json.load(f)

    for vec in vectors:
        canonical_bytes = canonicalize_jcs(vec["input"])
        expected_bytes = vec["expected_canonical"].encode("utf-8")
        assert canonical_bytes == expected_bytes, f"Mismatch in vector: {vec['name']}"


def test_t22_rfc8785_jcs_strict_rejections():
    # Reject duplicate keys in raw JSON
    raw_dup = '{"a": 1, "a": 2}'
    with pytest.raises(ValueError):
        canonicalize_from_json(raw_dup)

    # Reject NaN and Infinity
    with pytest.raises(ValueError):
        canonicalize_jcs({"val": float("nan")})

    with pytest.raises(ValueError):
        canonicalize_jcs({"val": float("inf")})


# ==============================================================================
# 2. End-to-End Detached Digital Signature Flow (Happy Path)
# ==============================================================================

def test_p4_complete_signing_flow(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "signer_e2e@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, file_sha256, pdf_bytes = upload_and_ready_doc(client_p4, headers)

    # 1. Prepare Sign
    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    assert prep_res.status_code == 200, prep_res.text
    prep_data = prep_res.json()

    manifest = prep_data["manifest"]
    assert manifest["manifest_version"] == 1
    assert manifest["document_version_id"] == ver_id
    assert manifest["document_sha256"] == file_sha256
    assert manifest["key_id"] == key_id
    assert manifest["signer_fingerprint"] == fingerprint
    assert manifest["algorithm"] == "RSA-PSS-3072"
    assert manifest["signing_context"] == "DOCSIGN_DOCUMENT_SIGNATURE_V1"
    assert len(manifest["signing_nonce"]) >= 32

    # 2. Sign manifest on client with WebCrypto/RSA-PSS equivalent
    sig_b64 = sign_manifest_py(priv_key, manifest)

    # 3. Submit signature
    sub_res = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id,
            "key_id": key_id,
            "manifest": manifest,
            "signature_b64": sig_b64,
        },
        headers=headers,
    )
    assert sub_res.status_code == 201, sub_res.text
    sig_data = sub_res.json()
    assert sig_data["version_id"] == ver_id
    assert sig_data["key_id"] == key_id
    assert sig_data["algorithm"] == "RSA-PSS-3072"
    assert sig_data["signature_format"] == "DETACHED_JCS_V1"
    assert sig_data["manifest_sha256"] == prep_data["manifest_sha256"]

    # 4. Verify version is now SIGNED in DB
    ver_check = client_p4.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}", headers=headers)
    assert ver_check.status_code == 200
    assert ver_check.json()["state"] == "SIGNED"

    # 5. Query signature endpoint
    get_sig_res = client_p4.get(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/signature",
        headers=headers,
    )
    assert get_sig_res.status_code == 200
    assert get_sig_res.json()["id"] == sig_data["id"]


# ==============================================================================
# 3. Concurrency Race Condition Defense (Test T-12)
# ==============================================================================

def test_t12_concurrency_race_condition(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "race@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, file_sha256, pdf_bytes = upload_and_ready_doc(client_p4, headers)

    # Prepare sign
    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    assert prep_res.status_code == 200
    prep_data = prep_res.json()
    manifest = prep_data["manifest"]
    sig_b64 = sign_manifest_py(priv_key, manifest)

    payload = {
        "version_id": ver_id,
        "key_id": key_id,
        "manifest": manifest,
        "signature_b64": sig_b64,
    }

    # Execute 2 concurrent requests to consume same nonce and sign same version
    from tests.conftest import TestingSessionLocal
    from backend.app.core.database import get_db

    def override_concurrent_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    old_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_concurrent_db

    def attempt_submit():
        return client_p4.post("/api/v1/signatures", json=payload, headers=headers)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(attempt_submit)
            f2 = executor.submit(attempt_submit)
            r1 = f1.result()
            r2 = f2.result()
    finally:
        if old_override:
            app.dependency_overrides[get_db] = old_override
        else:
            app.dependency_overrides.pop(get_db, None)

    statuses = sorted([r1.status_code, r2.status_code])
    # Exactly one must succeed (201) and the other must be rejected (400 or 409)
    assert statuses[0] == 201, f"Expected 201 in statuses: {statuses}"
    assert statuses[1] in [400, 409], f"Second request was not rejected with 400/409: {statuses}"

    # Confirm in DB only 1 signature exists
    sig_count = db_session.execute(
        text("SELECT COUNT(*) FROM signatures WHERE version_id = :vid"),
        {"vid": ver_id},
    ).scalar()
    assert sig_count == 1


# ==============================================================================
# 4. Replay & Nonce Defense (Test T-18)
# ==============================================================================

def test_t18_replay_nonce_reuse(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "replay@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, file_sha256, pdf_bytes = upload_and_ready_doc(client_p4, headers)

    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    manifest = prep_res.json()["manifest"]
    sig_b64 = sign_manifest_py(priv_key, manifest)

    payload = {
        "version_id": ver_id,
        "key_id": key_id,
        "manifest": manifest,
        "signature_b64": sig_b64,
    }

    # First attempt: succeeds
    res1 = client_p4.post("/api/v1/signatures", json=payload, headers=headers)
    assert res1.status_code == 201

    # Second attempt: replayed with same nonce/signature -> rejected with 409
    res2 = client_p4.post("/api/v1/signatures", json=payload, headers=headers)
    assert res2.status_code in [400, 409]


def test_t18_expired_nonce_rejected(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "expired@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, file_sha256, pdf_bytes = upload_and_ready_doc(client_p4, headers)

    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    manifest = prep_res.json()["manifest"]
    sig_b64 = sign_manifest_py(priv_key, manifest)

    # Manually expire signing session in DB
    past_time = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.execute(
        text("UPDATE signing_sessions SET expires_at = :exp WHERE version_id = :vid"),
        {"exp": past_time, "vid": ver_id},
    )
    db_session.commit()

    res = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id,
            "key_id": key_id,
            "manifest": manifest,
            "signature_b64": sig_b64,
        },
        headers=headers,
    )
    assert res.status_code == 400
    assert "hết hạn" in res.json()["detail"].lower()


def test_t18_cross_version_nonce_rejected(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "cross_ver@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id1, ver_id1, sha1, _ = upload_and_ready_doc(client_p4, headers)
    doc_id2, ver_id2, sha2, _ = upload_and_ready_doc(client_p4, headers)

    # Prepare sign for Version 1
    prep_res1 = client_p4.post(
        f"/api/v1/documents/{doc_id1}/versions/{ver_id1}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    manifest1 = prep_res1.json()["manifest"]

    # Submit nonce from Version 1 into Version 2
    fraud_manifest = dict(manifest1)
    fraud_manifest["document_version_id"] = ver_id2
    fraud_manifest["document_sha256"] = sha2
    fraud_sig = sign_manifest_py(priv_key, fraud_manifest)

    res = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id2,
            "key_id": key_id,
            "manifest": fraud_manifest,
            "signature_b64": fraud_sig,
        },
        headers=headers,
    )
    assert res.status_code == 400
    assert "nonce" in res.json()["detail"].lower()


# ==============================================================================
# 5. Cryptographic Verification & Tamper Tests
# ==============================================================================

def test_tampered_signature_bytes_rejected(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "bad_sig@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, _, _ = upload_and_ready_doc(client_p4, headers)
    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    manifest = prep_res.json()["manifest"]

    # Random corrupted signature bytes
    garbage_sig = base64.b64encode(os.urandom(384)).decode("utf-8")

    res = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id,
            "key_id": key_id,
            "manifest": manifest,
            "signature_b64": garbage_sig,
        },
        headers=headers,
    )
    assert res.status_code == 422
    assert "không hợp lệ" in res.json()["detail"].lower()


def test_wrong_private_key_signature_rejected(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "wrong_key@cyber.edu")
    headers = auth_info["headers"]
    priv_key_reg, _, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key_reg, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, _, _ = upload_and_ready_doc(client_p4, headers)
    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    manifest = prep_res.json()["manifest"]

    # Sign with another private key
    unrelated_priv_key, _, _, _ = generate_test_rsa_3072()
    wrong_sig = sign_manifest_py(unrelated_priv_key, manifest)

    res = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id,
            "key_id": key_id,
            "manifest": manifest,
            "signature_b64": wrong_sig,
        },
        headers=headers,
    )
    assert res.status_code == 422
    assert "không hợp lệ" in res.json()["detail"].lower()


def test_tampered_pdf_on_disk_rejected(client_p4, storage_p4, db_session):
    auth_info = register_and_login_user(client_p4, "disk_tamper@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, _, _ = upload_and_ready_doc(client_p4, headers)
    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    manifest = prep_res.json()["manifest"]
    sig_b64 = sign_manifest_py(priv_key, manifest)

    # Tamper with the PDF file on disk!
    ver_obj = db_session.get(DocumentVersion, ver_id)
    storage_path = Path(storage_p4.root) / ver_obj.storage_key
    with open(storage_path, "wb") as f:
        f.write(b"%PDF-1.4 TAMPERED CONTENT HACKED")

    res = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id,
            "key_id": key_id,
            "manifest": manifest,
            "signature_b64": sig_b64,
        },
        headers=headers,
    )
    assert res.status_code == 422
    assert "toàn vẹn" in res.json()["detail"].lower()


def test_revoked_key_signing_rejected(client_p4, db_session):
    auth_info = register_and_login_user(client_p4, "revoked_signer@cyber.edu")
    headers = auth_info["headers"]
    priv_key, pub_key, spki_pem, fingerprint = generate_test_rsa_3072()
    key_info = register_user_key(client_p4, auth_info, priv_key, spki_pem, fingerprint)
    key_id = key_info["id"]

    doc_id, ver_id, _, _ = upload_and_ready_doc(client_p4, headers)
    prep_res = client_p4.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    manifest = prep_res.json()["manifest"]
    sig_b64 = sign_manifest_py(priv_key, manifest)

    # Revoke key prior to submission
    rev_res = client_p4.post(f"/api/v1/keys/{key_id}/revoke", headers=headers)
    assert rev_res.status_code == 200

    res = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id,
            "key_id": key_id,
            "manifest": manifest,
            "signature_b64": sig_b64,
        },
        headers=headers,
    )
    assert res.status_code == 400
    assert "thu hồi" in res.json()["detail"].lower() or "revoked" in res.json()["detail"].lower()


# ==============================================================================
# 6. Database Immutability & Trigger Verification
# ==============================================================================

def test_database_trigger_blocks_signed_without_signature_row(db_session):
    # Attempt direct SQL transition of DocumentVersion to SIGNED without inserting a Signature
    user = User(
        email="trig_user@cyber.edu",
        full_name="Trig User",
        password_hash="dummy",
    )
    db_session.add(user)
    db_session.flush()

    doc = Document(owner_id=user.id, title="Trigger Doc")
    db_session.add(doc)
    db_session.flush()

    version = DocumentVersion(
        document_id=doc.id,
        version_no=1,
        file_sha256="a" * 64,
        file_size_bytes=1024,
        storage_key="test/trigger_path.pdf",
        original_filename="doc.pdf",
        state=VersionState.READY_TO_SIGN,
        locked_at=datetime.now(timezone.utc),
    )
    db_session.add(version)
    db_session.commit()

    # Now attempt illegal state update
    with pytest.raises(Exception) as exc_info:
        db_session.execute(
            text("UPDATE document_versions SET state = 'SIGNED' WHERE id = :vid"),
            {"vid": str(version.id)},
        )
        db_session.commit()

    assert "Immutable version or invalid transition" in str(exc_info.value)
    db_session.rollback()


# ==============================================================================
# 7. Authorization & IDOR Tests
# ==============================================================================

def test_idor_cross_user_signing_rejected(client_p4, db_session):
    auth_a = register_and_login_user(client_p4, "user_a@cyber.edu")
    auth_b = register_and_login_user(client_p4, "user_b@cyber.edu")

    priv_key_b, _, spki_pem_b, fp_b = generate_test_rsa_3072()
    key_b = register_user_key(client_p4, auth_b, priv_key_b, spki_pem_b, fp_b)

    # User A uploads a document
    doc_id_a, ver_id_a, _, _ = upload_and_ready_doc(client_p4, auth_a["headers"])

    # User B attempts to prepare sign User A's document
    res_b = client_p4.post(
        f"/api/v1/documents/{doc_id_a}/versions/{ver_id_a}/prepare-sign",
        json={"key_id": key_b["id"]},
        headers=auth_b["headers"],
    )
    assert res_b.status_code == 404

    # User B attempts to submit signature on User A's document
    fraud_manifest = {
        "manifest_version": 1,
        "document_version_id": ver_id_a,
        "document_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "key_id": key_b["id"],
        "signer_fingerprint": fp_b,
        "algorithm": "RSA-PSS-3072",
        "signing_nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "signing_timestamp": "2026-11-15T00:00:00.000Z",
        "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
    }
    fraud_sig = sign_manifest_py(priv_key_b, fraud_manifest)

    submit_b = client_p4.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id_a,
            "key_id": key_b["id"],
            "manifest": fraud_manifest,
            "signature_b64": fraud_sig,
        },
        headers=auth_b["headers"],
    )
    assert submit_b.status_code == 404
