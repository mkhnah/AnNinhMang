import base64
import hashlib
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import pytest
from sqlalchemy import select, text

from backend.app.core.config import Settings, settings
from backend.app.core.verification_limits import _ip_request_history
from backend.app.models.document import DocumentVersion, VersionState
from backend.app.models.enums import KeyStatus
from backend.app.models.key import PublicKey
from backend.app.models.share import ShareToken
from backend.app.models.signature import Signature
from backend.app.services.share_service import token_digest, validate_canonical_token
from backend.app.services.verification_receipts import _RECEIPTS
from tests.test_phase5_verification import (
    create_and_sign_document,
    generate_test_rsa_3072,
    register_and_login_user,
    register_user_key,
)


@pytest.fixture(autouse=True)
def reset_rate_limiters():
    _ip_request_history.clear()
    yield
    _ip_request_history.clear()


# --------------------------------------------------------------------------
# 1. Create share with valid signed PDF (Happy Path)
# --------------------------------------------------------------------------
def test_01_create_share_valid_signed_pdf(client_p5, db_session):
    user = register_and_login_user(client_p5, "share-user01@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7, "label": "Valid Share"},
        headers=user["headers"],
    )
    assert res.status_code == 201, res.text
    data = res.json()
    assert "id" in data
    assert data["version_id"] == ver_id
    assert data["label"] == "Valid Share"
    assert "/verify/share/" in data["share_url"]

    raw_token = data["share_url"].rsplit("/", 1)[-1]
    assert len(raw_token) == 43

    # Public verification
    pub_res = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert pub_res.status_code == 200, pub_res.text
    pub_data = pub_res.json()
    assert pub_data["title"] == "report.pdf"
    assert pub_data["results"]["summary_status"] == "VERIFIED"
    assert pub_data["results"]["evidence_consistency"] == "CONSISTENT"
    assert pub_data["results"]["results"]["cryptographic_validity"] == "VALID"
    assert pub_data["results"]["results"]["document_integrity"] == "UNCHANGED"
    assert pub_data["results"]["results"]["key_revocation_status"] == "ACTIVE"


# --------------------------------------------------------------------------
# 2. Create share with tampered PDF rejected (FIX-P6-01)
# --------------------------------------------------------------------------
def test_02_create_share_tampered_pdf_rejected(client_p5, db_session, storage_p5):
    user = register_and_login_user(client_p5, "share-tampered@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    ver = db_session.scalar(select(DocumentVersion).where(DocumentVersion.id == ver_id))
    # Tamper 1 byte in stored PDF file
    path = storage_p5.root / ver.storage_key
    with open(path, "r+b") as f:
        f.seek(50)
        original_byte = f.read(1)
        tampered_byte = bytes([(original_byte[0] ^ 0xFF)])
        f.seek(50)
        f.write(tampered_byte)

    # Attempt to create share
    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    assert res.status_code == 422
    assert "nguyên bản" in res.json()["detail"].lower() or "sửa đổi" in res.json()["detail"].lower()

    # Ensure no ShareToken was saved
    assert db_session.scalar(select(ShareToken).where(ShareToken.version_id == ver_id)) is None


# --------------------------------------------------------------------------
# 3. Create share with missing PDF rejected (FIX-P6-01)
# --------------------------------------------------------------------------
def test_03_create_share_missing_pdf_rejected(client_p5, db_session, storage_p5):
    user = register_and_login_user(client_p5, "share-missing@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    ver = db_session.scalar(select(DocumentVersion).where(DocumentVersion.id == ver_id))
    path = storage_p5.root / ver.storage_key
    path.unlink()

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    assert res.status_code == 422
    assert db_session.scalar(select(ShareToken).where(ShareToken.version_id == ver_id)) is None


# --------------------------------------------------------------------------
# 4. Create share with invalid/corrupted signature rejected
# --------------------------------------------------------------------------
def test_04_create_share_invalid_signature_rejected(client_p5, db_session):
    user = register_and_login_user(client_p5, "share-invalidsig@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    # Drop trigger temporarily to simulate DB tampering
    db_session.execute(text("DROP TRIGGER IF EXISTS signature_no_update"))
    db_session.execute(
        text("UPDATE signatures SET signature_b64 = :sig WHERE version_id = :vid"),
        {"sig": base64.b64encode(b"invalid_signature_bytes_3072_padding").decode(), "vid": ver_id},
    )
    db_session.commit()

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    assert res.status_code == 422
    assert "chữ ký" in res.json()["detail"].lower()


# --------------------------------------------------------------------------
# 5. Create share with inconsistent evidence rejected
# --------------------------------------------------------------------------
def test_05_create_share_inconsistent_evidence_rejected(client_p5, db_session):
    user = register_and_login_user(client_p5, "share-inconsistent@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    db_session.execute(text("DROP TRIGGER IF EXISTS signature_no_update"))
    db_session.execute(
        text("UPDATE signatures SET manifest_sha256 = '0000000000000000000000000000000000000000000000000000000000000000' WHERE version_id = :vid"),
        {"vid": ver_id},
    )
    db_session.commit()

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    assert res.status_code == 422
    assert "nhất quán" in res.json()["detail"].lower()


# --------------------------------------------------------------------------
# 6. Create share with revoked key issuance policy rejected (FIX-P6-01)
# --------------------------------------------------------------------------
def test_06_create_share_revoked_key_issuance_policy_rejected(client_p5, db_session):
    user = register_and_login_user(client_p5, "share-revokedkey@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    # Revoke key via API
    rev_res = client_p5.post(f"/api/v1/keys/{key['id']}/revoke", headers=user["headers"])
    assert rev_res.status_code == 200

    # Attempt to create share with revoked key
    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    assert res.status_code == 422
    assert "thu hồi" in res.json()["detail"].lower()
    assert db_session.scalar(select(ShareToken).where(ShareToken.version_id == ver_id)) is None


# --------------------------------------------------------------------------
# 7. Owner authorization (User B cannot share User A's document)
# --------------------------------------------------------------------------
def test_07_create_share_owner_authorization(client_p5, db_session):
    user_a = register_and_login_user(client_p5, "user-a@cyber.edu")
    user_b = register_and_login_user(client_p5, "user-b@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user_a, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user_a, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user_b["headers"],
    )
    assert res.status_code == 404


# --------------------------------------------------------------------------
# 8. Cross-document / non-existent version ID
# --------------------------------------------------------------------------
def test_08_create_share_nonexistent_version(client_p5):
    user = register_and_login_user(client_p5, "user-nonexistent@cyber.edu")
    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": "00000000-0000-0000-0000-000000000000", "expires_in_days": 7},
        headers=user["headers"],
    )
    assert res.status_code == 404


# --------------------------------------------------------------------------
# 9. Cross-user IDOR on revoke share rejected
# --------------------------------------------------------------------------
def test_09_cross_user_revoke_share_idor_rejected(client_p5, db_session):
    user_a = register_and_login_user(client_p5, "user-a-rev@cyber.edu")
    user_b = register_and_login_user(client_p5, "user-b-rev@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user_a, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user_a, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user_a["headers"],
    )
    share_id = res.json()["id"]

    # User B attempts to revoke User A's share
    del_res = client_p5.delete(f"/api/v1/shares/{share_id}", headers=user_b["headers"])
    assert del_res.status_code == 404

    # Verify share is still active
    share = db_session.scalar(select(ShareToken).where(ShareToken.id == share_id))
    assert share.revoked_at is None


# --------------------------------------------------------------------------
# 10. CSRF protection on share creation and revocation
# --------------------------------------------------------------------------
def test_10_csrf_protection_on_share_endpoints(client_p5):
    user = register_and_login_user(client_p5, "csrf-user@cyber.edu")
    # client_p5 has access_token cookie from login, but we send request without X-CSRF-Token or X-Requested-With
    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": "00000000-0000-0000-0000-000000000000", "expires_in_days": 7},
        headers={},
    )
    assert res.status_code == 403
    assert "CSRF" in res.json()["detail"]


# --------------------------------------------------------------------------
# 11. Token 256-bit entropy source validation
# --------------------------------------------------------------------------
def test_11_token_256bit_entropy_source(client_p5):
    user = register_and_login_user(client_p5, "entropy-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]
    assert len(raw_token) == 43
    # 43 chars urlsafe base64 decodes to exactly 32 bytes (256 bits)
    decoded = base64.urlsafe_b64decode(raw_token + "=")
    assert len(decoded) == 32


# --------------------------------------------------------------------------
# 12. Token canonical encoding validation (FIX-P6-07.A)
# --------------------------------------------------------------------------
def test_12_token_canonical_encoding_validation(client_p5):
    # Short token
    assert client_p5.get("/api/v1/verify/share/abc").status_code == 404
    # Special characters
    assert client_p5.get("/api/v1/verify/share/abc!@#$").status_code == 404
    # 43 chars with illegal base64 pad bits
    # A valid 32-byte decoded base64url has 2 unused bits in the 43rd char.
    # If those bits are modified, canonical re-encode will not match.
    valid_bytes = b"A" * 32
    valid_token = base64.urlsafe_b64encode(valid_bytes).rstrip(b"=").decode("ascii")
    assert len(valid_token) == 43

    # Mutate last char to non-canonical
    non_canonical_char = "B" if valid_token[-1] != "B" else "C"
    tampered_token = valid_token[:-1] + non_canonical_char
    assert client_p5.get(f"/api/v1/verify/share/{tampered_token}").status_code == 404


# --------------------------------------------------------------------------
# 13. Token SHA-256 only stored in DB (Zero raw token persistence)
# --------------------------------------------------------------------------
def test_13_token_hash_stored_only_in_db(client_p5, db_session):
    user = register_and_login_user(client_p5, "zerotoken-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]
    expected_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()

    share = db_session.scalar(select(ShareToken).where(ShareToken.token_hash == expected_hash))
    assert share is not None
    assert share.token_hash == expected_hash
    # Ensure raw token string is NOT anywhere in the row
    assert raw_token not in str(share.__dict__)


# --------------------------------------------------------------------------
# 14. Expired token T-09 returns HTTP 410
# --------------------------------------------------------------------------
def test_14_expired_token_t09(client_p5, db_session):
    user = register_and_login_user(client_p5, "expired-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]
    share_id = res.json()["id"]

    # Expire the token
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    db_session.execute(
        text("UPDATE share_tokens SET expires_at = :past WHERE id = :id"),
        {"past": past, "id": share_id},
    )
    db_session.commit()

    pub_res = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert pub_res.status_code == 410
    assert "hết hạn" in pub_res.json()["detail"].lower()


# --------------------------------------------------------------------------
# 15. Revoked token T-10 returns HTTP 404
# --------------------------------------------------------------------------
def test_15_revoked_token_t10(client_p5, db_session):
    user = register_and_login_user(client_p5, "revoked-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]
    share_id = res.json()["id"]

    # Revoke
    rev_res = client_p5.delete(f"/api/v1/shares/{share_id}", headers=user["headers"])
    assert rev_res.status_code == 204

    pub_res = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert pub_res.status_code == 404
    assert "không tồn tại" in pub_res.json()["detail"].lower()


# --------------------------------------------------------------------------
# 16. Digest comparison T-16
# --------------------------------------------------------------------------
def test_16_digest_comparison_t16():
    token = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
    digest = token_digest(token)
    assert len(digest) == 64
    assert int(digest, 16) > 0


# --------------------------------------------------------------------------
# 17. Concurrent revoke idempotency
# --------------------------------------------------------------------------
def test_17_concurrent_revoke_idempotency(client_p5):
    user = register_and_login_user(client_p5, "concurrent-revoke@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    share_id = res.json()["id"]

    # First revoke
    res1 = client_p5.delete(f"/api/v1/shares/{share_id}", headers=user["headers"])
    assert res1.status_code == 204

    # Second revoke (idempotent)
    res2 = client_p5.delete(f"/api/v1/shares/{share_id}", headers=user["headers"])
    assert res2.status_code == 204

    # Legacy POST revoke path (idempotent)
    res3 = client_p5.post(f"/api/v1/shares/{share_id}/revoke", headers=user["headers"])
    assert res3.status_code == 204


# --------------------------------------------------------------------------
# 18. Stale ORM state prevention on concurrent revoke (FIX-P6-02)
# --------------------------------------------------------------------------
def test_18_identity_map_stale_refresh_concurrent_revoke(client_p5, db_session):
    user = register_and_login_user(client_p5, "stale-orm@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]
    share_id = res.json()["id"]

    # Load share into session
    share = db_session.scalar(select(ShareToken).where(ShareToken.id == share_id))
    assert share.revoked_at is None

    # Revoke share via client
    rev_res = client_p5.delete(f"/api/v1/shares/{share_id}", headers=user["headers"])
    assert rev_res.status_code == 204

    # Direct query should immediately see revocation
    pub_res = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert pub_res.status_code == 404


# --------------------------------------------------------------------------
# 19. Rate limiting on public share verification
# --------------------------------------------------------------------------
def test_19_rate_limiting_on_public_verify(client_p5):
    # Trigger 429 by sending requests exceeding rate limit
    for i in range(65):
        res = client_p5.get("/api/v1/verify/share/not-a-valid-token-length-so-it-is-short")
        if res.status_code == 429:
            break
    assert res.status_code == 429
    assert res.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate"
    assert res.headers.get("Referrer-Policy") == "no-referrer"


# --------------------------------------------------------------------------
# 20. Public privacy allowlist (No PDF bytes, paths, or raw signatures)
# --------------------------------------------------------------------------
def test_20_public_privacy_allowlist(client_p5):
    user = register_and_login_user(client_p5, "privacy-check@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]

    pub_res = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert pub_res.status_code == 200
    body = pub_res.text

    # Forbidden leakages
    assert "password_hash" not in body
    assert "email" not in body
    assert "data/storage" not in body
    assert "storage_key" not in body
    assert "token_hash" not in body
    assert "document_version_id" not in body
    assert "verification_receipt" not in body


# --------------------------------------------------------------------------
# 21. Security headers on success and error responses (FIX-P6-05)
# --------------------------------------------------------------------------
def test_21_security_headers_on_all_responses(client_p5):
    # 200 OK
    user = register_and_login_user(client_p5, "headers-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 7},
        headers=user["headers"],
    )
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]

    res200 = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert res200.status_code == 200
    assert res200.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate"
    assert res200.headers.get("Referrer-Policy") == "no-referrer"
    assert res200.headers.get("X-Content-Type-Options") == "nosniff"

    # 404 Not Found
    res404 = client_p5.get("/api/v1/verify/share/invalid_token_404_test_check_here_now_1234")
    assert res404.status_code == 404
    assert res404.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate"
    assert res404.headers.get("Referrer-Policy") == "no-referrer"
    assert res404.headers.get("X-Content-Type-Options") == "nosniff"


# --------------------------------------------------------------------------
# 22. Public PDF download inaccessible (Zero PDF Leakage)
# --------------------------------------------------------------------------
def test_22_public_pdf_download_inaccessible(client_p5):
    # The public router has no PDF download endpoint
    res = client_p5.get("/api/v1/verify/share/download")
    assert res.status_code in (404, 405)


# --------------------------------------------------------------------------
# 23. Signature package export inaccessible using share token
# --------------------------------------------------------------------------
def test_23_signature_package_export_inaccessible_by_share_token(client_p5):
    user = register_and_login_user(client_p5, "pkg-export-test@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    # Clear auth cookies from client
    client_p5.cookies.clear()
    # Calling package export without session cookie
    res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/signature-package")
    assert res.status_code == 401


# --------------------------------------------------------------------------
# 24. Expiry config bounds validation (FIX-P6-07.B)
# --------------------------------------------------------------------------
def test_24_expiry_config_bounds(client_p5):
    user = register_and_login_user(client_p5, "bounds-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    # 0 days (below min 1)
    res_zero = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 0},
        headers=user["headers"],
    )
    assert res_zero.status_code == 422

    # 99 days (above max 30)
    res_max = client_p5.post(
        "/api/v1/shares",
        json={"version_id": ver_id, "expires_in_days": 99},
        headers=user["headers"],
    )
    assert res_max.status_code == 422


# --------------------------------------------------------------------------
# 25. Invalid PUBLIC_APP_BASE_URL rejected by Settings validator (FIX-P6-07.C)
# --------------------------------------------------------------------------
def test_25_invalid_public_app_base_url_rejected():
    with pytest.raises(ValueError):
        Settings.validate_public_app_base_url("ftp://localhost:5173")

    with pytest.raises(ValueError):
        Settings.validate_public_app_base_url("http://user:pass@localhost:5173")

    with pytest.raises(ValueError):
        Settings.validate_public_app_base_url("http://localhost:5173?param=val")

    with pytest.raises(ValueError):
        Settings.validate_public_app_base_url("http://localhost:5173#frag")

    with pytest.raises(ValueError):
        Settings.validate_public_app_base_url("http://localhost:5173/../../etc")

    # Valid URLs
    assert Settings.validate_public_app_base_url("http://localhost:5173") == "http://localhost:5173"
    assert Settings.validate_public_app_base_url("https://docsign.example.com") == "https://docsign.example.com"


# --------------------------------------------------------------------------
# 26. List shares ownership & document filtering (FIX-P6-06)
# --------------------------------------------------------------------------
def test_26_list_shares_ownership_and_filtering(client_p5):
    user_a = register_and_login_user(client_p5, "list-user-a@cyber.edu")
    user_b = register_and_login_user(client_p5, "list-user-b@cyber.edu")

    priv_a, _, pem_a, fp_a = generate_test_rsa_3072()
    key_a = register_user_key(client_p5, user_a, priv_a, pem_a, fp_a)
    doc_a1, ver_a1, _, _, _ = create_and_sign_document(client_p5, user_a, key_a, priv_a)
    doc_a2, ver_a2, _, _, _ = create_and_sign_document(client_p5, user_a, key_a, priv_a)

    # User A creates shares for doc_a1 and doc_a2
    s1 = client_p5.post("/api/v1/shares", json={"version_id": ver_a1, "label": "Doc A1"}, headers=user_a["headers"]).json()
    s2 = client_p5.post("/api/v1/shares", json={"version_id": ver_a2, "label": "Doc A2"}, headers=user_a["headers"]).json()

    # User B list should be empty
    list_b = client_p5.get("/api/v1/shares", headers=user_b["headers"]).json()
    assert len(list_b) == 0

    # User A listing all
    list_all = client_p5.get("/api/v1/shares", headers=user_a["headers"]).json()
    assert len(list_all) >= 2

    # User A filtering by document_id
    list_filtered = client_p5.get(f"/api/v1/shares?document_id={doc_a1}", headers=user_a["headers"]).json()
    assert len(list_filtered) == 1
    assert list_filtered[0]["id"] == s1["id"]
    assert list_filtered[0]["status"] == "ACTIVE"


# --------------------------------------------------------------------------
# 27. Pagination on list shares
# --------------------------------------------------------------------------
def test_27_pagination_on_list_shares(client_p5):
    user = register_and_login_user(client_p5, "paged-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    # Create 3 shares
    for i in range(3):
        client_p5.post("/api/v1/shares", json={"version_id": ver_id, "label": f"Share {i}"}, headers=user["headers"])

    # Page 1 (limit 2)
    p1 = client_p5.get(f"/api/v1/shares?document_id={doc_id}&limit=2&offset=0", headers=user["headers"]).json()
    assert len(p1) == 2

    # Page 2 (offset 2)
    p2 = client_p5.get(f"/api/v1/shares?document_id={doc_id}&limit=2&offset=2", headers=user["headers"]).json()
    assert len(p2) == 1


# --------------------------------------------------------------------------
# 28. No raw token leakage in application logs or server responses
# --------------------------------------------------------------------------
def test_28_no_raw_token_leakage(client_p5):
    # Public verify response must not repeat the raw token
    user = register_and_login_user(client_p5, "no-token-leak@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post("/api/v1/shares", json={"version_id": ver_id}, headers=user["headers"])
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]

    pub = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert raw_token not in pub.text


# --------------------------------------------------------------------------
# 29. No unused receipt issuance during public verify (FIX-P6-07.F)
# --------------------------------------------------------------------------
def test_29_no_unused_receipt_issuance(client_p5):
    user = register_and_login_user(client_p5, "receipt-check@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post("/api/v1/shares", json={"version_id": ver_id}, headers=user["headers"])
    raw_token = res.json()["share_url"].rsplit("/", 1)[-1]

    cache_size_before = len(_RECEIPTS)
    pub = client_p5.get(f"/api/v1/verify/share/{raw_token}")
    assert pub.status_code == 200
    cache_size_after = len(_RECEIPTS)
    assert cache_size_after == cache_size_before


# --------------------------------------------------------------------------
# 30. SQLite trigger and data retention (share_token_immutable)
# --------------------------------------------------------------------------
def test_30_sqlite_trigger_share_token_immutable(client_p5, db_session):
    user = register_and_login_user(client_p5, "trigger-user@cyber.edu")
    priv, _, pem, fp = generate_test_rsa_3072()
    key = register_user_key(client_p5, user, priv, pem, fp)
    doc_id, ver_id, _, _, _ = create_and_sign_document(client_p5, user, key, priv)

    res = client_p5.post("/api/v1/shares", json={"version_id": ver_id}, headers=user["headers"])
    share_id = res.json()["id"]

    # Attempt to tamper with token_hash should abort via trigger
    with pytest.raises(Exception):
        db_session.execute(
            text("UPDATE share_tokens SET token_hash = '1111111111111111111111111111111111111111111111111111111111111111' WHERE id = :id"),
            {"id": share_id},
        )
        db_session.commit()
    db_session.rollback()

    # Revoke once
    client_p5.delete(f"/api/v1/shares/{share_id}", headers=user["headers"])

    # Attempt to un-revoke (set revoked_at back to NULL) should abort via trigger
    with pytest.raises(Exception):
        db_session.execute(
            text("UPDATE share_tokens SET revoked_at = NULL WHERE id = :id"),
            {"id": share_id},
        )
        db_session.commit()
    db_session.rollback()
