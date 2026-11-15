import base64
import copy
import hashlib
import json
import os
import secrets
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
from backend.app.crypto.jcs import canonicalize_jcs
from backend.app.main import app
from backend.app.models.document import Document, DocumentVersion, VersionState
from backend.app.models.enums import KeyStatus
from backend.app.models.key import PublicKey
from backend.app.models.signature import Signature
from backend.app.models.verification import VerificationEvent
from backend.app.models.user import User
from backend.app.services.verification_service import VerificationService, _ip_request_history
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
def storage_p5():
    with tempfile.TemporaryDirectory(prefix="p5-test-storage-", dir="data") as root:
        yield LocalStorageService(Path(root).resolve())


@pytest.fixture
def client_p5(client, storage_p5):
    app.dependency_overrides[get_storage] = lambda: storage_p5
    # Reset in-memory rate limiter between tests
    _ip_request_history.clear()
    yield client
    app.dependency_overrides.pop(get_storage, None)


def register_and_login_user(client: TestClient, email: str = "verifier@cyber.edu"):
    payload = {
        "email": email,
        "full_name": "Verification User",
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


def create_and_sign_document(client: TestClient, auth_info: dict, key_info: dict, private_key):
    headers = auth_info["headers"]
    key_id = key_info["id"]
    pdf_bytes = make_pdf()

    up_res = client.post(
        "/api/v1/documents",
        files={"file": ("report.pdf", pdf_bytes, "application/pdf")},
        headers=headers,
    )
    assert up_res.status_code == 201
    doc_id = up_res.json()["document_id"]
    ver_id = up_res.json()["version_id"]

    ready_res = client.post(f"/api/v1/documents/{doc_id}/versions/{ver_id}/ready", headers=headers)
    assert ready_res.status_code == 200

    prep_res = client.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key_id},
        headers=headers,
    )
    assert prep_res.status_code == 200
    prep_data = prep_res.json()
    manifest = prep_data["manifest"]

    sig_b64 = sign_manifest_py(private_key, manifest)

    sub_res = client.post(
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
    return doc_id, ver_id, pdf_bytes, manifest, sig_b64


# =========================================================================
# TEST SUITE — PHASE 5 VERIFICATION ENGINE
# =========================================================================

class TestModeAInternalVerification:
    """Mode A: Authenticated internal verification of documents stored in DB & filesystem."""

    def test_internal_verify_valid_signature_six_dimensions(self, client_p5, db_session):
        """Case A: Valid signed document returns 6 independent dimensions with VERIFIED summary."""
        user = register_and_login_user(client_p5, "internal_valid@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/verify", headers=user["headers"])
        assert res.status_code == 200
        data = res.json()

        assert data["verification_mode"] == "INTERNAL"
        assert data["summary_status"] == "VERIFIED"
        assert data["document_hash_expected"] == data["document_hash_computed"]
        assert data["signer_fingerprint"] == fp
        assert data["key_id"] == key["id"]

        results = data["results"]
        assert results["cryptographic_validity"] == "VALID"
        assert results["document_integrity"] == "UNCHANGED"
        assert results["key_ownership"] == "VERIFIED_POP"
        assert results["certificate_trust"] == "SELF_REGISTERED"
        assert results["key_revocation_status"] == "ACTIVE"
        assert results["timestamp_trust_level"] == "SERVER_RECORDED"

        # Verify audit log was recorded in DB
        event = db_session.query(VerificationEvent).filter_by(document_version_id=ver_id).first()
        assert event is not None
        assert event.verification_mode == "INTERNAL"
        assert event.summary_status == "VERIFIED"

    def test_internal_verify_tampered_pdf_file(self, client_p5, db_session, storage_p5):
        """Case B: PDF file tampered on disk -> crypto VALID, integrity TAMPERED, summary INTEGRITY_COMPROMISED."""
        user = register_and_login_user(client_p5, "tampered_pdf@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        # Alter 1 byte in stored PDF on disk (byte 50 inside document body)
        version = db_session.query(DocumentVersion).filter_by(id=ver_id).first()
        file_path = storage_p5.root / version.storage_key
        with open(file_path, "r+b") as f:
            f.seek(50)
            byte = f.read(1)
            f.seek(50)
            f.write(bytes([(byte[0] ^ 0xFF)]))

        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/verify", headers=user["headers"])
        assert res.status_code == 200
        data = res.json()

        assert data["summary_status"] == "INTEGRITY_COMPROMISED"
        assert data["results"]["cryptographic_validity"] == "VALID"
        assert data["results"]["document_integrity"] == "TAMPERED"
        assert data["document_hash_expected"] != data["document_hash_computed"]
        assert len(data["warnings"]) > 0

    def test_internal_verify_corrupted_signature_row(self, client_p5, db_session):
        """Case C: Corrupted signature_b64 in DB -> crypto INVALID, integrity UNCHANGED, summary SIGNATURE_INVALID."""
        user = register_and_login_user(client_p5, "corrupted_sig@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        # SQLite trigger prevents normal UPDATE on signatures, so we temporarily test via raw text or service
        sig = db_session.query(Signature).filter_by(version_id=ver_id).first()
        raw_sig = base64.b64decode(sig.signature_b64)
        corrupted_raw = bytes([raw_sig[0] ^ 0xFF]) + raw_sig[1:]
        corrupted_b64 = base64.b64encode(corrupted_raw).decode("utf-8")

        # Disable SQLite trigger to simulate database corruption attack
        db_session.execute(text("DROP TRIGGER IF EXISTS signature_no_update;"))
        db_session.execute(text("UPDATE signatures SET signature_b64 = :sig WHERE id = :id"), {"sig": corrupted_b64, "id": sig.id})
        db_session.commit()

        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/verify", headers=user["headers"])
        assert res.status_code == 200
        data = res.json()

        assert data["summary_status"] == "SIGNATURE_INVALID"
        assert data["results"]["cryptographic_validity"] == "INVALID"
        assert data["results"]["document_integrity"] == "UNCHANGED"

    def test_internal_verify_revoked_key(self, client_p5, db_session):
        """Case F: Enrolled key revoked after signing -> crypto VALID, integrity UNCHANGED, revocation REVOKED."""
        user = register_and_login_user(client_p5, "revoked_key@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        # Revoke the signing key
        rev_res = client_p5.post(f"/api/v1/keys/{key['id']}/revoke", headers=user["headers"])
        assert rev_res.status_code == 200

        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/verify", headers=user["headers"])
        assert res.status_code == 200
        data = res.json()

        assert data["summary_status"] == "REVOKED_KEY"
        assert data["results"]["cryptographic_validity"] == "VALID"
        assert data["results"]["document_integrity"] == "UNCHANGED"
        assert data["results"]["key_revocation_status"] == "REVOKED"
        assert data["results"]["revoked_at"] is not None

    def test_internal_verify_idor_unauthorized_user(self, client_p5):
        """Case I: Cross-user IDOR access returns 404 (document not found for user B)."""
        user_a = register_and_login_user(client_p5, "owner_a@cyber.edu")
        user_b = register_and_login_user(client_p5, "attacker_b@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user_a, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user_a, key, priv)

        # User B attempts to verify User A's document
        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/verify", headers=user_b["headers"])
        assert res.status_code == 404

    def test_internal_verify_unsigned_version_rejected(self, client_p5):
        """Unsigned or Draft version cannot be verified -> 400 Bad Request."""
        user = register_and_login_user(client_p5, "unsigned_doc@cyber.edu")
        pdf_bytes = make_pdf()
        up_res = client_p5.post(
            "/api/v1/documents",
            files={"file": ("draft.pdf", pdf_bytes, "application/pdf")},
            headers=user["headers"],
        )
        doc_id = up_res.json()["document_id"]
        ver_id = up_res.json()["version_id"]

        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/verify", headers=user["headers"])
        assert res.status_code in (400, 404)
        detail = res.json()["detail"].lower()
        assert "chữ ký" in detail or "not signed" in detail or "signature" in detail


class TestSignaturePackageExport:
    """Tests for Signature Package export and IDOR security."""

    def test_export_package_success(self, client_p5):
        """Owner can successfully export standalone detached signature package."""
        user = register_and_login_user(client_p5, "exporter@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/signature-package", headers=user["headers"])
        assert res.status_code == 200
        pkg = res.json()

        assert pkg["package_version"] == 1
        assert pkg["signature_format"] == "DETACHED_JCS_V1"
        assert pkg["manifest"] == manifest
        assert pkg["signature_b64"] == sig_b64
        assert pkg["public_key_spki_pem"].strip() == pem.strip()

    def test_export_package_idor_rejected(self, client_p5):
        """Non-owner user cannot export signature package -> 404."""
        user_a = register_and_login_user(client_p5, "owner_exp@cyber.edu")
        user_b = register_and_login_user(client_p5, "spy_exp@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user_a, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user_a, key, priv)

        res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/signature-package", headers=user_b["headers"])
        assert res.status_code == 404


class TestModeBIndependentVerification:
    """Mode B: Anonymous / Public Detached Verification."""

    def test_independent_verify_with_file_upload_success(self, client_p5):
        """Case J: Roundtrip export & independent re-verification passes 100% anonymously."""
        user = register_and_login_user(client_p5, "roundtrip@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        # Export signature package
        pkg_res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/signature-package", headers=user["headers"])
        pkg_bytes = json.dumps(pkg_res.json()).encode("utf-8")

        # Independent verify WITHOUT login (no auth headers)
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={
                "file": ("original.pdf", pdf_bytes, "application/pdf"),
                "package_file": ("signature-package.json", pkg_bytes, "application/json"),
            },
        )
        assert res.status_code == 200
        data = res.json()

        assert data["verification_mode"] == "INDEPENDENT_DETACHED"
        assert data["summary_status"] == "VERIFIED"
        assert data["results"]["cryptographic_validity"] == "VALID"
        assert data["results"]["document_integrity"] == "UNCHANGED"
        # Since key was enrolled in DB, key_ownership is VERIFIED_POP
        assert data["results"]["key_ownership"] == "VERIFIED_POP"
        assert data["results"]["certificate_trust"] == "SELF_REGISTERED"
        assert data["results"]["key_revocation_status"] == "ACTIVE"

    def test_independent_verify_with_package_json_form_string(self, client_p5):
        """Independent verify using package_json form text field."""
        user = register_and_login_user(client_p5, "form_string@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        pkg_res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/signature-package", headers=user["headers"])
        pkg_str = json.dumps(pkg_res.json())

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("doc.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": pkg_str},
        )
        assert res.status_code == 200
        assert res.json()["summary_status"] == "VERIFIED"

    def test_independent_verify_unknown_external_key(self, client_p5):
        """G: Verification with key NOT in DB results in UNVERIFIED ownership and UNKNOWN revocation."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": pdf_sha256,
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        sig_b64 = sign_manifest_py(priv, manifest)

        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": sig_b64,
            "public_key_spki_pem": pem,
        }

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("external.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 200, res.text
        data = res.json()

        assert data["summary_status"] == "VERIFIED"
        assert data["results"]["cryptographic_validity"] == "VALID"
        assert data["results"]["document_integrity"] == "UNCHANGED"
        assert data["results"]["key_ownership"] == "UNVERIFIED"
        assert data["results"]["key_revocation_status"] == "UNKNOWN"

    def test_independent_verify_tampered_pdf_detected(self, client_p5):
        """Case B: Tampered PDF provided to independent verify -> INTEGRITY_COMPROMISED."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": pdf_sha256,
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        sig_b64 = sign_manifest_py(priv, manifest)
        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": sig_b64,
            "public_key_spki_pem": pem,
        }

        # Modify 1 byte of PDF content body (preserving header and %%EOF)
        tampered_pdf = pdf_bytes[:50] + (b"X" if pdf_bytes[50:51] != b"X" else b"Y") + pdf_bytes[51:]

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("tampered.pdf", tampered_pdf, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 200, res.text
        data = res.json()

        assert data["summary_status"] == "INTEGRITY_COMPROMISED"
        assert data["results"]["cryptographic_validity"] == "VALID"
        assert data["results"]["document_integrity"] == "TAMPERED"

    def test_independent_verify_tampered_signature_detected(self, client_p5):
        """Case C: Tampered signature string -> SIGNATURE_INVALID."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": pdf_sha256,
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        sig_b64 = sign_manifest_py(priv, manifest)

        # Corrupt signature string (valid length 512 base64 chars)
        corrupted_raw = base64.b64decode(sig_b64)
        corrupted_b64 = base64.b64encode(bytes([corrupted_raw[0] ^ 0xFF]) + corrupted_raw[1:]).decode("utf-8")

        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": corrupted_b64,
            "public_key_spki_pem": pem,
        }

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 200, res.text
        data = res.json()

        assert data["summary_status"] == "SIGNATURE_INVALID"
        assert data["results"]["cryptographic_validity"] == "INVALID"
        assert data["results"]["document_integrity"] == "UNCHANGED"

    def test_independent_verify_mismatched_public_key(self, client_p5):
        """Case D: Signature made by Key 1, but package presents Key 2 -> rejected."""
        priv1, pub1, pem1, fp1 = generate_test_rsa_3072()
        priv2, pub2, pem2, fp2 = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()

        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": pdf_sha256,
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp1,  # Manifest declares Key 1
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        sig_b64 = sign_manifest_py(priv1, manifest)

        # Package attaches Key 2 SPKI PEM instead of Key 1
        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": sig_b64,
            "public_key_spki_pem": pem2,
        }

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 200
        assert res.json()["results"]["cryptographic_validity"] == "INVALID"

    def test_duplicate_json_keys_rejected(self, client_p5):
        """Case G / RFC 8785: Duplicate keys in JSON payload rejected."""
        pdf_bytes = make_pdf()
        dup_json = '{"package_version": 1, "package_version": 2, "signature_format": "DETACHED_JCS_V1"}'

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": dup_json},
        )
        assert res.status_code == 400
        assert "trùng lặp" in res.json()["detail"].lower() or "duplicate" in res.json()["detail"].lower()

    def test_missing_package_rejected(self, client_p5):
        """Neither package_file nor package_json provided -> 400."""
        pdf_bytes = make_pdf()
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
        )
        assert res.status_code == 400
        assert "package" in res.json()["detail"].lower()

    def test_non_pdf_file_rejected(self, client_p5):
        """Non-PDF uploaded file -> 400 or 415."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": "0" * 64,
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": "A" * 512,
            "public_key_spki_pem": pem,
        }
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("malicious.exe", b"MZ\x90\x00", "application/octet-stream")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code in (400, 415)
        assert "pdf" in res.json()["detail"].lower()


class TestVerificationReportGeneration:
    """Tests for Standardized Verification Report JSON export."""

    def test_generate_verification_report_schema_and_privacy(self, client_p5):
        """Case K: Verification report conforms to schema and does NOT leak secrets or local paths."""
        user = register_and_login_user(client_p5, "reporter@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        ver_res = client_p5.get(f"/api/v1/documents/{doc_id}/versions/{ver_id}/verify", headers=user["headers"])
        assert ver_res.status_code == 200
        verification_result = ver_res.json()

        # Generate report
        rep_res = client_p5.post("/api/v1/verify/report", json={"receipt_id":verification_result["verification_receipt"]}, headers=user["headers"])
        assert rep_res.status_code == 200
        report = rep_res.json()

        assert report["report_version"] == 1
        assert "report_id" in report
        assert "generated_at" in report
        assert "DOCSIGN" in report["evidence_source"]
        assert len(report["disclaimer"]) > 10
        assert report["verification_result"]["summary_status"] == "VERIFIED"

        # Check privacy / secret leakage
        report_str = json.dumps(report).lower()
        assert "private_key" not in report_str
        assert "password" not in report_str
        assert "bearer" not in report_str
        assert "bcrypt" not in report_str
        assert "/users/minhkhanhnguyen" not in report_str
        assert "users/staff" not in report_str


class TestRateLimitingAndLimits:
    """Security tests: rate limiting and payload size guards."""

    def test_rate_limiting_exceeded_triggers_429(self, client_p5):
        """Case L: More than 60 requests in sliding window triggers HTTP 429."""
        pdf_bytes = make_pdf()

        # Simulate filling rate limiter up to 60 requests
        client_ip = "testclient"
        now = datetime.now(timezone.utc).timestamp()
        _ip_request_history[client_ip] = [now] * 60

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": "{}"},
        )
        assert res.status_code == 429
        assert "quá nhiều yêu cầu" in res.json()["detail"].lower() or "rate limit" in res.json()["detail"].lower()
        assert "Retry-After" in res.headers

    def test_oversized_package_file_triggers_413(self, client_p5):
        """Oversized package file (> 512KB) is rejected with HTTP 413."""
        pdf_bytes = make_pdf()
        large_json = (" " * (513 * 1024)).encode("utf-8")
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={
                "file": ("contract.pdf", pdf_bytes, "application/pdf"),
                "package_file": ("large-package.json", large_json, "application/json"),
            },
        )
        assert res.status_code == 413
        assert "512kb" in res.json()["detail"].lower()

    def test_oversized_package_json_str_triggers_413(self, client_p5):
        """Oversized package JSON form string (> 512KB) is rejected with HTTP 413."""
        pdf_bytes = make_pdf()
        large_str = " " * (513 * 1024)
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": large_str},
        )
        assert res.status_code == 413
        assert "512kb" in res.json()["detail"].lower()


class TestAdditionalVerificationEdgeCases:
    """Additional edge cases to ensure complete 30-case verification test suite."""

    def test_independent_verify_revoked_key_in_db(self, client_p5):
        """Package presents an enrolled key that was REVOKED -> REVOKED_KEY."""
        user = register_and_login_user(client_p5, "edge_revoked@cyber.edu")
        priv, pub, pem, fp = generate_test_rsa_3072()
        key = register_user_key(client_p5, user, priv, pem, fp)
        doc_id, ver_id, pdf_bytes, manifest, sig_b64 = create_and_sign_document(client_p5, user, key, priv)

        # Revoke key in database
        client_p5.post(f"/api/v1/keys/{key['id']}/revoke", headers=user["headers"])

        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": sig_b64,
            "public_key_spki_pem": pem,
        }

        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["summary_status"] == "REVOKED_KEY"
        assert data["results"]["key_revocation_status"] == "REVOKED"
        assert data["results"]["key_ownership"] == "VERIFIED_POP"

    def test_independent_verify_missing_signature_b64(self, client_p5):
        """Package missing signature_b64 is rejected with 422."""
        pdf_bytes = make_pdf()
        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": {},
            "public_key_spki_pem": "pem",
        }
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 422

    def test_independent_verify_invalid_manifest_version(self, client_p5):
        """Manifest version != 1 is rejected with 422."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 2,  # Invalid version
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": "A" * 512,
            "public_key_spki_pem": pem,
        }
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 422

    def test_independent_verify_unsupported_algorithm(self, client_p5):
        """Algorithm not RSA-PSS-3072 is rejected with 422."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        manifest = {
            "algorithm": "ECDSA-P256",  # Formally deferred, strictly rejected
            "document_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": manifest,
            "signature_b64": "A" * 512,
            "public_key_spki_pem": pem,
        }
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 422

    def test_tampered_manifest_nonce_fails_math_verification(self, client_p5):
        """Tampering nonce causes RSA-PSS signature verification failure."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        sig_b64 = sign_manifest_py(priv, manifest)

        # Alter nonce after signing
        tampered_manifest = copy.deepcopy(manifest)
        tampered_manifest["signing_nonce"] = secrets.token_urlsafe(32)

        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": tampered_manifest,
            "signature_b64": sig_b64,
            "public_key_spki_pem": pem,
        }
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["summary_status"] == "SIGNATURE_INVALID"
        assert data["results"]["cryptographic_validity"] == "INVALID"

    def test_tampered_manifest_timestamp_fails_math_verification(self, client_p5):
        """Tampering timestamp causes RSA-PSS signature verification failure."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        sig_b64 = sign_manifest_py(priv, manifest)

        tampered_manifest = copy.deepcopy(manifest)
        tampered_manifest["signing_timestamp"] = "2026-11-15T11:00:00.000Z"

        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": tampered_manifest,
            "signature_b64": sig_b64,
            "public_key_spki_pem": pem,
        }
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["summary_status"] == "SIGNATURE_INVALID"
        assert data["results"]["cryptographic_validity"] == "INVALID"

    def test_tampered_manifest_context_fails_math_verification(self, client_p5):
        """Tampering domain separation context string fails validation or signature."""
        priv, pub, pem, fp = generate_test_rsa_3072()
        pdf_bytes = make_pdf()
        manifest = {
            "algorithm": "RSA-PSS-3072",
            "document_sha256": hashlib.sha256(pdf_bytes).hexdigest(),
            "document_version_id": str(uuid.uuid4()),
            "key_id": str(uuid.uuid4()),
            "manifest_version": 1,
            "signer_fingerprint": fp,
            "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
            "signing_nonce": secrets.token_urlsafe(32),
            "signing_timestamp": "2026-11-15T10:00:00.000Z",
        }
        sig_b64 = sign_manifest_py(priv, manifest)

        tampered_manifest = copy.deepcopy(manifest)
        tampered_manifest["signing_context"] = "DOCSIGN_MALICIOUS_CONTEXT_V2"

        pkg = {
            "package_version": 1,
            "signature_format": "DETACHED_JCS_V1",
            "manifest": tampered_manifest,
            "signature_b64": sig_b64,
            "public_key_spki_pem": pem,
        }
        res = client_p5.post(
            "/api/v1/verify/upload",
            files={"file": ("contract.pdf", pdf_bytes, "application/pdf")},
            data={"package_json": json.dumps(pkg)},
        )
        assert res.status_code == 422

    def test_internal_verify_nonexistent_document_returns_404(self, client_p5):
        """Internal verify for non-existent document returns 404."""
        user = register_and_login_user(client_p5, "not_found_doc@cyber.edu")
        res = client_p5.get(
            f"/api/v1/documents/{uuid.uuid4()}/versions/{uuid.uuid4()}/verify",
            headers=user["headers"],
        )
        assert res.status_code == 404

    def test_internal_verify_nonexistent_version_returns_404(self, client_p5):
        """Internal verify for existing doc with non-existent version returns 404."""
        user = register_and_login_user(client_p5, "not_found_ver@cyber.edu")
        pdf_bytes = make_pdf()
        up_res = client_p5.post(
            "/api/v1/documents",
            files={"file": ("doc.pdf", pdf_bytes, "application/pdf")},
            headers=user["headers"],
        )
        doc_id = up_res.json()["document_id"]
        res = client_p5.get(
            f"/api/v1/documents/{doc_id}/versions/{uuid.uuid4()}/verify",
            headers=user["headers"],
        )
        assert res.status_code == 404

