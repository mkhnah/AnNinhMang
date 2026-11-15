"""Full real WebCrypto -> Share -> Public Verification End-to-End Interop Test."""
import json
import pytest
from tests.test_phase4_interop import bridge
from tests.conftest import client_p5, storage_p5
from tests.test_phase4_signatures import register_and_login_user, upload_and_ready_doc
from backend.app.services.verification_service import _ip_request_history


def test_real_webcrypto_to_share_public_verification(client_p5, bridge):
    """
    Section X.C: End-to-End Interoperability
    1. Node.js WebCrypto generates real RSA-PSS 3072-bit key pair.
    2. Export SPKI PEM, SHA-256 fingerprint, register key with valid PoP.
    3. Upload test PDF and transition to READY_TO_SIGN.
    4. Prepare signing manifest via /prepare-sign.
    5. Real WebCrypto signs RFC 8785 canonical bytes using RSA-PSS saltLength=32, SHA-256.
    6. Submit signature to /api/v1/signatures.
    7. Owner creates public share token via /api/v1/shares.
    8. Anonymous public client requests GET /api/v1/verify/share/{token}.
    9. Assert: status=VERIFIED, all 6 dimensions VALID, correct security headers,
       and zero signature/PDF bytes/private key leakage.
    """
    _ip_request_history.clear()
    auth = register_and_login_user(client_p5, "webcrypto_share@cyber.edu")
    h = auth["headers"]

    # 1. Keygen via real WebCrypto
    public = bridge("keygen")
    assert public["fingerprint"] and public["public_key_pem"]

    # 2. Challenge & Register Key with Proof-of-Possession
    chal_res = client_p5.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": public["fingerprint"], "purpose": "REGISTER_KEY"},
        headers=h,
    )
    assert chal_res.status_code == 201
    challenge = chal_res.json()
    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": challenge["challenge_id"],
        "challenge_nonce": challenge["challenge_nonce"],
        "fingerprint": public["fingerprint"],
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth["user_id"],
    }
    pop_sig = bridge("pop", pop_payload)["signature"]
    reg_res = client_p5.post(
        "/api/v1/keys",
        json={
            "algorithm": "RSA-PSS-3072",
            "public_key_pem": public["public_key_pem"],
            "challenge_id": challenge["challenge_id"],
            "pop_signature_b64": pop_sig,
        },
        headers=h,
    )
    assert reg_res.status_code == 201
    key = reg_res.json()

    # 3. Upload & Ready Document
    doc_id, ver_id, digest, pdf_bytes = upload_and_ready_doc(client_p5, h)

    # 4. Prepare Sign
    prep_res = client_p5.post(
        f"/api/v1/documents/{doc_id}/versions/{ver_id}/prepare-sign",
        json={"key_id": key["id"]},
        headers=h,
    )
    assert prep_res.status_code == 200
    manifest = prep_res.json()["manifest"]

    # 5. Sign with real WebCrypto (RSA-PSS 3072-bit, saltLength=32, SHA-256)
    sig_b64 = bridge("sign", manifest)["signature"]

    # 6. Submit signature
    signed_res = client_p5.post(
        "/api/v1/signatures",
        json={
            "version_id": ver_id,
            "key_id": key["id"],
            "manifest": manifest,
            "signature_b64": sig_b64,
        },
        headers=h,
    )
    assert signed_res.status_code == 201

    # 7. Create Share Token
    share_res = client_p5.post(
        "/api/v1/shares",
        json={
            "version_id": ver_id,
            "expires_in_days": 14,
            "label": "WebCrypto Field Verification",
        },
        headers=h,
    )
    assert share_res.status_code == 201, share_res.text
    share_data = share_res.json()
    share_url = share_data["share_url"]
    token = share_url.split("/")[-1]
    assert len(token) == 43
    assert share_url.endswith(f"/verify/share/{token}")

    # 8. Anonymous public scan (clear cookies and headers)
    client_p5.cookies.clear()
    pub_res = client_p5.get(f"/api/v1/verify/share/{token}")

    # 9. Assertions on verification response and security headers
    assert pub_res.status_code == 200
    assert "no-store" in pub_res.headers.get("Cache-Control", "")
    assert "no-cache" in pub_res.headers.get("Cache-Control", "")
    assert pub_res.headers.get("Referrer-Policy") == "no-referrer"
    assert pub_res.headers.get("X-Content-Type-Options") == "nosniff"

    data = pub_res.json()
    assert data["title"] == "contract.pdf"
    assert data["version_no"] == 1
    assert data["original_filename"] == "contract.pdf"
    assert data["signer_fingerprint"] == public["fingerprint"]

    summary = data["results"]
    assert summary["summary_status"] == "VERIFIED"
    assert summary["evidence_consistency"] == "CONSISTENT"

    dims = summary["results"]
    assert dims["cryptographic_validity"] == "VALID"
    assert dims["document_integrity"] == "UNCHANGED"
    assert dims["key_ownership"] == "VERIFIED_POP"
    assert dims["certificate_trust"] == "SELF_REGISTERED"
    assert dims["key_revocation_status"] == "ACTIVE"
    assert dims["declared_timestamp"] is not None

    # 10. Verify zero PDF leakage, no private keys, no raw signature packages
    raw_text = pub_res.text
    assert "private" not in raw_text.lower()
    assert sig_b64 not in raw_text
    assert "storage_key" not in raw_text
    assert "file_path" not in raw_text
    assert "verification_receipt" not in raw_text  # Unused receipt issuance disabled

    # Owner revokes the actual share; the same anonymous capability is invalidated.
    revoked = client_p5.post(f"/api/v1/shares/{share_data['id']}/revoke", headers=h)
    assert revoked.status_code == 204
    after = client_p5.get(f"/api/v1/verify/share/{token}")
    assert after.status_code == 404
    assert "title" not in after.json()
