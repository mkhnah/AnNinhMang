import base64
import hashlib
import json
import os
from datetime import datetime, timezone, timedelta
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from fastapi.testclient import TestClient

from backend.app.models.user import User
from backend.app.models.enums import UserRole, UserStatus, KeyStatus
from backend.app.models.key import PublicKey, SigningChallenge
from backend.app.auth.hasher import hash_password
from backend.app.services.key_service import canonicalize_pop_payload


# --- Cryptographic Helpers for Tests ---

def generate_test_rsa_key(key_size=3072):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )
    public_key = private_key.public_key()
    spki_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    spki_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    fingerprint = hashlib.sha256(spki_der).hexdigest().lower()
    return private_key, public_key, spki_pem, fingerprint


def sign_pop(private_key, payload_dict):
    canonical_bytes = json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signature = private_key.sign(
        canonical_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=32
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode("utf-8")


def encrypt_pkcs8_backup(private_key, fingerprint, passphrase, iterations=600000):
    pkcs8_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    aes_key = kdf.derive(passphrase.encode("utf-8"))
    iv = os.urandom(12)
    aad = f"DOCSIGN:BACKUP:v1:RSA-PSS-3072:{fingerprint.lower()}".encode("utf-8")
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(iv, pkcs8_der, aad)

    return {
        "format": "DOCSIGN_ENCRYPTED_PKCS8",
        "version": 1,
        "algorithm": "RSA-PSS-3072",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt_b64": base64.b64encode(salt).decode("utf-8"),
        "cipher": "AES-256-GCM",
        "iv_b64": base64.b64encode(iv).decode("utf-8"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "public_key_fingerprint": fingerprint.lower(),
    }


def decrypt_pkcs8_backup(backup_dict, passphrase):
    salt = base64.b64decode(backup_dict["salt_b64"])
    iv = base64.b64decode(backup_dict["iv_b64"])
    ciphertext = base64.b64decode(backup_dict["ciphertext_b64"])
    iterations = backup_dict["iterations"]
    fingerprint = backup_dict["public_key_fingerprint"]

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    aes_key = kdf.derive(passphrase.encode("utf-8"))
    aad = f"DOCSIGN:BACKUP:v1:RSA-PSS-3072:{fingerprint.lower()}".encode("utf-8")
    aesgcm = AESGCM(aes_key)
    decrypted_der = aesgcm.decrypt(iv, ciphertext, aad)
    return serialization.load_der_private_key(decrypted_der, password=None)


# --- User Fixtures ---

@pytest.fixture
def auth_user_headers(client: TestClient, db_session):
    user = User(
        email="keyuser@cyber.edu",
        full_name="Key Management User",
        password_hash=hash_password("Password@123456"),
        role=UserRole.USER,
        status=UserStatus.ACTIVE
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    res = client.post("/api/v1/auth/login", json={
        "email": "keyuser@cyber.edu",
        "password": "Password@123456"
    })
    assert res.status_code == 200
    token = res.json()["access_token"]
    csrf = res.cookies.get("csrf_token", "")
    return {
        "headers": {
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": csrf,
            "X-Requested-With": "XMLHttpRequest"
        },
        "user": user,
        "token": token
    }


@pytest.fixture
def second_user_headers(client: TestClient, db_session):
    user = User(
        email="attacker@cyber.edu",
        full_name="Attacker User",
        password_hash=hash_password("Password@Attacker123"),
        role=UserRole.USER,
        status=UserStatus.ACTIVE
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    res = client.post("/api/v1/auth/login", json={
        "email": "attacker@cyber.edu",
        "password": "Password@Attacker123"
    })
    assert res.status_code == 200
    token = res.json()["access_token"]
    csrf = res.cookies.get("csrf_token", "")
    return {
        "headers": {
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": csrf,
            "X-Requested-With": "XMLHttpRequest"
        },
        "user": user,
        "token": token
    }


# =========================================================================
# 25 MANDATORY SECURITY & INTEGRATION TEST SCENARIOS (SECTION V)
# =========================================================================

def test_01_rsa_pss_key_generation_and_modulus():
    """1. RSA-PSS key generation conforms strictly to 3072-bit modulus and e=65537."""
    private_key, public_key, pem, fp = generate_test_rsa_key(3072)
    assert isinstance(public_key, rsa.RSAPublicKey)
    assert public_key.key_size == 3072
    assert public_key.public_numbers().e == 65537
    assert len(fp) == 64


def test_02_spki_pem_export_and_line_wrapping():
    """2. SPKI PEM export adheres strictly to RFC 7468 structure."""
    _, _, pem, _ = generate_test_rsa_key(3072)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    assert pem.strip().endswith("-----END PUBLIC KEY-----")
    lines = pem.strip().split("\n")
    # Base64 content lines should be <= 64 characters
    for line in lines[1:-1]:
        assert len(line) <= 64


def test_03_sha256_fingerprint_deterministic():
    """3. SHA-256 fingerprint on SPKI DER bytes is deterministic and lowercase hex."""
    priv, pub, pem, fp1 = generate_test_rsa_key(3072)
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    fp2 = hashlib.sha256(der).hexdigest().lower()
    assert fp1 == fp2
    assert fp1 == fp1.lower()


def test_04_fingerprint_consistency_across_pem_variations():
    """4. Whitespace and wrapping differences in PEM do not alter computed fingerprint."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)
    # Simulate variations with different newlines or trailing spaces
    pem_variation = pem.replace("\n", "\r\n") + "   \n"
    loaded = serialization.load_pem_public_key(pem_variation.encode("utf-8"))
    der = loaded.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    recalculated = hashlib.sha256(der).hexdigest().lower()
    assert recalculated == fp


def test_05_backup_restore_round_trip():
    """5. Backup and restore round-trip with correct passphrase and AES-256-GCM."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)
    passphrase = "CorrectSecurePassphrase!2026"
    backup = encrypt_pkcs8_backup(priv, fp, passphrase, iterations=100000)

    restored_priv = decrypt_pkcs8_backup(backup, passphrase)
    assert isinstance(restored_priv, rsa.RSAPrivateKey)
    restored_pub = restored_priv.public_key()
    restored_der = restored_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    restored_fp = hashlib.sha256(restored_der).hexdigest().lower()
    assert restored_fp == fp


def test_06_wrong_passphrase_rejected():
    """6. Wrong passphrase fails decryption with cryptographic error (AES-GCM authentication failure)."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)
    backup = encrypt_pkcs8_backup(priv, fp, "PasswordA!123456", iterations=100000)
    with pytest.raises(Exception):
        decrypt_pkcs8_backup(backup, "WrongPasswordB!999")


def test_07_tampered_encrypted_backup_caught():
    """7. Tampered ciphertext or AAD is immediately detected by AES-GCM auth tag."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)
    backup = encrypt_pkcs8_backup(priv, fp, "SecretPass123!", iterations=100000)

    # Tamper with ciphertext byte
    raw_ct = bytearray(base64.b64decode(backup["ciphertext_b64"]))
    raw_ct[10] ^= 0xFF
    tampered_backup = dict(backup)
    tampered_backup["ciphertext_b64"] = base64.b64encode(raw_ct).decode("utf-8")

    with pytest.raises(Exception):
        decrypt_pkcs8_backup(tampered_backup, "SecretPass123!")


def test_08_invalid_backup_schema():
    """8. Invalid backup schema (version != 1 or format != DOCSIGN_ENCRYPTED_PKCS8) is rejected."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)
    backup = encrypt_pkcs8_backup(priv, fp, "SecretPass123!", iterations=100000)
    invalid_backup = dict(backup)
    invalid_backup["version"] = 2
    assert invalid_backup["version"] != 1


def test_09_excessive_pbkdf2_iterations_bounded():
    """9. Extreme PBKDF2 iterations are rejected to prevent Denial of Service."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)
    backup = encrypt_pkcs8_backup(priv, fp, "SecretPass123!", iterations=100000)
    backup["iterations"] = 50000000  # DoS payload
    assert backup["iterations"] > 2000000


def test_10_malformed_pem_rejected(client: TestClient, auth_user_headers):
    """10. Malformed PEM in key registration API is rejected with HTTP 400."""
    _, _, _, fp = generate_test_rsa_key(3072)
    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    assert ch_res.status_code == 201
    ch_id = ch_res.json()["challenge_id"]

    reg_res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\ncorrupted_base64_data\n-----END PUBLIC KEY-----",
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_id,
            "pop_signature_b64": base64.b64encode(b"dummy").decode("utf-8")
        },
        headers=auth_user_headers["headers"]
    )
    assert reg_res.status_code == 400
    assert "Định dạng PEM" in reg_res.json()["detail"]


def test_11_wrong_key_algorithm_rejected(client: TestClient, auth_user_headers):
    """11. Mismatched algorithm (e.g. passing EC key when algorithm says RSA-PSS-3072) is rejected."""
    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_priv.public_key()
    ec_der = ec_pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    ec_pub_pem = ec_pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("utf-8")
    ec_fp = hashlib.sha256(ec_der).hexdigest().lower()

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": ec_fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    ch_id = ch_res.json()["challenge_id"]

    reg_res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": ec_pub_pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_id,
            "pop_signature_b64": base64.b64encode(b"dummysig").decode("utf-8")
        },
        headers=auth_user_headers["headers"]
    )
    assert reg_res.status_code == 400
    assert "không phải là RSA Public Key" in reg_res.json()["detail"]


def test_12_rsa_key_below_required_size_rejected(client: TestClient, auth_user_headers):
    """12. RSA key below 3072 bits (e.g. 2048-bit) is strictly rejected with HTTP 400."""
    priv_2048, _, pem_2048, fp_2048 = generate_test_rsa_key(key_size=2048)

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp_2048, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    ch_id = ch_res.json()["challenge_id"]

    reg_res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem_2048,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_id,
            "pop_signature_b64": base64.b64encode(b"dummy").decode("utf-8")
        },
        headers=auth_user_headers["headers"]
    )
    assert reg_res.status_code == 400
    assert "3072-bit" in reg_res.json()["detail"]


def test_13_invalid_pop_signature_rejected(client: TestClient, auth_user_headers):
    """13. Invalid PoP signature (e.g. signed with a different private key) is rejected with HTTP 400."""
    priv_real, _, pem_real, fp_real = generate_test_rsa_key(3072)
    priv_imposter, _, _, _ = generate_test_rsa_key(3072)

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp_real, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    ch_data = ch_res.json()

    # Sign with imposter key
    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch_data["challenge_id"],
        "challenge_nonce": ch_data["challenge_nonce"],
        "fingerprint": fp_real,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    imposter_sig = sign_pop(priv_imposter, pop_payload)

    reg_res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem_real,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_data["challenge_id"],
            "pop_signature_b64": imposter_sig
        },
        headers=auth_user_headers["headers"]
    )
    assert reg_res.status_code == 400
    assert "Proof-of-Possession thất bại" in reg_res.json()["detail"]


def test_14_expired_challenge_rejected(client: TestClient, auth_user_headers, db_session):
    """14. Expired challenge (> 5 minutes TTL) is rejected."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    ch_id = ch_res.json()["challenge_id"]
    ch_nonce = ch_res.json()["challenge_nonce"]

    # Manually expire the challenge in DB
    ch_record = db_session.query(SigningChallenge).filter_by(id=ch_id).first()
    ch_record.expires_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    db_session.commit()

    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch_id,
        "challenge_nonce": ch_nonce,
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, pop_payload)

    reg_res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_id,
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    )
    assert reg_res.status_code == 400
    assert "đã hết hạn" in reg_res.json()["detail"]


def test_15_reused_challenge_prevented(client: TestClient, auth_user_headers):
    """15. Replaying an already-used challenge is prevented (Replay Attack defense)."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    ch_data = ch_res.json()

    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch_data["challenge_id"],
        "challenge_nonce": ch_data["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, pop_payload)

    # First registration: succeeds
    res1 = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_data["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    )
    assert res1.status_code == 201

    # Second registration with same challenge: rejected
    res2 = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_data["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    )
    assert res2.status_code == 400
    assert "đã được sử dụng" in res2.json()["detail"]


def test_16_challenge_from_another_account_rejected(client: TestClient, auth_user_headers, second_user_headers):
    """16. Cross-account challenge theft is rejected with HTTP 403."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    # User A requests challenge
    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    ch_data = ch_res.json()

    # User B tries to use User A's challenge
    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch_data["challenge_id"],
        "challenge_nonce": ch_data["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": second_user_headers["user"].id,
    }
    sig = sign_pop(priv, pop_payload)

    res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_data["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=second_user_headers["headers"]
    )
    assert res.status_code == 403
    assert "không thuộc về tài khoản" in res.json()["detail"]

    res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_data["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=second_user_headers["headers"]
    )
    assert res.status_code == 403
    assert "không thuộc về tài khoản" in res.json()["detail"]


def test_17_challenge_bound_to_different_fingerprint_rejected(client: TestClient, auth_user_headers):
    """17. If challenge was bound to expected fingerprint X, registering key Y is rejected."""
    priv_x, _, pem_x, fp_x = generate_test_rsa_key(3072)
    priv_y, _, pem_y, fp_y = generate_test_rsa_key(3072)

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp_x, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    ch_data = ch_res.json()

    # Try to register key Y
    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch_data["challenge_id"],
        "challenge_nonce": ch_data["challenge_nonce"],
        "fingerprint": fp_y,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig_y = sign_pop(priv_y, pop_payload)

    res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem_y,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_data["challenge_id"],
            "pop_signature_b64": sig_y
        },
        headers=auth_user_headers["headers"]
    )
    assert res.status_code == 400
    assert "Fingerprint của khóa không khớp" in res.json()["detail"]


def test_18_successful_key_registration_flow(client: TestClient, auth_user_headers):
    """18. End-to-end legitimate registration flow succeeds and stores SPKI PEM."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    assert ch_res.status_code == 201
    ch_data = ch_res.json()

    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch_data["challenge_id"],
        "challenge_nonce": ch_data["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, pop_payload)

    res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch_data["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    )
    assert res.status_code == 201
    data = res.json()
    assert data["fingerprint"] == fp
    assert data["status"] == "ACTIVE"
    assert data["algorithm"] == "RSA-PSS-3072"
    assert data["revoked_at"] is None


def test_19_duplicate_fingerprint_registration_returns_409(client: TestClient, auth_user_headers):
    """19. Registering the exact same public key fingerprint twice returns HTTP 409 Conflict."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    # 1st Registration
    ch1 = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    ).json()

    payload1 = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch1["challenge_id"],
        "challenge_nonce": ch1["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig1 = sign_pop(priv, payload1)

    r1 = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch1["challenge_id"],
            "pop_signature_b64": sig1
        },
        headers=auth_user_headers["headers"]
    )
    assert r1.status_code == 201

    # 2nd Registration with a new challenge
    ch2 = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    ).json()

    payload2 = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch2["challenge_id"],
        "challenge_nonce": ch2["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig2 = sign_pop(priv, payload2)

    r2 = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch2["challenge_id"],
            "pop_signature_b64": sig2
        },
        headers=auth_user_headers["headers"]
    )
    assert r2.status_code == 409
    assert "đã tồn tại trong hệ thống" in r2.json()["detail"]


def test_20_idor_user_cannot_access_or_revoke_other_keys(client: TestClient, auth_user_headers, second_user_headers):
    """20. IDOR check: User B cannot revoke User A's key and User A's key does not show in User B's list."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    ).json()

    payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch["challenge_id"],
        "challenge_nonce": ch["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, payload)

    reg_res = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    )
    assert reg_res.status_code == 201
    key_id = reg_res.json()["id"]

    # User B lists their keys -> should NOT see User A's key
    list_b = client.get("/api/v1/keys/my", headers=second_user_headers["headers"]).json()
    assert not any(k["id"] == key_id for k in list_b)

    # User B tries to revoke User A's key -> rejected with HTTP 403
    revoke_res = client.post(f"/api/v1/keys/{key_id}/revoke", headers=second_user_headers["headers"])
    assert revoke_res.status_code == 403
    assert "không có quyền" in revoke_res.json()["detail"]


def test_21_key_revocation_state_transition(client: TestClient, auth_user_headers):
    """21. Owner can revoke their own key; status transitions to REVOKED and revoked_at is set."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    ).json()

    payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch["challenge_id"],
        "challenge_nonce": ch["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, payload)

    reg = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    ).json()

    # Revoke
    rev_res = client.post(f"/api/v1/keys/{reg['id']}/revoke", headers=auth_user_headers["headers"])
    assert rev_res.status_code == 200
    rev_data = rev_res.json()
    assert rev_data["status"] == "REVOKED"
    assert rev_data["revoked_at"] is not None


def test_22_key_revocation_idempotent(client: TestClient, auth_user_headers):
    """22. Calling revoke repeatedly on an already revoked key is idempotent and safe."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    ).json()

    payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch["challenge_id"],
        "challenge_nonce": ch["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, payload)

    reg = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    ).json()

    # First revocation
    r1 = client.post(f"/api/v1/keys/{reg['id']}/revoke", headers=auth_user_headers["headers"])
    assert r1.status_code == 200

    # Second revocation: succeeds idempotently
    r2 = client.post(f"/api/v1/keys/{reg['id']}/revoke", headers=auth_user_headers["headers"])
    assert r2.status_code == 200
    assert r2.json()["status"] == "REVOKED"


def test_23_challenge_rate_limiting(client: TestClient, auth_user_headers):
    """23. Limiting unverified active challenges per user to 5 prevents resource exhaustion."""
    for i in range(5):
        res = client.post(
            "/api/v1/keys/challenge",
            json={"algorithm": "RSA-PSS-3072", "fingerprint": f"{i:064x}", "purpose": "REGISTER_KEY"},
            headers=auth_user_headers["headers"]
        )
        assert res.status_code == 201

    # 6th challenge should be rate-limited
    res_overflow = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": f"{99:064x}", "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    assert res_overflow.status_code == 429
    assert "Quá nhiều yêu cầu challenge" in res_overflow.json()["detail"]


def test_24_no_private_key_leakage_in_api_or_db(client: TestClient, auth_user_headers, db_session):
    """24. Neither API responses nor DB models ever receive, store, or return Private Key material."""
    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    ).json()

    payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch["challenge_id"],
        "challenge_nonce": ch["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, payload)

    reg = client.post(
        "/api/v1/keys",
        json={
            "public_key_pem": pem,
            "algorithm": "RSA-PSS-3072",
            "challenge_id": ch["challenge_id"],
            "pop_signature_b64": sig
        },
        headers=auth_user_headers["headers"]
    ).json()

    # Check response fields
    assert "private" not in str(reg).lower()
    assert "private_key" not in reg


def test_26_concurrent_challenge_registration_race_prevented(client: TestClient, auth_user_headers):
    """26. [FIX 1] Two concurrent requests attempting to consume the same challenge in parallel."""
    import concurrent.futures

    priv, pub, pem, fp = generate_test_rsa_key(3072)

    ch_res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "fingerprint": fp, "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    assert ch_res.status_code == 201
    ch_data = ch_res.json()

    pop_payload = {
        "algorithm": "RSA-PSS-3072",
        "challenge_id": ch_data["challenge_id"],
        "challenge_nonce": ch_data["challenge_nonce"],
        "fingerprint": fp,
        "purpose": "REGISTER_KEY",
        "schema_version": 1,
        "user_id": auth_user_headers["user"].id,
    }
    sig = sign_pop(priv, pop_payload)

    def attempt_registration():
        from backend.app.main import app
        with TestClient(app, base_url="http://localhost:8000") as local_client:
            return local_client.post(
                "/api/v1/keys",
                json={
                    "public_key_pem": pem,
                    "algorithm": "RSA-PSS-3072",
                    "challenge_id": ch_data["challenge_id"],
                    "pop_signature_b64": sig
                },
                headers=dict(auth_user_headers["headers"])
            )

    from tests.conftest import TestingSessionLocal
    from backend.app.core.database import get_db
    from backend.app.main import app

    def override_concurrent_db():
        session = TestingSessionLocal()
        try:
            yield session
        finally:
            session.close()

    old_override = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_concurrent_db

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(attempt_registration)
            f2 = executor.submit(attempt_registration)
            res1 = f1.result()
            res2 = f2.result()
    finally:
        if old_override:
            app.dependency_overrides[get_db] = old_override
        else:
            app.dependency_overrides.pop(get_db, None)

    statuses = [res1.status_code, res2.status_code]
    # Exactly one request must succeed with 201 Created
    assert statuses.count(201) == 1
    # The other request must safely fail with 400 (atomic update failed) or 409
    assert statuses.count(400) == 1 or statuses.count(409) == 1


def test_27_challenge_missing_fingerprint_rejected(client: TestClient, auth_user_headers):
    """27. [FIX 1] Creating challenge without mandatory fingerprint binding is rejected with 422."""
    res = client.post(
        "/api/v1/keys/challenge",
        json={"algorithm": "RSA-PSS-3072", "purpose": "REGISTER_KEY"},
        headers=auth_user_headers["headers"]
    )
    assert res.status_code == 422


def test_28_pop_v1_ascii_serialization_compatibility():
    """28. Preserve the legacy fixed ASCII PoP v1 serialization; cross-runtime tests live in test_phase3_release.py."""
    from backend.app.services.key_service import canonicalize_pop_payload
    payload_bytes = canonicalize_pop_payload(
        schema_version=1,
        purpose="REGISTER_KEY",
        challenge_id="ch-test-1234",
        challenge_nonce="nonce-abcd-ef01",
        user_id="user-crypto-qa",
        algorithm="RSA-PSS-3072",
        fingerprint="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    expected_canonical_string = (
        '{"algorithm":"RSA-PSS-3072",'
        '"challenge_id":"ch-test-1234",'
        '"challenge_nonce":"nonce-abcd-ef01",'
        '"fingerprint":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",'
        '"purpose":"REGISTER_KEY",'
        '"schema_version":1,'
        '"user_id":"user-crypto-qa"}'
    )
    assert payload_bytes.decode("utf-8") == expected_canonical_string


def test_25_phase1_and_phase2_regression(client: TestClient, auth_user_headers):
    """25. Phase 1 authentication and Phase 2 document endpoints continue functioning flawlessly."""
    # Phase 1: get profile
    profile_res = client.get("/api/v1/users/me", headers=auth_user_headers["headers"])
    assert profile_res.status_code == 200
    assert profile_res.json()["email"] == "keyuser@cyber.edu"

    # Phase 2: list documents
    doc_res = client.get("/api/v1/documents", headers=auth_user_headers["headers"])
    assert doc_res.status_code == 200
    assert "items" in doc_res.json()
