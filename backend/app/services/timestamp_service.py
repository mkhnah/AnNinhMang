"""RFC 3161 timestamps over signature bytes; trust comes only from configured pins."""
import base64
import hashlib
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

from asn1crypto import cms, tsp
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtendedKeyUsageOID
from fastapi import HTTPException

from backend.app.core.config import settings
from backend.app.crypto.certificates import read_private_file

MAX_TOKEN_BYTES = 65536


def _run(args, *, env=None):
    result = subprocess.run([settings.TSA_OPENSSL_BINARY, *args], capture_output=True,
        timeout=settings.TSA_TIMEOUT_SECONDS, check=False, env=env)
    if result.returncode:
        raise ValueError('TSA OpenSSL operation failed: '+result.stderr.decode(errors='replace')[-1000:])
    return result.stdout


def _decode(value):
    raw = base64.b64decode(value, validate=True)
    if not raw or len(raw) > MAX_TOKEN_BYTES or base64.b64encode(raw).decode() != value:
        raise ValueError('Invalid timestamp token encoding/size')
    return raw


def _root(db=None):
    raw = Path(settings.TSA_CA_CERTIFICATE_PATH).read_bytes()
    if len(raw) > 16384:
        raise ValueError('TSA root too large')
    cert = x509.load_pem_x509_certificate(raw)
    if cert.fingerprint(hashes.SHA256()).hex() != settings.TSA_ROOT_SHA256.lower():
        raise ValueError('TSA root is not pinned')
    if db is not None:
        from sqlalchemy import select
        from backend.app.models.certificate import CertificateAuthority
        record = db.scalar(select(CertificateAuthority).where(CertificateAuthority.fingerprint == settings.TSA_ROOT_SHA256.lower()))
        if record is not None and (record.trust_status != 'TRUSTED' or record.compromised_at):
            raise ValueError('TSA issuer is no longer trusted')
    return raw


def verify_timestamp(token_b64, signature_b64, db=None):
    """Verify CMS signature, ESS signer binding, chain, EKU, imprint and signed time."""
    token = _decode(token_b64)
    content = cms.ContentInfo.load(token, strict=True)
    if content.dump() != token or content['content_type'].native != 'signed_data':
        raise ValueError('Expected DER SignedData')
    signed = content['content']
    if signed['encap_content_info']['content_type'].native != 'tst_info' or len(signed['signer_infos']) != 1:
        raise ValueError('Expected one TSA signer and TSTInfo')
    info = signed['encap_content_info']['content'].parsed
    imprint = info['message_imprint']
    signature = base64.b64decode(signature_b64, validate=True)
    if (imprint['hash_algorithm']['algorithm'].native != 'sha256'
            or imprint['hashed_message'].native != hashlib.sha256(signature).digest()):
        raise ValueError('Timestamp belongs to a different signature')
    when = info['gen_time'].native
    if when > datetime.now(timezone.utc) + timedelta(seconds=300):
        raise ValueError('Timestamp is in the future')
    signer = signed['signer_infos'][0]
    if signer['digest_algorithm']['algorithm'].native not in {'sha256', 'sha384', 'sha512'}:
        raise ValueError('Weak TSA digest')
    sid = signer['sid']
    if sid.name != 'issuer_and_serial_number':
        raise ValueError('Unsupported TSA signer identifier')
    matches = [item.chosen for item in signed['certificates'] if item.name == 'certificate'
        and item.chosen.serial_number == sid.chosen['serial_number'].native
        and item.chosen.issuer.dump() == sid.chosen['issuer'].dump()]
    if len(matches) != 1:
        raise ValueError('Missing/ambiguous TSA certificate')
    cert = x509.load_der_x509_certificate(matches[0].dump())
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    if fingerprint not in {pin.strip().lower() for pin in settings.TSA_SIGNER_SHA256.split(',') if pin.strip()}:
        raise ValueError('Untrusted TSA signer')
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    if not eku.critical or list(eku.value) != [ExtendedKeyUsageOID.TIME_STAMPING]:
        raise ValueError('Expected exclusive critical timeStamping EKU')
    if not cert.not_valid_before_utc <= when < cert.not_valid_after_utc:
        raise ValueError('TSA certificate was not valid at token time')
    root = _root(db)
    # Direct issuance by this exact pinned root prevents fallback to system roots.
    cert.verify_directly_issued_by(x509.load_pem_x509_certificate(root))
    with tempfile.TemporaryDirectory(prefix='tsa-verify-') as folder:
        path = Path(folder)
        (path / 'token.der').write_bytes(token)
        (path / 'root.pem').write_bytes(root)
        _run(['ts', '-verify', '-token_in', '-in', str(path / 'token.der'),
            '-digest', hashlib.sha256(signature).hexdigest(), '-CAfile', str(path / 'root.pem'),
            '-attime', str(int(when.timestamp()))])
    return {'time': when, 'authority': cert.subject.rfc4514_string(), 'fingerprint': fingerprint,
        'serial': str(info['serial_number'].native), 'scope': 'DOCSIGN_PRIVATE_TSA'}


def issue_timestamp(signature_b64, db=None):
    if not settings.TSA_ENABLED:
        return None
    try:
        signature = base64.b64decode(signature_b64, validate=True)
        root = _root(db)
        password = read_private_file(settings.TSA_PRIVATE_KEY_PASSWORD_FILE).decode().strip()
        # The runtime reads only the dedicated TSA key, never the CA private key.
        key = read_private_file(settings.TSA_PRIVATE_KEY_PATH)
        cert = Path(settings.TSA_CERTIFICATE_PATH).read_bytes()
        with tempfile.TemporaryDirectory(prefix='tsa-issue-') as folder:
            path = Path(folder)
            for name, value in [('key.pem',key), ('cert.pem',cert), ('root.pem',root)]:
                target = path / name
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(descriptor, 'wb') as stream:
                    stream.write(value)
            # A random 159-bit serial avoids shared serial files and cross-worker races.
            (path / 'serial').write_text(format(secrets.randbits(159) or 1, 'X'))
            (path / 'request.der').write_bytes(_run(['ts','-query','-digest',hashlib.sha256(signature).hexdigest(),'-sha256','-cert']))
            config = '\n'.join(['[tsa]', 'default_tsa = signer', '[signer]',
                'serial = ' + str(path / 'serial'), 'signer_cert = ' + str(path / 'cert.pem'),
                'certs = ' + str(path / 'root.pem'), 'signer_key = ' + str(path / 'key.pem'),
                'signer_digest = sha256', 'default_policy = 1.3.6.1.4.1.55555.1.1',
                'digests = sha256', 'ordering = no', 'tsa_name = yes',
                'ess_cert_id_chain = no', 'ess_cert_id_alg = sha256'])
            (path / 'tsa.cnf').write_text(config)
            env = {**os.environ, 'DOCSIGN_TSA_PASSWORD':password}
            response = _run(['ts','-reply','-config',str(path / 'tsa.cnf'),'-queryfile',str(path / 'request.der'),
                '-passin','env:DOCSIGN_TSA_PASSWORD'], env=env)
            if len(response) > MAX_TOKEN_BYTES:
                raise ValueError('TSA response too large')
            parsed = tsp.TimeStampResp.load(response, strict=True)
            if parsed['status']['status'].native not in {'granted', 'granted_with_mods'}:
                raise ValueError('TSA rejected request')
            request = tsp.TimeStampReq.load((path / 'request.der').read_bytes(), strict=True)
            info = parsed['time_stamp_token']['content']['encap_content_info']['content'].parsed
            if info['nonce'].native != request['nonce'].native:
                raise ValueError('TSA nonce mismatch')
            token_b64 = base64.b64encode(parsed['time_stamp_token'].dump()).decode()
        verify_timestamp(token_b64, signature_b64, db)
        return token_b64
    except Exception as error:
        raise HTTPException(503, 'TSA_UNAVAILABLE: Không lấy được dấu thời gian hợp lệ; chữ ký chưa được lưu. Vui lòng thử lại.') from error
