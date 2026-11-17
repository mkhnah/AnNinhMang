"""Issue a dedicated internal RFC 3161 TSA signer from the configured private CA."""
import argparse
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import secrets
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from backend.app.core.config import settings
from backend.app.crypto.certificates import load_ca


def initialize_tsa(directory):
    ca = load_ca()
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cert = (x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DocSign Internal TSA')]))
        .issuer_name(ca.certificate.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(max(ca.certificate.not_valid_before_utc, now-timedelta(minutes=1)))
        .not_valid_after(min(ca.certificate.not_valid_after_utc, now+timedelta(days=365)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.private_key.public_key()), critical=False)
        .sign(ca.private_key, hashes.SHA256()))
    directory = Path(directory).expanduser().resolve()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    password = secrets.token_urlsafe(48).encode()
    for name, value in {
        'tsa-key.pem': key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password)),
        'tsa-cert.pem': cert.public_bytes(serialization.Encoding.PEM),
        'tsa-password': password,
    }.items():
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(value)
    return {'TSA_ENABLED':'true', 'TSA_CERTIFICATE_PATH':str(directory/'tsa-cert.pem'),
        'TSA_PRIVATE_KEY_PATH':str(directory/'tsa-key.pem'), 'TSA_PRIVATE_KEY_PASSWORD_FILE':str(directory/'tsa-password'),
        'TSA_CA_CERTIFICATE_PATH':str(Path(settings.CA_CERTIFICATE_PATH).resolve()),
        'TSA_ROOT_SHA256':ca.fingerprint, 'TSA_SIGNER_SHA256':cert.fingerprint(hashes.SHA256()).hex()}


def configure_env(path, values):
    lines = Path(path).read_text(encoding='utf-8').splitlines()
    remaining = dict(values)
    for index, line in enumerate(lines):
        name = line.split('=',1)[0].strip()
        if name in values:
            lines[index] = name + '=' + values[name]
            remaining.pop(name, None)
    lines.extend(name+'='+value for name,value in remaining.items())
    Path(path).write_text('\n'.join(lines)+'\n', encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True)
    parser.add_argument('--configure-env', help='Update this .env after a successful TSA self-test')
    args = parser.parse_args()
    values = initialize_tsa(args.output_dir)
    for name, value in values.items():
        setattr(settings, name, value == 'true' if name == 'TSA_ENABLED' else value)
    from backend.app.services.timestamp_service import issue_timestamp, verify_timestamp
    import base64
    signature = base64.b64encode(secrets.token_bytes(384)).decode()
    token = issue_timestamp(signature)
    proof = verify_timestamp(token, signature)
    if args.configure_env:
        configure_env(args.configure_env, values)
    else:
        for name,value in values.items():
            print(name+'='+value)
    print('RFC 3161 TSA self-test PASS; trust scope DOCSIGN_PRIVATE_TSA; signer '+proof['fingerprint'])
