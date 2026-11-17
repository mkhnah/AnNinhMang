"""Isolated local PKI demo server; never opens the project database or production CA."""
import os
from pathlib import Path
import secrets
import sys
import tempfile
import argparse

repository = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repository))
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--resume', help='Existing QA workspace printed by a previous run')
args = parser.parse_args()
root = Path(args.resume).resolve() if args.resume else Path(tempfile.mkdtemp(prefix='docsign-pki-qa-', dir='/tmp'))
if root.parent != Path('/tmp') or not root.name.startswith('docsign-pki-qa-'):
    raise ValueError('Expected a /tmp/docsign-pki-qa-* workspace')
from scripts.init_ca import initialize_ca
password = secrets.token_urlsafe(48).encode()
secret = root / 'ca-password'
if args.resume:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    pin = x509.load_pem_x509_certificate((root / 'ca/ca-cert.pem').read_bytes()).fingerprint(hashes.SHA256()).hex()
else:
    pin = initialize_ca(root / 'ca', password, 'DocSign QA CA')
    secret.write_bytes(password)
    secret.chmod(0o600)
os.environ.update(DATABASE_URL=f'sqlite:///{root}/qa.db', PKI_ENABLED='true', DEBUG='false',
    SECRET_KEY=secrets.token_urlsafe(48), JWT_SECRET_KEY=secrets.token_urlsafe(48),
    CA_PRIVATE_KEY_PATH=str(root / 'ca/ca-key.pem'), CA_CERTIFICATE_PATH=str(root / 'ca/ca-cert.pem'),
    CA_PRIVATE_KEY_PASSWORD_FILE=str(secret), CA_PRIVATE_KEY_PASSWORD='', CA_TRUSTED_ROOT_SHA256=pin,
    CA_ADDITIONAL_TRUSTED_ROOT_SHA256='', LOCAL_STORAGE_PATH=str(repository / 'data/tmp/pki-qa' / root.name / 'storage'),
    CORS_ORIGINS='http://localhost:5173', PUBLIC_APP_BASE_URL='http://localhost:5173', COOKIE_SECURE='false')
from backend.app.main import app
from backend.app.core.database import Base, engine, SessionLocal
from backend.app.models.user import User
from backend.app.models.enums import UserRole, UserStatus
from backend.app.auth.hasher import hash_password
Base.metadata.create_all(engine)
with SessionLocal() as db:
    for email, role in [('ca-qa-owner@cyber.edu', UserRole.USER), ('ca-qa-admin@cyber.edu', UserRole.ADMIN)]:
        from sqlalchemy import select
        if db.scalar(select(User.id).where(User.email == email)) is None:
            db.add(User(email=email, full_name='CA QA ' + role.value, password_hash=hash_password('QaDemo@2026!'), role=role, status=UserStatus.ACTIVE))
    db.commit()
fixtures = repository / 'data/tmp/pki-qa'
fixtures.mkdir(parents=True, exist_ok=True)
from tests.phase2.conftest import make_pdf
(fixtures / 'sample.pdf').write_bytes(make_pdf())
print(f'QA workspace: {root}; synthetic accounts ca-qa-owner@cyber.edu / ca-qa-admin@cyber.edu; password QaDemo@2026!', flush=True)
import uvicorn
uvicorn.run(app, host='127.0.0.1', port=8000, log_level='warning', access_log=False)
