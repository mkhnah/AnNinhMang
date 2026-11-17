"""Check restoration from an isolated encrypted CA key/certificate copy without issuing a certificate."""
import os
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.app.core.config import settings
from backend.app.crypto.certificates import load_ca, read_private_file


def main():
    original = load_ca()
    key_path, cert_path = settings.CA_PRIVATE_KEY_PATH, settings.CA_CERTIFICATE_PATH
    try:
        with tempfile.TemporaryDirectory(prefix='docsign-ca-recovery-', dir='/tmp') as directory:
            root = Path(directory)
            for name, content in [('ca-key.pem',read_private_file(key_path)), ('ca-cert.pem',Path(cert_path).read_bytes())]:
                descriptor = os.open(root / name,os.O_WRONLY | os.O_CREAT | os.O_EXCL,0o600)
                with os.fdopen(descriptor,'wb') as stream:
                    stream.write(content)
            settings.CA_PRIVATE_KEY_PATH = str(root / 'ca-key.pem')
            settings.CA_CERTIFICATE_PATH = str(root / 'ca-cert.pem')
            restored = load_ca()
            if restored.fingerprint != original.fingerprint:
                raise RuntimeError('Restored CA pin mismatch')
            print('Encrypted CA key recovery check PASS; root SHA-256: ' + restored.fingerprint)
    finally:
        settings.CA_PRIVATE_KEY_PATH,settings.CA_CERTIFICATE_PATH = key_path,cert_path


if __name__ == '__main__':
    main()
