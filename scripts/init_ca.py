"""Initialize a private Root CA in a new directory without overwriting evidence."""
import argparse
from datetime import datetime, timedelta, timezone
import getpass
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def initialize_ca(directory, password, name="DocSign Private CA"):
    if len(password) < 16:
        raise ValueError("Use a password of at least 16 bytes")
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=1825))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .sign(key, hashes.SHA256()))
    directory = Path(directory).expanduser().absolute()
    directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    outputs = {
        "ca-key.pem": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.BestAvailableEncryption(password)),
        "ca-cert.pem": cert.public_bytes(serialization.Encoding.PEM),
    }
    created = []
    try:
        for filename, content in outputs.items():
            path = directory / filename
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for path in created:
            path.unlink()
        directory.rmdir()
        raise
    return cert.fingerprint(hashes.SHA256()).hex()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--name", default="DocSign Private CA")
    args = parser.parse_args()
    password = getpass.getpass("CA password (at least 16 characters): ")
    if password != getpass.getpass("Confirm CA password: "):
        parser.exit(1, "Password confirmation differs\n")
    try:
        fingerprint = initialize_ca(args.output_dir, password.encode(), args.name)
    except Exception:
        parser.exit(1, "CA initialization failed; check output path and permissions\n")
    print("CA_TRUSTED_ROOT_SHA256=" + fingerprint)
    print("CA created. Configure the certificate/key paths and one password source.")


if __name__ == "__main__":
    main()
