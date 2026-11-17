"""DocSign X.509 profile v1: a pinned RSA root directly issues account leaves."""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hmac
import os
from pathlib import Path
import stat
from urllib.parse import quote
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID, ExtensionOID
from fastapi import HTTPException

from backend.app.core.config import settings


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA256()).hex()


def public_der(key):
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def subject_uri(user_id):
    try:
        return "urn:uuid:" + str(UUID(user_id))
    except ValueError:
        # Imported legacy accounts can have opaque IDs rather than UUIDs.
        return "https://docsign.invalid/accounts/" + quote(user_id, safe="")


def read_private_file(path, max_bytes=65536):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or Path(path).is_symlink():
            raise ValueError("Secret must be a regular file")
        if os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.geteuid()):
            raise ValueError("Secret requires private owner permissions")
        content = stream.read(max_bytes + 1)
        if len(content) > max_bytes:
            raise ValueError("Secret file exceeds size limit")
        return content


def validate_root(cert, pin, now=None):
    now = now or datetime.now(timezone.utc)
    if not hmac.compare_digest(fingerprint(cert), pin.lower()):
        raise ValueError("Untrusted CA fingerprint")
    public = cert.public_key()
    if not isinstance(public, rsa.RSAPublicKey) or public.key_size != 4096 or public.public_numbers().e != 65537:
        raise ValueError("Unsupported CA key")
    if cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
        raise ValueError("Unsupported CA signature")
    if cert.subject != cert.issuer:
        raise ValueError("Expected direct root")
    cert.verify_directly_issued_by(cert)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("CA validity failure")
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    if not basic.critical or not basic.value.ca or basic.value.path_length != 0:
        raise ValueError("CA constraints failure")
    if not usage.critical or not usage.value.key_cert_sign or not usage.value.crl_sign:
        raise ValueError("CA key usage failure")
    allowed = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
               ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    if any(extension.oid not in allowed for extension in cert.extensions):
        raise ValueError("Unsupported CA extension")
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    if ski != x509.SubjectKeyIdentifier.from_public_key(public) or aki != x509.AuthorityKeyIdentifier.from_issuer_public_key(public):
        raise ValueError("CA key identifier mismatch")


@dataclass(frozen=True)
class LoadedCA:
    certificate: x509.Certificate
    private_key: rsa.RSAPrivateKey = field(repr=False)

    @property
    def fingerprint(self):
        return fingerprint(self.certificate)


def load_ca():
    if not settings.PKI_ENABLED:
        raise HTTPException(503, "PKI_DISABLED")
    try:
        if bool(settings.CA_PRIVATE_KEY_PASSWORD_FILE) == bool(settings.CA_PRIVATE_KEY_PASSWORD):
            raise ValueError("Configure one password source")
        password = (read_private_file(settings.CA_PRIVATE_KEY_PASSWORD_FILE).rstrip(b"\r\n")
                    if settings.CA_PRIVATE_KEY_PASSWORD_FILE
                    else settings.CA_PRIVATE_KEY_PASSWORD.get_secret_value().encode())
        if len(password) < 16:
            raise ValueError("CA password must have at least 16 bytes")
        key = serialization.load_pem_private_key(read_private_file(settings.CA_PRIVATE_KEY_PATH), password=password)
        with open(settings.CA_CERTIFICATE_PATH, "rb") as stream:
            pem = stream.read(65537)
        if len(pem) > 65536:
            raise ValueError("CA certificate exceeds limit")
        certs = x509.load_pem_x509_certificates(pem)
        if len(certs) != 1:
            raise ValueError("Configure one root certificate")
        cert = certs[0]
        validate_root(cert, settings.CA_TRUSTED_ROOT_SHA256)
        if not isinstance(key, rsa.RSAPrivateKey) or public_der(key.public_key()) != public_der(cert.public_key()):
            raise ValueError("CA key mismatch")
        return LoadedCA(cert, key)
    except Exception:
        raise HTTPException(503, "PKI_CA_CONFIGURATION_INVALID") from None


def issue_leaf(ca, user_id, public_key, common_name=None):
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 3072 or public_key.public_numbers().e != 65537:
        raise ValueError("Expected RSA 3072/e65537")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    validate_root(ca.certificate, settings.CA_TRUSTED_ROOT_SHA256, now)
    expires = min(now + timedelta(days=settings.CA_USER_CERT_VALIDITY_DAYS), ca.certificate.not_valid_after_utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name or f"DocSign account {user_id}")])
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(ca.certificate.subject)
            .public_key(public_key).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(expires)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(subject_uri(user_id))]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.certificate.public_key()), critical=False)
            .sign(ca.private_key, hashes.SHA256()))


def validate_leaf(cert, root, pin, user_id, public_key, now=None):
    now = now or datetime.now(timezone.utc)
    validate_root(root, pin, now)
    cert.verify_directly_issued_by(root)
    if cert.signature_algorithm_oid != SignatureAlgorithmOID.RSA_WITH_SHA256:
        raise ValueError("Unsupported certificate signature")
    if not root.not_valid_before_utc <= cert.not_valid_before_utc < cert.not_valid_after_utc <= root.not_valid_after_utc:
        raise ValueError("Invalid certificate lifetime")
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ValueError("Certificate validity failure")
    basic = cert.extensions.get_extension_for_class(x509.BasicConstraints)
    usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
    if not basic.critical or basic.value.ca or not usage.critical or not usage.value.digital_signature:
        raise ValueError("Certificate constraints failure")
    if any((usage.value.key_cert_sign, usage.value.crl_sign, usage.value.key_encipherment,
            usage.value.data_encipherment, usage.value.key_agreement, usage.value.content_commitment)):
        raise ValueError("Unexpected key usage")
    allowed = {ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
               ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER}
    if any(extension.oid not in allowed for extension in cert.extensions):
        raise ValueError("Unsupported certificate extension")
    uris = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    if list(uris) != [x509.UniformResourceIdentifier(subject_uri(user_id))]:
        raise ValueError("Certificate subject mismatch")
    if public_der(cert.public_key()) != public_der(public_key):
        raise ValueError("Certificate key mismatch")
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 3072 or public_key.public_numbers().e != 65537:
        raise ValueError("Unsupported leaf key")
    ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    aki = cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value
    if ski != x509.SubjectKeyIdentifier.from_public_key(public_key) or aki != x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()):
        raise ValueError("Certificate key identifier mismatch")
