#!/usr/bin/env python3
"""Bounded Python/OpenSSL benchmark, not browser or API performance."""
import base64
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import psutil
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def main():
    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = time.process_time()
    results = {}
    def measure(stage, action):
        start = time.perf_counter()
        value = action()
        results.setdefault(stage, []).append((time.perf_counter() - start) * 1000)
        return value
    for _ in range(3):
        private = measure('rsa3072_keygen', lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072))
        public = private.public_key()
        der = public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        measure('spki_parse', lambda: serialization.load_der_public_key(der))
        measure('spki_sha256', lambda: hashlib.sha256(der).hexdigest())
        salt = os.urandom(16)
        key = measure('pbkdf2_sha256_600000', lambda: PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600000).derive(b'Synthetic-benchmark-passphrase'))
        aes = AESGCM(key)
        raw = private.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        iv, aad = os.urandom(12), b'DOCSIGN synthetic benchmark'
        ciphertext = measure('aes256gcm_encrypt_pkcs8_only', lambda: aes.encrypt(iv, raw, aad))
        restored = measure('aes256gcm_decrypt_pkcs8_only', lambda: aes.decrypt(iv, ciphertext, aad))
        assert restored == raw
        payload = Path('tests/fixtures/pop-v1.json').read_bytes()
        signature = private.sign(payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        measure('rsa_pss_verify', lambda: public.verify(signature, payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()))
    report = dict(runtime=f'Python {platform.python_version()} cryptography/OpenSSL', platform=platform.platform(), machine=platform.machine(), physical_memory_bytes=psutil.virtual_memory().total,
                  method='Three sequential synthetic samples per stage, no network/browser/IndexedDB. AES-only times exclude KDF. Verification uses fixed synthetic fixture bytes; not full HTTP request latency. RSS before/end only; no peak, memory-leak, swap or SLA claims.',
                  rss_before_bytes=rss_before, rss_end_bytes=process.memory_info().rss, peak_rss_bytes=None, peak_rss_status='Not measured', cpu_seconds=time.process_time()-cpu_before,
                  results={stage:dict(samples_ms=samples,mean_ms=statistics.mean(samples),median_ms=statistics.median(samples)) for stage,samples in results.items()})
    Path('docs/phase3-benchmark-python.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__ == '__main__':
    main()
