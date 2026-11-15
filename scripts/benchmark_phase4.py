#!/usr/bin/env python3
"""
Phase 4 Benchmark: RFC 8785 JCS, RSA-PSS 3072-bit Signing & Verification,
Streaming PDF SHA-256 hashing, and memory footprint on MacBook Apple Silicon ARM64 8GB RAM.
"""
import base64
import hashlib
import io
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

from backend.app.crypto.jcs import canonicalize_jcs, compute_manifest_sha256


def main():
    process = psutil.Process()
    rss_before = process.memory_info().rss
    cpu_before = time.process_time()

    results = {}

    def measure(stage, action):
        start = time.perf_counter()
        val = action()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        results.setdefault(stage, []).append(elapsed_ms)
        return val

    # Test keypair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    public_key = private_key.public_key()

    manifest_template = {
        "manifest_version": 1,
        "document_version_id": "7f8b86d6-0562-4318-9719-74d320295874",
        "document_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "key_id": "19bfae79-5095-4682-8959-19ffcf6fa505",
        "signer_fingerprint": "8cf55227bf317c24f6050b1d3d63b92cbddf6a8e83b482bcf0ebca1c88820cfb",
        "algorithm": "RSA-PSS-3072",
        "signing_nonce": "e_zL7Qc7t3uX6G9yD4vN8mK2pL5wR1tY0oP9aB3cV8s",
        "signing_timestamp": "2026-11-15T00:00:00.000Z",
        "signing_context": "DOCSIGN_DOCUMENT_SIGNATURE_V1",
    }

    # Synthetic PDF streams
    synthetic_1mb = b"%PDF-1.4\n" + (b"0" * (1024 * 1024 - 15)) + b"\n%%EOF"
    synthetic_5mb = b"%PDF-1.4\n" + (b"0" * (5 * 1024 * 1024 - 15)) + b"\n%%EOF"

    NUM_ROUNDS = 10

    for _ in range(NUM_ROUNDS):
        # 1. RFC 8785 JCS Canonicalization
        canonical_bytes = measure(
            "jcs_canonicalize_manifest",
            lambda: canonicalize_jcs(manifest_template),
        )

        # 2. Manifest SHA-256 Digest
        manifest_digest = measure(
            "manifest_sha256",
            lambda: compute_manifest_sha256(manifest_template),
        )

        # 3. Streaming PDF SHA-256 (1MB)
        def stream_hash_1mb():
            stream = io.BytesIO(synthetic_1mb)
            h = hashlib.sha256()
            while chunk := stream.read(65536):
                h.update(chunk)
            return h.hexdigest()

        measure("pdf_sha256_streaming_1mb", stream_hash_1mb)

        # 4. Streaming PDF SHA-256 (5MB)
        def stream_hash_5mb():
            stream = io.BytesIO(synthetic_5mb)
            h = hashlib.sha256()
            while chunk := stream.read(65536):
                h.update(chunk)
            return h.hexdigest()

        measure("pdf_sha256_streaming_5mb", stream_hash_5mb)

        # 5. RSA-PSS 3072-bit Sign Manifest
        def rsa_pss_sign():
            return private_key.sign(
                canonical_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )

        signature_raw = measure("rsa_pss_3072_sign", rsa_pss_sign)

        # 6. RSA-PSS 3072-bit Verify Manifest
        def rsa_pss_verify():
            public_key.verify(
                signature_raw,
                canonical_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
            return True

        measure("rsa_pss_3072_verify", rsa_pss_verify)

    rss_end = process.memory_info().rss
    cpu_duration = time.process_time() - cpu_before

    summary_stats = {}
    for stage, samples in results.items():
        summary_stats[stage] = {
            "samples_ms": [round(s, 4) for s in samples],
            "mean_ms": round(statistics.mean(samples), 4),
            "median_ms": round(statistics.median(samples), 4),
            "stdev_ms": round(statistics.stdev(samples), 4) if len(samples) > 1 else 0.0,
            "min_ms": round(min(samples), 4),
            "max_ms": round(max(samples), 4),
        }

    report = {
        "title": "DocSign Phase 4 Performance Benchmark",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "runtime": f"Python {platform.python_version()} (macOS {platform.mac_ver()[0]} {platform.machine()})",
        "cpu_arch": platform.machine(),
        "total_physical_ram_mb": round(psutil.virtual_memory().total / (1024 * 1024), 2),
        "rss_before_mb": round(rss_before / (1024 * 1024), 2),
        "rss_end_mb": round(rss_end / (1024 * 1024), 2),
        "rss_delta_mb": round((rss_end - rss_before) / (1024 * 1024), 2),
        "cpu_time_seconds": round(cpu_duration, 4),
        "num_iterations": NUM_ROUNDS,
        "results": summary_stats,
    }

    out_file = Path("docs/phase4-benchmark.json")
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    print("\n" + "=" * 65)
    print("PHASE 4 CRYPTOGRAPHIC & STREAMING PERFORMANCE BENCHMARK")
    print("=" * 65)
    print(f"Platform: {report['runtime']} | Architecture: {report['cpu_arch']}")
    print(f"Physical RAM: {report['total_physical_ram_mb']} MB | Process RSS: {report['rss_end_mb']} MB (Delta: {report['rss_delta_mb']} MB)")
    print("-" * 65)
    print(f"{'Operation':<32} | {'Mean (ms)':<10} | {'Median (ms)':<10} | {'Min (ms)':<10}")
    print("-" * 65)
    for op, data in summary_stats.items():
        print(f"{op:<32} | {data['mean_ms']:<10.3f} | {data['median_ms']:<10.3f} | {data['min_ms']:<10.3f}")
    print("=" * 65)
    print(f"Results saved to: {out_file}\n")


if __name__ == "__main__":
    main()
