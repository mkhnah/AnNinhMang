#!/usr/bin/env python3
"""Bounded synthetic TestClient benchmark. No browser/network/camera timings."""
import json
import logging
import math
import os
from pathlib import Path
import platform
import resource
import statistics
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import psutil

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ['DEBUG'] = 'false'


def summarize(samples):
    """Retain every sample in milliseconds; nearest-rank p95."""
    values = sorted(samples)
    return dict(iterations=len(values), samples_ms=samples,
                mean_ms=statistics.mean(values), median_ms=statistics.median(values),
                p95_ms=values[math.ceil(.95 * len(values)) - 1],
                min_ms=values[0], max_ms=values[-1])


def measure(operation, count):
    samples = []
    for _ in range(count):
        started = time.perf_counter()
        operation()
        samples.append((time.perf_counter() - started) * 1000)
    return summarize(samples)


def run_benchmark():
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from backend.app.main import app
    from backend.app.core.database import Base, get_db
    from backend.app.api.v1.documents import get_storage
    from backend.app.storage.local import LocalStorageService
    from backend.app.services.share_service import generate_share_token, token_digest
    from backend.app.core.verification_limits import _ip_request_history
    from backend.app.models.share import ShareToken
    from tests.test_phase5_verification import (generate_test_rsa_3072, register_and_login_user,
        register_user_key, create_and_sign_document)

    logging.disable(logging.CRITICAL)  # Synthetic bearer URLs must not enter HTTPX logs.
    process = psutil.Process()
    before = process.memory_info().rss
    sampled_peak = [before]
    stop = threading.Event()
    def sample():
        while not stop.wait(.005):
            sampled_peak[0] = max(sampled_peak[0], process.memory_info().rss)
    sampler = threading.Thread(target=sample, daemon=True)
    cpu_start, wall_start = time.process_time(), time.perf_counter()
    child_start = resource.getrusage(resource.RUSAGE_CHILDREN)
    sampler.start()
    previous_overrides = app.dependency_overrides.copy()
    try:
        with tempfile.TemporaryDirectory(prefix='p6-benchmark-', dir=ROOT / 'data/tmp') as temporary:
            root = Path(temporary)
            engine = create_engine(f'sqlite:///{root / "bench.db"}', connect_args={'check_same_thread': False})
            Base.metadata.create_all(engine)
            sessions = sessionmaker(bind=engine)
            storage = LocalStorageService(root / 'storage')
            def database():
                with sessions() as session:
                    yield session
            app.dependency_overrides[get_db] = database
            app.dependency_overrides[get_storage] = lambda: storage
            _ip_request_history.clear()
            with TestClient(app) as client:
                user = register_and_login_user(client, 'p6-benchmark@cyber.edu')
                private, _, pem, fingerprint = generate_test_rsa_3072()
                key = register_user_key(client, user, private, pem, fingerprint)
                _, version, pdf, _, _ = create_and_sign_document(client, user, key, private)
                headers = user['headers']
                shares = []
                def create():
                    response = client.post('/api/v1/shares', json={'version_id': version}, headers=headers)
                    assert response.status_code == 201, response.status_code
                    shares.append(response.json())
                create()
                token = shares[0]['share_url'].rsplit('/', 1)[1]
                digest = token_digest(token)
                metrics = {}
                metrics['token_generation'] = measure(generate_share_token, 1000)
                metrics['token_hashing_sha256'] = measure(lambda: token_digest(token), 1000)
                with sessions() as session:
                    def lookup():
                        assert session.scalar(select(ShareToken.id).where(ShareToken.token_hash == digest))
                    metrics['indexed_sqlite_lookup'] = measure(lookup, 100)
                metrics['share_creation_api_with_gate'] = measure(create, 10)
                client.cookies.clear()
                def verify():
                    response = client.get('/api/v1/verify/share/' + token)
                    assert response.status_code == 200, response.status_code
                metrics['public_verification_api'] = measure(verify, 20)
                concurrent_samples, statuses = [], []
                def concurrent_verify():
                    started = time.perf_counter()
                    response = client.get('/api/v1/verify/share/' + token)
                    return (time.perf_counter() - started) * 1000, response.status_code
                with ThreadPoolExecutor(max_workers=2) as pool:
                    for _ in range(4):
                        futures = [pool.submit(concurrent_verify) for _ in range(2)]
                        for future in futures:
                            elapsed, status = future.result(15)
                            concurrent_samples.append(elapsed)
                            statuses.append(status)
                metrics['concurrent_public_verification_api'] = {
                    **summarize(concurrent_samples), 'workers': 2, 'batches': 4, 'status_codes': statuses}
                def revoke():
                    share = shares.pop()
                    response = client.post(f'/api/v1/shares/{share["id"]}/revoke', headers=headers)
                    assert response.status_code == 204, response.status_code
                metrics['share_revocation_api'] = measure(revoke, 10)
            engine.dispose()
        after = process.memory_info().rss
        child_end = resource.getrusage(resource.RUSAGE_CHILDREN)
        result = dict(
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            platform=dict(system=platform.system(), architecture=platform.machine(), python=platform.python_version()),
            scope='In-process FastAPI TestClient; real SQLite, SHA-256, RSA verification and atomic share issuance. No TCP/TLS/browser/camera measurement.',
            fixture=dict(pdf_bytes=len(pdf), pdf_kind='Synthetic blank page', signing='Python fixture signer; real WebCrypto interoperability is separately tested'),
            percentile_method='Nearest rank: sorted samples[ceil(0.95*n)-1]; raw milliseconds retained',
            benchmarks=metrics,
            resources=dict(parent_cpu_seconds=time.process_time() - cpu_start,
                child_cpu_seconds=(child_end.ru_utime + child_end.ru_stime - child_start.ru_utime - child_start.ru_stime),
                wall_seconds=time.perf_counter() - wall_start,
                rss_before_bytes=before, rss_after_bytes=after, rss_delta_bytes=after-before,
                sampled_parent_peak_rss_bytes=max(sampled_peak[0], after), sample_period_ms=5,
                os_process_lifetime_peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform=='darwin' else 1024)),
            limitations='Resource interval includes fixture setup/cleanup; OS peak includes imports and entire process lifetime. Sampling can miss short peaks. RSS delta does not prove no leak. Small synthetic PDF and bounded 2-way concurrency do not establish production capacity.')
        (ROOT / 'docs/phase6-benchmark.json').write_text(json.dumps(result, indent=2) + '\n')
        print('Wrote benchmark with raw samples; no bearer tokens included.')
    finally:
        stop.set(); sampler.join(1)
        app.dependency_overrides.clear(); app.dependency_overrides.update(previous_overrides)


if __name__ == '__main__':
    run_benchmark()
