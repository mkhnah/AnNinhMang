#!/usr/bin/env python3
"""Sequential bounded benchmark: real multipart FastAPI requests + parser + private DB.
Fresh child process per size; no live DB/storage. This is in-process HTTP, not browser/TCP.
"""
import os
os.environ['DEBUG']='false'
import sys
import json
import subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def child(mb):
    import tempfile
    with tempfile.TemporaryDirectory(prefix='p5-benchmark-',dir=ROOT/'data/tmp') as folder:
        os.environ['DATABASE_URL']=f'sqlite:///{folder}/benchmark.db'
        return measure(mb,folder)

def measure(mb,folder):
    import asyncio,base64,hashlib,secrets,statistics,time,threading,resource
    import psutil
    from datetime import datetime,timezone
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session,sessionmaker
    from cryptography.hazmat.primitives import hashes,serialization
    from cryptography.hazmat.primitives.asymmetric import padding,rsa
    from backend.app.main import app
    from backend.app.core.database import Base,get_db
    from backend.app.core.upload_limit import UploadLimitMiddleware
    from backend.app.services import verification_service as service
    from backend.app.services.verification_service import VerificationService
    from tests.phase2.conftest import make_pdf
    import logging
    logging.disable(logging.CRITICAL)
    metrics={};active=False
    def record(name,elapsed):metrics.setdefault(name,[]).append(elapsed*1000)
    for name,label in [('validate_pdf','pdf_parser_ms'),('compute_stream_sha256','sha256_ms'),('canonicalize_jcs','jcs_ms'),('parse_profile','spki_profile_ms'),('verify_rsa_pss','rsa_pss_verify_ms')]:
        original=getattr(service,name)
        def instrument(*args,_fn=original,_label=label,**kwargs):
            start=time.perf_counter()
            try:return _fn(*args,**kwargs)
            finally:
                if active:record(_label,time.perf_counter()-start)
        setattr(service,name,instrument)
    class TimedSession(Session):
        def commit(self):
            start=time.perf_counter()
            try:return super().commit()
            finally:
                if active:record('event_flush_commit_ms',time.perf_counter()-start)
    engine=create_engine(os.environ['DATABASE_URL'],connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine);factory=sessionmaker(engine,class_=TimedSession)
    def database():
        with factory() as session:yield session
    app.dependency_overrides[get_db]=database
    # One synthetic blank-page content stream, close to the requested number of MiB.
    pdf=make_pdf(target_size=mb*1024*1024)
    private=rsa.generate_private_key(public_exponent=65537,key_size=3072)
    pub=private.public_key();der=pub.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    manifest=dict(manifest_version=1,document_version_id='11111111-1111-4111-8111-111111111111',document_sha256=hashlib.sha256(pdf).hexdigest(),key_id='22222222-2222-4222-8222-222222222222',signer_fingerprint=hashlib.sha256(der).hexdigest(),algorithm='RSA-PSS-3072',signing_nonce=secrets.token_urlsafe(32),signing_timestamp='2026-11-15T00:00:00.000Z',signing_context='DOCSIGN_DOCUMENT_SIGNATURE_V1')
    canonical=service.canonicalize_jcs(manifest)
    signature=private.sign(canonical,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=32),hashes.SHA256())
    package=json.dumps(dict(package_version=1,signature_format='DETACHED_JCS_V1',manifest=manifest,signature_b64=base64.b64encode(signature).decode(),public_key_spki_pem=pub.public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode())).encode()
    # Isolated body guard microbenchmark; not presented as E2E latency.
    async def guard_only():
        remaining=len(pdf)+len(package)+1024
        async def receive():
            nonlocal remaining
            size=min(65536,remaining);remaining-=size
            return {'type':'http.request','body':b'x'*size,'more_body':remaining>0}
        async def downstream(scope,receive,send):
            while (await receive())['more_body']:pass
        async def send(message):pass
        scope={'type':'http','method':'POST','path':'/api/v1/verify/upload','headers':[], 'client':('benchmark-guard',1)}
        await UploadLimitMiddleware(downstream)(scope,receive,send)
    for _ in range(5):
        start=time.perf_counter();asyncio.run(guard_only());record('body_guard_in_memory_ms',time.perf_counter()-start)
    parent=psutil.Process();stop=threading.Event()
    baseline=parent.memory_info().rss;peak_parent=baseline;peak_tree=baseline
    def monitor():
        nonlocal peak_parent,peak_tree
        while not stop.wait(.005):
            try:
                rss=parent.memory_info().rss
                descendants=sum(p.memory_info().rss for p in parent.children(recursive=True) if p.is_running())
                peak_parent=max(peak_parent,rss);peak_tree=max(peak_tree,rss+descendants)
            except psutil.Error:pass
    thread=threading.Thread(target=monitor,daemon=True);thread.start()
    cpu=time.process_time();child_cpu=resource.getrusage(resource.RUSAGE_CHILDREN)
    active=True
    try:
        with TestClient(app,base_url='http://localhost:8000') as client:
            for _ in range(5):
                start=time.perf_counter()
                response=client.post('/api/v1/verify/upload',files={'file':('benchmark.pdf',pdf,'application/pdf'),'package':('signature-package.json',package,'application/json')})
                record('multipart_api_total_ms',time.perf_counter()-start)
                assert response.status_code==200,response.text
                assert response.json()['summary_status']=='VERIFIED'
                assert response.json()['results']['key_ownership']=='UNVERIFIED'
    finally:
        active=False;stop.set();thread.join();app.dependency_overrides.clear();engine.dispose()
    cpu=time.process_time()-cpu;child_after=resource.getrusage(resource.RUSAGE_CHILDREN)
    summary={label:dict(samples=len(values),mean_ms=round(statistics.mean(values),3),median_ms=round(statistics.median(values),3),min_ms=round(min(values),3),max_ms=round(max(values),3)) for label,values in metrics.items()}
    return dict(target_mib=mb,actual_pdf_bytes=len(pdf),package_bytes=len(package),samples_per_size=5,
        metrics=summary,parent_cpu_seconds=round(cpu,4),parser_child_cpu_seconds=round((child_after.ru_utime+child_after.ru_stime)-(child_cpu.ru_utime+child_cpu.ru_stime),4),
        parent_rss_baseline_mib=round(baseline/1048576,2),sampled_parent_peak_rss_mib=round(peak_parent/1048576,2),sampled_process_tree_peak_rss_mib=round(peak_tree/1048576,2),memory_sampling_interval_ms=5,
        process_lifetime_peak_rss_mib=round(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss/1048576,2))

if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--child':
        print(json.dumps(child(int(sys.argv[2]))))
    else:
        import platform
        from datetime import datetime,timezone
        results=[]
        for mb in [1,5,10,20]:
            run=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--child',str(mb)],cwd=ROOT,capture_output=True,text=True,timeout=60)
            if run.returncode:raise RuntimeError(run.stderr[-4000:])
            results.append(json.loads(run.stdout.strip().splitlines()[-1]))
        report=dict(timestamp=datetime.now(timezone.utc).isoformat(),runtime=f'Python {platform.python_version()} {platform.system()} {platform.machine()}',scope='FastAPI TestClient multipart E2E; real bounded parser subprocess, SHA/JCS/RSA, private SQLite event commit and receipt issuance. No TCP/browser/TLS measurement.',limitations='Five serial samples per size, synthetic blank-page PDFs; sampled tree RSS can miss peaks between 5ms samples; child-process sum can count shared pages. ru_maxrss is macOS bytes, process lifetime peak includes setup. Not complex/scanned/malicious PDF or browser memory evidence.',results=results)
        (ROOT/'docs/phase5-benchmark.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps(report,indent=2))
