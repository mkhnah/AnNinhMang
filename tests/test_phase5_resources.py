import asyncio
import io
import json
import threading
import time
from datetime import datetime,timezone
import pytest
import httpx
from backend.app.main import app
from backend.app.core.config import settings
from backend.app.core import verification_limits as limits
from backend.app.schemas.verify import VerificationResultResponse
from backend.app.services.verification_service import VerificationService
from tests.test_phase5_remediation import evidence, client_p5, storage_p5, upload

@pytest.fixture(autouse=True)
def clear_limits():
    limits._ip_request_history.clear()
    yield
    limits._ip_request_history.clear()

async def raw_request(path,chunks,headers=None):
    messages=[];calls=0;data=iter(chunks)
    async def receive():
        nonlocal calls
        calls+=1
        try:body=next(data)
        except StopIteration:return {'type':'http.disconnect'}
        return {'type':'http.request','body':body,'more_body':True}
    async def send(message):messages.append(message)
    scope={'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':'POST','scheme':'http',
        'path':path,'raw_path':path.encode(),'query_string':b'','root_path':'',
        'headers':headers or [],'client':('audit-peer',1234),'server':('localhost',8000)}
    await app(scope,receive,send)
    return messages,calls

@pytest.mark.parametrize('length',[False,True])
def test_early_body_cap_no_parse(monkeypatch,length):
    monkeypatch.setattr(settings,'VERIFY_MAX_BODY_BYTES',1024)
    head=[(b'content-type',b'multipart/form-data; boundary=a')]
    if length:head.append((b'content-length',b'2048'))
    messages,calls=asyncio.run(raw_request('/api/v1/verify/upload',[b'--a\r\nContent-Disposition: form-data; name="file"; filename="x.pdf"\r\n\r\n'+b'x'*2048],head))
    assert next(m['status'] for m in messages if m['type']=='http.response.start')==413
    if length:assert calls==0

def test_rate_before_multipart_and_untrusted_forwarding(monkeypatch):
    monkeypatch.setattr(settings,'VERIFY_RATE_PER_MINUTE',1)
    limits._ip_request_history['audit-peer']=[time.monotonic()]
    messages,calls=asyncio.run(raw_request('/api/v1/verify/upload',[],[(b'x-forwarded-for',b'different-ip')]))
    assert next(m['status'] for m in messages if m['type']=='http.response.start')==429
    assert calls==0

def test_rate_state_is_bounded(monkeypatch):
    monkeypatch.setattr(settings,'VERIFY_MAX_TRACKED_IPS',2)
    limits.check_rate_limit('a');limits.check_rate_limit('b')
    with pytest.raises(Exception) as e:limits.check_rate_limit('c')
    assert e.value.status_code==503 and len(limits._ip_request_history)==2

def test_public_jobs_capped_health_responsive(client_p5,monkeypatch):
    entered=0;lock=threading.Lock();release=threading.Event()
    sample=VerificationResultResponse(verification_id='sample',verification_mode='INDEPENDENT_DETACHED',summary_status='UNVERIFIABLE',document_hash_expected='',document_hash_computed='',results=dict(cryptographic_validity='UNVERIFIABLE',document_integrity='UNKNOWN',key_ownership='UNKNOWN',certificate_trust='UNKNOWN',key_revocation_status='UNKNOWN',verification_time=datetime.now(timezone.utc),timestamp_trust_level='DECLARED'))
    def slow(*args,**kwargs):
        nonlocal entered
        with lock:entered+=1
        assert release.wait(3)
        return sample
    monkeypatch.setattr(VerificationService,'verify_independent_package',slow)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost:8000') as client:
            async def post():return await client.post('/api/v1/verify/upload',files={'file':('x.pdf',b'x','application/pdf')},data={'package_json':'{}'})
            tasks=[asyncio.create_task(post()) for _ in range(settings.VERIFY_CONCURRENCY)]
            try:
                for _ in range(100):
                    if entered==settings.VERIFY_CONCURRENCY:break
                    await asyncio.sleep(.01)
                assert entered==settings.VERIFY_CONCURRENCY
                assert (await asyncio.wait_for(client.get('/health'),.5)).status_code==200
                assert (await post()).status_code==503
            finally:release.set()
            assert all(r.status_code==200 for r in await asyncio.gather(*tasks))
    asyncio.run(scenario())

def test_oversized_package_and_malformed_multipart(client_p5,evidence):
    r=client_p5.post('/api/v1/verify/upload',files={'file':('x.pdf',evidence['pdf']),'package':('x.json',b'x'*(settings.VERIFY_MAX_PACKAGE_BYTES+1))})
    assert r.status_code==413
    r=client_p5.post('/api/v1/verify/upload',content=b'malformed',headers={'Content-Type':'multipart/form-data'})
    assert r.status_code==400

def test_pdf_limit_and_timeout_cleanup(client_p5,evidence,monkeypatch):
    from backend.app.services import pdf_validator
    from pathlib import Path
    before=set(Path('data/tmp').iterdir())
    monkeypatch.setattr(settings,'MAX_UPLOAD_BYTES',64)
    assert upload(client_p5,evidence).status_code==413
    monkeypatch.setattr(settings,'MAX_UPLOAD_BYTES',20*1024*1024)
    monkeypatch.setattr(settings,'PDF_TIMEOUT_SECONDS',.000001)
    assert upload(client_p5,evidence).status_code==400
    assert not pdf_validator.ACTIVE_PARSER_PIDS
    assert set(Path('data/tmp').iterdir())==before

def test_admission_retained_until_worker_finishes():
    sem=threading.BoundedSemaphore(1);assert sem.acquire(False)
    lease=limits.Admission(sem);lease.start_job();lease.close_request()
    assert not sem.acquire(False)
    lease.finish_job();assert sem.acquire(False)

def test_stream_abort_closes_multipart_temp_files_and_releases_slot(monkeypatch):
    import starlette.formparsers as parsers
    tracked=[];factory=parsers.SpooledTemporaryFile
    def track(*args,**kwargs):
        stream=factory(*args,**kwargs);tracked.append(stream);return stream
    monkeypatch.setattr(parsers,'SpooledTemporaryFile',track)
    chunk=b'--a\r\nContent-Disposition: form-data; name="file"; filename="x.pdf"\r\nContent-Type: application/pdf\r\n\r\n'+b'x'*(1100*1024)
    asyncio.run(raw_request('/api/v1/verify/upload',[chunk],[(b'content-type',b'multipart/form-data; boundary=a')]))
    assert tracked and all(stream.closed for stream in tracked)
    assert limits.PUBLIC_SLOTS.acquire(False);limits.PUBLIC_SLOTS.release()

def test_spoofed_small_content_length_still_counts_actual_bytes(monkeypatch):
    monkeypatch.setattr(settings,'VERIFY_MAX_BODY_BYTES',1024)
    messages,_=asyncio.run(raw_request('/api/v1/verify/upload',[b'x'*2048],[(b'content-type',b'multipart/form-data; boundary=a'),(b'content-length',b'1')]))
    assert next(m['status'] for m in messages if m['type']=='http.response.start')==413

def test_valid_streaming_upload_without_content_length(client_p5,evidence):
    async def scenario():
        req=httpx.Request('POST','http://localhost:8000/api/v1/verify/upload',files={'file':('x.pdf',evidence['pdf'],'application/pdf')},data={'package_json':json.dumps(evidence['package'])})
        body=req.read()
        async def chunks():
            for offset in range(0,len(body),113):yield body[offset:offset+113]
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost:8000') as client:
            response=await client.post('/api/v1/verify/upload',content=chunks(),headers={'content-type':req.headers['content-type']})
            assert 'content-length' not in response.request.headers
            assert response.status_code==200,response.text
            assert response.json()['summary_status']=='VERIFIED'
    asyncio.run(scenario())

def test_cancelled_http_job_keeps_slot_until_thread_finishes(client_p5,monkeypatch):
    started=threading.Event();release=threading.Event();finished=threading.Event();streams=[]
    monkeypatch.setattr(limits,'PUBLIC_SLOTS',threading.BoundedSemaphore(1))
    def slow(db,pdf,*args,**kwargs):
        streams.append(pdf);started.set()
        try:
            assert release.wait(3)
            # Cancellation must never turn this request into an unbounded background job.
            return VerificationResultResponse(verification_id='cancelled',verification_mode='INDEPENDENT_DETACHED',summary_status='UNVERIFIABLE',document_hash_expected='',document_hash_computed='',results=dict(cryptographic_validity='UNVERIFIABLE',document_integrity='UNKNOWN',key_ownership='UNKNOWN',certificate_trust='UNKNOWN',key_revocation_status='UNKNOWN',verification_time=datetime.now(timezone.utc),timestamp_trust_level='UNKNOWN'))
        finally:finished.set()
    monkeypatch.setattr(VerificationService,'verify_independent_package',slow)
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://localhost:8000') as client:
            async def post():return await client.post('/api/v1/verify/upload',files={'file':('x.pdf',b'x','application/pdf')},data={'package_json':'{}'})
            task=asyncio.create_task(post())
            try:
                for _ in range(100):
                    if started.is_set():break
                    await asyncio.sleep(.01)
                assert started.is_set()
                task.cancel();await asyncio.sleep(.03)
                assert not finished.is_set()
                assert (await post()).status_code==503
            finally:release.set()
            try:await task
            except asyncio.CancelledError:pass
            for _ in range(100):
                if finished.is_set() and all(stream.closed for stream in streams):break
                await asyncio.sleep(.01)
            assert finished.is_set() and all(stream.closed for stream in streams)
            assert limits.PUBLIC_SLOTS.acquire(False);limits.PUBLIC_SLOTS.release()
    asyncio.run(scenario())
