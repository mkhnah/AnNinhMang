"""Sequential synthetic benchmarks. Private DB/storage; no live service or network."""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import io
import json
import tempfile
import time
import threading
import resource
import platform
import hashlib
import psutil
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient


def main():
    with tempfile.TemporaryDirectory(prefix='p2-benchmark-', dir='data') as root:
        os.environ['DATABASE_URL'] = f'sqlite:///{root}/benchmark.db'
        os.environ['DEBUG'] = 'false'
        from backend.app.core.database import Base, get_db
        from backend.app.models.user import User
        from backend.app.models.document import DocumentVersion
        from backend.app.auth.jwt import create_access_token
        from backend.app.main import app
        from backend.app.api.v1.documents import get_storage
        from backend.app.storage.local import LocalStorageService
        from backend.app.crypto.hasher import sha256_stream
        from backend.app.services.pdf_validator import validate_pdf, ACTIVE_PARSER_PIDS
        from backend.app.core.config import settings
        from pypdf import PdfWriter
        from pypdf.generic import DecodedStreamObject, NameObject
        engine = create_engine(os.environ['DATABASE_URL'], connect_args={'check_same_thread':False})
        Base.metadata.create_all(engine); sessions=sessionmaker(bind=engine)
        with sessions() as db:
            user=User(email='benchmark@test.edu', full_name='Synthetic', password_hash='unused');db.add(user);db.commit();token=create_access_token(user.id,'USER')
        storage=LocalStorageService(Path(root).resolve()/'storage')
        def database():
            with sessions() as db: yield db
        app.dependency_overrides[get_db]=database
        app.dependency_overrides[get_storage]=lambda:storage
        process=psutil.Process()
        results=[]

        def measure(stage, amount, operation):
            baseline=process.memory_info().rss
            peak_parent=baseline;peak_child=0;peak_total=baseline
            done=threading.Event()
            def sample():
                nonlocal peak_parent,peak_child,peak_total
                while not done.is_set():
                    parent=process.memory_info().rss
                    children=0
                    for pid in ACTIVE_PARSER_PIDS.copy():
                        try: children+=psutil.Process(pid).memory_info().rss
                        except psutil.NoSuchProcess: pass
                    peak_parent=max(peak_parent,parent);peak_child=max(peak_child,children);peak_total=max(peak_total,parent+children)
                    done.wait(.002)
            thread=threading.Thread(target=sample);thread.start()
            cpu0=resource.getrusage(resource.RUSAGE_SELF);child0=resource.getrusage(resource.RUSAGE_CHILDREN)
            started=time.perf_counter()
            try: value=operation()
            finally:
                elapsed=time.perf_counter()-started;done.set();thread.join()
            cpu1=resource.getrusage(resource.RUSAGE_SELF);child1=resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu=(cpu1.ru_utime+cpu1.ru_stime-cpu0.ru_utime-cpu0.ru_stime)+(child1.ru_utime+child1.ru_stime-child0.ru_utime-child0.ru_stime)
            results.append({'stage':stage,'file_bytes':amount,'latency_ms':round(elapsed*1000,3),'cpu_seconds_parent_and_children':round(cpu,5),'parent_peak_rss_mb':round(peak_parent/1024**2,2),'parent_rss_delta_mb':round((peak_parent-baseline)/1024**2,2),'child_peak_rss_mb':round(peak_child/1024**2,2),'combined_peak_rss_mb':round(peak_total/1024**2,2),'throughput_mib_s':round(amount/1024**2/elapsed,2)})
            return value
        with TestClient(app) as client:
            client.headers['Authorization']='Bearer '+token
            for target in [1024**2,5*1024**2,10*1024**2,settings.MAX_UPLOAD_BYTES]:
                writer=PdfWriter();page=writer.add_blank_page(200,200)
                stream=DecodedStreamObject();stream.set_data(b' '*(target-1024));page[NameObject('/Contents')]=writer._add_object(stream)
                path=Path(root)/'synthetic.pdf'
                with path.open('wb') as out:writer.write(out)
                # Pad inside stream to exact target size, including writer overhead.
                correction=target-path.stat().st_size
                stream.set_data(stream.get_data()+b' '*correction)
                with path.open('wb') as out:writer.write(out)
                amount=path.stat().st_size
                with path.open('rb') as source:
                    digest=measure('sha256',amount,lambda:sha256_stream(source))
                key=f'00000000-0000-0000-0000-000000000000/v1_{__import__("uuid").uuid4()}.pdf'
                with path.open('rb') as source:measure('storage_write',amount,lambda:storage.save_file(key,source))
                def read():
                    with storage.get_file(key) as source:assert sha256_stream(source)==digest
                measure('storage_read_and_hash',amount,read)
                with path.open('rb') as source:measure('pdf_validation',amount,lambda:validate_pdf(source,'synthetic.pdf','application/pdf'))
                with path.open('rb') as source:
                    response=measure('api_upload',amount,lambda:client.post('/api/v1/documents',files={'file':('synthetic.pdf',source,'application/pdf')}))
                assert response.status_code==201,response.text
                version=response.json()
                def download():
                    sha=hashlib.sha256()
                    with client.stream('GET',f"/api/v1/documents/{version['document_id']}/versions/{version['version_id']}/download") as response:
                        assert response.status_code==200
                        for chunk in response.iter_bytes(65536):sha.update(chunk)
                    assert sha.hexdigest()==digest
                measure('api_download',amount,download)
                storage.delete_file(key)
        disk=sum(p.stat().st_size for p in Path(root).rglob('*') if p.is_file())
        allocated=sum(p.stat().st_blocks * 512 for p in Path(root).rglob('*') if p.is_file())
        report={'host_physical_memory_mb':round(psutil.virtual_memory().total / 1024**2), 'disk_allocated_bytes_at_end':allocated, 'platform':platform.platform(),'machine':platform.machine(),'python':platform.python_version(),'method':'One sequential sample per stage/size; 2ms RSS sampling; CPU includes child processes. API uses in-process TestClient, which buffers HTTP bodies; not a network/browser throughput benchmark. Fixture generation excluded. Warm OS cache. No stress test. RSS sampling is approximate, not an OS hard cap.', 'disk_bytes_at_end_including_fixtures_db_storage':disk,'results':results}
        Path('docs/phase2-benchmark.json').write_text(json.dumps(report,indent=2)+'\n')
        app.dependency_overrides.clear();engine.dispose()
        print(json.dumps({'samples':len(results),'report':'docs/phase2-benchmark.json','disk_bytes':disk}))


if __name__=='__main__':main()
