import io
import os
import subprocess
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import UploadFile
from backend.app.core.database import Base
from backend.app.models.user import User
from backend.app.models.document import DocumentVersion
from backend.app.services import document_service
from tests.phase2.conftest import make_pdf


def test_concurrent_numbering(storage, monkeypatch):
    engine=create_engine(f'sqlite:///{storage.root}/concurrent.db', connect_args={'check_same_thread':False})
    Base.metadata.create_all(engine); sessions=sessionmaker(bind=engine)
    with sessions() as db:
        user=User(email='race@test.edu',full_name='Test',password_hash='synthetic');db.add(user);db.commit(); owner=user.id
    def create(doc=None):
        with sessions() as db, tempfile.SpooledTemporaryFile() as file:
            file.write(make_pdf());file.seek(0)
            result=document_service.create_version(db,storage,owner,UploadFile(file,filename='same.pdf'),document_id=doc)
            return result.document_id,result.version_no
    doc,_=create()
    barrier=threading.Barrier(2)
    real=document_service.validate_pdf
    def synchronized(*args):
        size=real(*args);barrier.wait(timeout=10);return size
    monkeypatch.setattr(document_service,'validate_pdf',synchronized)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:create(doc), range(2)))
    assert sorted(n for _,n in results)==[2,3]
    with sessions() as db:
        assert len(db.scalars(select(DocumentVersion)).all())==3
    assert len(list(storage.root.rglob('*.pdf')))==3
    engine.dispose()


def test_migration_preserves_phase1(storage):
    path=storage.root/'migration.db'
    env={**os.environ,'DATABASE_URL':f'sqlite:///{path}','DEBUG':'false'}
    def migrate(target):
        result=subprocess.run([sys.executable,'-m','alembic','upgrade',target],env=env,capture_output=True,text=True,timeout=20)
        assert result.returncode==0,result.stderr
    migrate('063d00eeffb0')
    engine=create_engine(f'sqlite:///{path}')
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO users (id,email,full_name,password_hash,role,status,failed_login_attempts,created_at,updated_at) VALUES ('original','keep@test.edu','Keep','synthetic','USER','ACTIVE',0,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
        conn.execute(text("INSERT INTO auth_sessions (id,user_id,refresh_token_hash,created_at,expires_at) VALUES ('session','original','hash',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)"))
    migrate('head')
    with engine.connect() as conn:
        assert conn.scalar(text('SELECT count(*) FROM users'))==1
        assert conn.scalar(text('SELECT count(*) FROM auth_sessions'))==1
        assert conn.scalar(text("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND name='version_immutable'"))==1
        assert conn.scalar(text('PRAGMA foreign_keys'))==1
    engine.dispose()


def test_memory_adapter(auth_user,db_session,pdf):
    class MemoryStorage:
        def __init__(self): self.files={}
        def save_file(self,key,source):
            assert key not in self.files
            self.files[key]=source.read()
        def get_file(self,key): return io.BytesIO(self.files[key])
        def exists(self,key): return key in self.files
        def delete_file(self,key): del self.files[key]
    storage=MemoryStorage();owner=db_session.scalar(select(User.id))
    with tempfile.SpooledTemporaryFile() as source:
        source.write(pdf);source.seek(0)
        version=document_service.create_version(db_session,storage,owner,UploadFile(source,filename='test.pdf'))
    with document_service.verified_file(storage,version) as source:
        assert source.read()==pdf
