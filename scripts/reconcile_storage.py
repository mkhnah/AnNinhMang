"""Read-only recovery report. Never delete or attach files automatically.
Run while uploads are stopped to avoid reporting in-flight transactions as orphans.
"""
import sys
import json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sqlalchemy import select
from backend.app.core.database import SessionLocal
from backend.app.core.config import settings
from backend.app.models.document import DocumentVersion
from backend.app.storage.local import LocalStorageService


def reconcile(storage, versions):
    referenced={version.storage_key for version in versions}
    present=set(); temporary=[]; unsafe=[]
    for path in storage.root.rglob('*'):
        relative=path.relative_to(storage.root).as_posix()
        if relative == '.gitkeep':
            continue
        if path.is_symlink():
            unsafe.append(relative)
        elif path.is_file():
            if path.name.startswith('.upload-'): temporary.append(relative)
            else: present.add(relative)
    return {'orphan_keys':sorted(present-referenced),'missing_keys':sorted(referenced-present),
            'temporary_files':sorted(temporary),'unsafe_symlinks':sorted(unsafe),
            'action':'READ_ONLY: stop uploads, investigate, restore from backup or review individual operation keys; nothing deleted'}


def main():
    storage=LocalStorageService(settings.LOCAL_STORAGE_PATH)
    with SessionLocal() as db:
        print(json.dumps(reconcile(storage,db.scalars(select(DocumentVersion)).all()),indent=2))


if __name__=='__main__':main()
