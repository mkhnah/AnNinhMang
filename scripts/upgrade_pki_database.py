"""Back up the configured repository SQLite database, upgrade, and compare retained rows."""
from datetime import datetime
from zoneinfo import ZoneInfo
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys

repository = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repository))
from backend.app.core.config import settings


def identifier(value):
    return '"' + value.replace('"', '""') + '"'


def snapshot(connection):
    result = {}
    tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name!='alembic_version'").fetchall()
    for (name,) in tables:
        columns = [row[1] for row in connection.execute(f'PRAGMA table_info({identifier(name)})')]
        rows = connection.execute(f'SELECT * FROM {identifier(name)} ORDER BY ' + ','.join(map(identifier,columns))).fetchall()
        digest = hashlib.sha256(json.dumps(rows, ensure_ascii=True, default=lambda value:value.hex(), separators=(',',':')).encode()).hexdigest()
        result[name] = len(rows), digest
    return result


def main():
    if not settings.DATABASE_URL.startswith('sqlite:///'):
        raise ValueError('Expected SQLite database')
    path = Path(settings.DATABASE_URL.removeprefix('sqlite:///')).resolve()
    if not path.is_relative_to(repository / 'data/db') or not path.is_file():
        raise ValueError('Expected an existing repository data/db database')
    backup = repository / 'data/db/backups' / ('docsign_pre_pki_v2_' + datetime.now(ZoneInfo('Asia/Bangkok')).strftime('%Y%m%d_%H%M%S') + '.db')
    backup.parent.mkdir(parents=True, exist_ok=True)
    if backup.exists():
        raise ValueError('Refusing to overwrite backup')
    with sqlite3.connect(path) as source, sqlite3.connect(backup) as destination:
        source.backup(destination)
    with sqlite3.connect(backup) as connection:
        before = snapshot(connection)
        revision = connection.execute('SELECT version_num FROM alembic_version').fetchone()[0]
    print(f'Backup: {backup.relative_to(repository)}; previous revision: {revision}', flush=True)
    subprocess.run([sys.executable, '-m', 'alembic', 'upgrade', 'head'], cwd=repository, check=True)
    subprocess.run([sys.executable, '-m', 'alembic', 'check'], cwd=repository, check=True)
    with sqlite3.connect(path) as connection:
        after = snapshot(connection)
        if any(after.get(name) != evidence for name,evidence in before.items()):
            raise RuntimeError('Retained data comparison failed; preserve backup for recovery')
        if connection.execute('PRAGMA foreign_key_check').fetchall() or connection.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise RuntimeError('Database integrity check failed')
        revision = connection.execute('SELECT version_num FROM alembic_version').fetchone()[0]
    print(f'Revision {revision}; all {len(before)} historical table snapshots preserved; FK/integrity PASS', flush=True)


if __name__ == '__main__':
    main()
