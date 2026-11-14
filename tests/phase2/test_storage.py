import errno
import hashlib
import io
import os
import uuid
import pytest
from backend.app.crypto.hasher import sha256_stream
from backend.app.storage.local import LocalStorageService


def key():
    return f'{uuid.uuid4()}/v1_{uuid.uuid4()}.pdf'


def test_round_trip(storage, pdf):
    name = key(); storage.save_file(name, io.BytesIO(pdf))
    with storage.get_file(name) as source:
        assert source.read() == pdf
        source.seek(0)
        assert sha256_stream(source) == hashlib.sha256(pdf).hexdigest()
    assert storage.exists(name)
    assert (storage.root / name).stat().st_mode & 0o777 == 0o600
    restarted = LocalStorageService(storage.root)
    assert restarted.exists(name)
    storage.delete_file(name)
    assert not storage.exists(name)


def test_duplicate_key_never_overwrites(storage):
    name = key(); storage.save_file(name, io.BytesIO(b'first'))
    with pytest.raises(FileExistsError):
        storage.save_file(name, io.BytesIO(b'second'))
    with storage.get_file(name) as source:
        assert source.read() == b'first'
    assert not list(storage.root.rglob('*.tmp'))


@pytest.mark.parametrize('name', ['../secret.pdf', '/tmp/escape.pdf', '../../etc/passwd', 'a/v1_b.pdf'])
def test_traversal(storage, name):
    with pytest.raises(ValueError): storage.save_file(name, io.BytesIO(b'x'))


def test_symlink_directory_and_file(storage):
    first, other = key(), key()
    storage.save_file(other, io.BytesIO(b'original'))
    document, name = first.split('/')
    (storage.root / document).symlink_to((storage.root / other).parent)
    with pytest.raises(OSError): storage.save_file(first, io.BytesIO(b'bad'))
    # Final component must not follow a symlink either.
    target = key(); storage.save_file(target, io.BytesIO(b'x'))
    (storage.root / target).unlink()
    (storage.root / target).symlink_to(storage.root / other)
    with pytest.raises(OSError): storage.get_file(target)


def test_symlink_root(storage):
    link = storage.root / 'escape'; link.symlink_to(storage.root, target_is_directory=True)
    with pytest.raises(ValueError): LocalStorageService(link)


def test_missing(storage):
    assert not storage.exists(key())
    with pytest.raises(FileNotFoundError): storage.get_file(key())


def test_atomic_failure(storage, monkeypatch):
    def fail(*args, **kwargs): raise OSError(errno.ENOSPC, 'synthetic disk full')
    monkeypatch.setattr(os, 'link', fail)
    with pytest.raises(OSError): storage.save_file(key(), io.BytesIO(b'test'))
    assert not list(storage.root.rglob('*.pdf'))
    assert not list(storage.root.rglob('*.tmp'))


def test_permission_denied(storage, monkeypatch):
    original = os.open
    def denied(path, flags, *args, **kwargs):
        if flags & os.O_CREAT: raise PermissionError('synthetic denial')
        return original(path, flags, *args, **kwargs)
    monkeypatch.setattr(os, 'open', denied)
    with pytest.raises(PermissionError): storage.save_file(key(), io.BytesIO(b'test'))
    assert not list(storage.root.rglob('*.pdf'))


@pytest.mark.parametrize('amount', [0, 1, 1024**2, 5*1024**2, 10*1024**2])
def test_hasher_reference(amount):
    data = b'a' * amount
    assert sha256_stream(io.BytesIO(data)) == hashlib.sha256(data).hexdigest()


def test_hasher_errors():
    with pytest.raises(ValueError): sha256_stream(io.BytesIO(), 0)
    class Broken:
        def read(self, _): raise OSError('read failed')
    with pytest.raises(OSError): sha256_stream(Broken())


def test_reconciliation_reports_only(storage):
    from scripts.reconcile_storage import reconcile
    orphan=key();storage.save_file(orphan,io.BytesIO(b'fixture'))
    result=reconcile(storage,[])
    assert result['orphan_keys']==[orphan]
    assert storage.exists(orphan)
