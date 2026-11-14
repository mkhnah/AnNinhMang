import io
import tempfile
from pathlib import Path
import pytest
from pypdf import PdfWriter
from pypdf.generic import NameObject, DictionaryObject, TextStringObject, DecodedStreamObject
from backend.app.api.v1.documents import get_storage
from backend.app.main import app
from backend.app.storage.local import LocalStorageService


def make_pdf(action=None, target_size=0, indirect=False, orphan=False):
    writer = PdfWriter()
    page = writer.add_blank_page(width=200, height=200)
    if action:
        obj = DictionaryObject({NameObject('/S'): NameObject(action)})
        obj[NameObject('/JS' if action == '/JavaScript' else '/F')] = TextStringObject('synthetic test only')
        if indirect:
            obj = writer._add_object(obj)
        if not orphan:
            writer._root_object[NameObject('/OpenAction')] = obj
        else:
            writer._add_object(obj)
    if target_size:
        padding = DecodedStreamObject()
        padding.set_data(b' ' * max(0, target_size - 600))
        page[NameObject('/Contents')] = writer._add_object(padding)
    output = io.BytesIO(); writer.write(output)
    return output.getvalue()


@pytest.fixture
def pdf():
    return make_pdf()


@pytest.fixture
def storage():
    with tempfile.TemporaryDirectory(prefix='p2-test-', dir='data') as root:
        yield LocalStorageService(Path(root).resolve())


@pytest.fixture
def documents_client(client, storage):
    app.dependency_overrides[get_storage] = lambda: storage
    yield client
    app.dependency_overrides.pop(get_storage, None)


@pytest.fixture
def auth_user(documents_client):
    payload = {'email': 'pdf@cyber.edu', 'full_name': 'PDF Tester', 'password': 'SecurePassword123!', 'confirm_password': 'SecurePassword123!'}
    assert documents_client.post('/api/v1/auth/register', json=payload).status_code == 201
    assert documents_client.post('/api/v1/auth/login', json=payload).status_code == 200
    documents_client.headers['X-Requested-With'] = 'XMLHttpRequest'
    return documents_client
