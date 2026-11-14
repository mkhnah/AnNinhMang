import tempfile
import pytest
from fastapi import HTTPException
from pypdf import PdfWriter
from pypdf.generic import NameObject
from backend.app.core.config import settings
from backend.app.services.pdf_validator import validate_pdf, sanitize_filename
from tests.phase2.conftest import make_pdf


def validate(data, name='test.pdf', mime='application/pdf'):
    with tempfile.SpooledTemporaryFile() as source:
        source.write(data); source.seek(0)
        return validate_pdf(source, name, mime)


def test_valid(pdf):
    assert validate(pdf) == len(pdf)
    assert validate(pdf, mime='application/x-misleading') == len(pdf)


@pytest.mark.parametrize('name', ['test.exe', '../../etc/passwd'])
def test_extension(pdf, name):
    with pytest.raises(HTTPException) as exc: validate(pdf, name)
    assert exc.value.status_code == 415


@pytest.mark.parametrize('data,code', [(b'MZfake',415), (b'',415), (b'%PDF-1.7\n%%EOF',400)])
def test_invalid(data, code):
    with pytest.raises(HTTPException) as exc: validate(data)
    assert exc.value.status_code == code


def test_truncated(pdf):
    with pytest.raises(HTTPException) as exc: validate(pdf[:-10])
    assert exc.value.status_code == 400


def test_oversized(pdf, monkeypatch):
    monkeypatch.setattr(settings, 'MAX_UPLOAD_BYTES', 10)
    with pytest.raises(HTTPException) as exc: validate(pdf)
    assert exc.value.status_code == 413


@pytest.mark.parametrize('action', ['/JavaScript','/Launch','/SubmitForm','/GoToR','/GoToE'])
@pytest.mark.parametrize('indirect', [False, True])
def test_active_action(action, indirect):
    with pytest.raises(HTTPException) as exc: validate(make_pdf(action, indirect=indirect))
    assert exc.value.status_code == 400


def test_orphan_active_object():
    with pytest.raises(HTTPException): validate(make_pdf('/JavaScript', orphan=True))


def test_embedded_file():
    writer = PdfWriter(); writer.add_blank_page(200,200); writer.add_attachment('synthetic.txt', b'safe fixture')
    with tempfile.SpooledTemporaryFile() as source:
        writer.write(source); source.seek(0)
        with pytest.raises(HTTPException): validate_pdf(source, 'test.pdf', None)


def test_encrypted():
    writer = PdfWriter(); writer.add_blank_page(200,200); writer.encrypt('test-only')
    with tempfile.SpooledTemporaryFile() as source:
        writer.write(source); source.seek(0)
        with pytest.raises(HTTPException): validate_pdf(source, 'test.pdf', None)


@pytest.mark.parametrize('budget', ['PDF_TIMEOUT_SECONDS', 'PDF_MAX_OBJECTS', 'PDF_MAX_DEPTH'])
def test_parser_budgets(pdf, monkeypatch, budget):
    monkeypatch.setattr(settings, budget, .001 if budget == 'PDF_TIMEOUT_SECONDS' else 1)
    with pytest.raises(HTTPException) as exc: validate(pdf)
    assert exc.value.status_code == 400


@pytest.mark.parametrize('filename', ['../secret.pdf', '../../etc/passwd', 'tài liệu.pdf', '<script>alert(1)</script>.pdf', 'a\x00\r\n.pdf'])
def test_safe_filename(filename):
    safe = sanitize_filename(filename)
    assert not any(c in safe for c in ['/', '\\', '<', '>', '\r', '\n', '\x00'])
    assert len(safe) <= 255


def test_maximum_valid_file(monkeypatch):
    # Regression: worker file-size resource cap must allow disk-spooled uploads.
    assert validate(make_pdf(target_size=20 * 1024**2)) > 19 * 1024**2


def test_memory_budget(pdf,monkeypatch):
    monkeypatch.setattr(settings,'PDF_MEMORY_MB',1)
    with pytest.raises(HTTPException) as exc: validate(pdf)
    assert exc.value.status_code==400


def test_parser_slots(pdf):
    from backend.app.services.pdf_validator import _PARSER_SLOTS
    assert _PARSER_SLOTS.acquire(False)
    assert _PARSER_SLOTS.acquire(False)
    try:
        with pytest.raises(HTTPException) as exc: validate(pdf)
        assert exc.value.status_code==503
    finally:
        _PARSER_SLOTS.release();_PARSER_SLOTS.release()
