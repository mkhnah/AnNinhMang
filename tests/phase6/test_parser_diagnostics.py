"""Real bounded worker termination; synthetic input and private worker copy."""
import logging
from pathlib import Path
import tempfile

import pytest
from fastapi import HTTPException
from backend.app.core.config import settings
from backend.app.services import pdf_validator
from tests.phase2.conftest import make_pdf


def test_real_cpu_budget_signal_is_logged_without_input(tmp_path, monkeypatch, caplog):
    worker = Path(pdf_validator.__file__).with_name('pdf_worker.py')
    instrumented = tmp_path / 'cpu_bound_parser.py'
    instrumented.write_text(worker.read_text().replace(
        '    from pypdf import PdfReader', '    while True: pass\n    from pypdf import PdfReader'))
    original = pdf_validator.subprocess.Popen
    def spawn(command, **kwargs):
        return original([command[0], str(instrumented), *command[2:]], **kwargs)
    monkeypatch.setattr(pdf_validator.subprocess, 'Popen', spawn)
    monkeypatch.setattr(settings, 'PDF_CPU_SECONDS', 1)
    monkeypatch.setattr(settings, 'PDF_TIMEOUT_SECONDS', 5)
    data = make_pdf()
    with tempfile.TemporaryFile() as stream:
        stream.write(data); stream.seek(0)
        with caplog.at_level(logging.WARNING, logger='docsign.pdf'):
            with pytest.raises(HTTPException) as error:
                pdf_validator.validate_pdf(stream, 'synthetic.pdf', None)
        assert error.value.status_code == 400
    assert 'signal=SIGXCPU' in caplog.text
    assert 'stage=import' in caplog.text
    assert 'cpu_budget=1' in caplog.text
    assert 'worker_cpu_seconds=None' not in caplog.text
    assert '%PDF' not in caplog.text
    assert not pdf_validator.ACTIVE_PARSER_PIDS
