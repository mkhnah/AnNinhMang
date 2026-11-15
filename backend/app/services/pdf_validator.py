import logging
import json
import signal
import threading
import os
import subprocess
import sys
import time
import unicodedata
from pathlib import Path
from typing import BinaryIO
import psutil
from fastapi import HTTPException
from backend.app.core.config import settings

logger = logging.getLogger('docsign.pdf')
_PARSER_SLOTS = threading.BoundedSemaphore(2)
ACTIVE_PARSER_PIDS: set[int] = set()
REPOSITORY = Path(__file__).resolve().parents[3]


def sanitize_filename(filename: str) -> str:
    name = filename.replace('\\', '/').split('/')[-1]
    name = ''.join(c for c in unicodedata.normalize('NFC', name) if not unicodedata.category(c).startswith('C'))
    name = name.replace('<', '').replace('>', '').replace('"', '').replace("'", '')
    return (name[:250] or 'document.pdf')


def _validate_pdf(stream: BinaryIO, filename: str, mime: str | None) -> int:
    if not filename or not filename.lower().endswith('.pdf'):
        raise HTTPException(415, 'Chỉ chấp nhận tệp .pdf')
    stream.seek(0, 2)
    size = stream.tell()
    if size > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(413, 'PDF vượt giới hạn dung lượng')
    stream.seek(0)
    if stream.read(5) != b'%PDF-':
        raise HTTPException(415, 'Tệp không có định dạng PDF')
    stream.seek(max(0, size - 2048))
    if not stream.read().rstrip().endswith(b'%%EOF'):
        raise HTTPException(400, 'PDF bị cắt cụt hoặc có dữ liệu sau EOF')
    stream.seek(0)
    # MIME is advisory only; parser and bytes decide acceptance.
    worker = Path(__file__).with_name('pdf_worker.py')
    command = [sys.executable, str(worker), str(settings.PDF_CPU_SECONDS),
               str(settings.PDF_MEMORY_MB * 1024 * 1024), str(settings.PDF_MAX_OBJECTS), str(settings.PDF_MAX_DEPTH)]
    temp_root = REPOSITORY / 'data' / 'tmp'
    if temp_root.is_symlink():
        raise HTTPException(503, 'Thư mục tạm không an toàn')
    temp_root.mkdir(mode=0o700, exist_ok=True)
    process = subprocess.Popen(command, stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               env={**os.environ, 'TMPDIR': str(REPOSITORY / 'data' / 'tmp')})
    ACTIVE_PARSER_PIDS.add(process.pid)
    monitor = psutil.Process(process.pid)
    started = time.monotonic()
    deadline = started + settings.PDF_TIMEOUT_SECONDS
    peak_rss = 0
    cpu_seconds = 0.0
    reason = "worker_exit"
    rejected = False
    try:
        while process.poll() is None:
            try:
                rss = monitor.memory_info().rss
                peak_rss = max(peak_rss, rss)
                cpu = monitor.cpu_times()
                cpu_seconds = cpu.user + cpu.system
                over_memory = rss > settings.PDF_MEMORY_MB * 1024 * 1024
            except psutil.NoSuchProcess:
                break
            if time.monotonic() > deadline or over_memory:
                rejected = True
                reason = "rss_limit" if over_memory else "wall_timeout"
                process.kill()
                break
            time.sleep(0.01)
        output, _ = process.communicate(timeout=1)
        try:
            result = json.loads(output) if len(output) <= 4096 else {}
            ok = isinstance(result, dict) and set(result) <= {"ok", "diagnostics"} and result.get("ok") is True
            diagnostics = result.get("diagnostics", {}) if isinstance(result, dict) else {}
        except (ValueError, TypeError):
            ok, diagnostics = False, {}
        if rejected or process.returncode != 0 or not ok:
            number = -process.returncode if process.returncode < 0 else None
            # Explicitly copy safe numeric/enum diagnostics; never log raw output.
            stage = diagnostics.get("stage") if isinstance(diagnostics, dict) else None
            if stage not in {"bootstrap", "limits", "import", "spool", "parse", "traverse", "complete"}:
                stage = "unknown"
            worker_cpu = diagnostics.get("cpu_seconds") if isinstance(diagnostics, dict) else None
            logger.warning("PDF rejected reason=%s signal=%s returncode=%s stage=%s "
                           "cpu_sample_seconds=%.6f worker_cpu_seconds=%s wall_seconds=%.6f "
                           "peak_rss_sample_bytes=%d input_bytes=%d cpu_budget=%d wall_budget=%.3f pid=%d",
                           reason, signal.Signals(number).name if number else "none", process.returncode,
                           stage, cpu_seconds, worker_cpu if isinstance(worker_cpu, (int, float)) else None,
                           time.monotonic() - started, peak_rss, size, settings.PDF_CPU_SECONDS,
                           settings.PDF_TIMEOUT_SECONDS, process.pid)
            raise HTTPException(400, 'PDF không hợp lệ, có nội dung chủ động hoặc vượt giới hạn xử lý')
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        ACTIVE_PARSER_PIDS.discard(process.pid)
        if process.stdout:
            process.stdout.close()
        stream.seek(0)
    return size


def validate_pdf(stream: BinaryIO, filename: str, mime: str | None) -> int:
    if not _PARSER_SLOTS.acquire(blocking=False):
        raise HTTPException(503, 'Bộ kiểm tra PDF đang bận; vui lòng thử lại')
    try:
        return _validate_pdf(stream, filename, mime)
    finally:
        _PARSER_SLOTS.release()
