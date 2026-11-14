import logging
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
    deadline = time.monotonic() + settings.PDF_TIMEOUT_SECONDS
    rejected = False
    try:
        while process.poll() is None:
            try:
                over_memory = monitor.memory_info().rss > settings.PDF_MEMORY_MB * 1024 * 1024
            except psutil.NoSuchProcess:
                break
            if time.monotonic() > deadline or over_memory:
                rejected = True
                process.kill()
                break
            time.sleep(0.01)
        output, _ = process.communicate(timeout=1)
        if rejected or process.returncode != 0 or output.strip() != b'{"ok": true}':
            logger.warning('PDF rejected: malformed, active content, encrypted, or parser budget exceeded')
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
