"""Document business rules depend only on the storage protocol."""
import errno
import logging
import uuid
from fastapi import HTTPException
from sqlalchemy import select, func, update
from sqlalchemy.exc import SQLAlchemyError
from backend.app.models.document import Document, DocumentVersion, VersionState
from backend.app.models.user import utc_now
from backend.app.crypto.hasher import sha256_stream
from backend.app.storage.base import IStorageService
from backend.app.services.pdf_validator import validate_pdf, sanitize_filename

logger = logging.getLogger('docsign.documents')


def owned_document(db, document_id, owner_id):
    doc = db.scalar(select(Document).where(Document.id == str(document_id), Document.owner_id == owner_id))
    if doc is None:
        raise HTTPException(404, 'Không tìm thấy tài liệu')
    return doc


def owned_version(db, document_id, version_id, owner_id):
    owned_document(db, document_id, owner_id)
    version = db.scalar(select(DocumentVersion).where(DocumentVersion.id == str(version_id), DocumentVersion.document_id == str(document_id)))
    if version is None:
        raise HTTPException(404, 'Không tìm thấy phiên bản')
    return version


def verified_file(storage: IStorageService, version):
    try:
        source = storage.get_file(version.storage_key)
    except FileNotFoundError:
        raise HTTPException(409, 'Tệp lưu trữ không tồn tại; cần khôi phục từ bản sao lưu')
    except (OSError, ValueError):
        raise HTTPException(503, 'Không thể đọc tệp lưu trữ')
    try:
        digest = sha256_stream(source)
        size = source.tell()
        if digest != version.file_sha256 or size != version.file_size_bytes:
            logger.error('Integrity mismatch for version %s', version.id)
            raise HTTPException(409, 'Kiểm tra toàn vẹn thất bại')
        source.seek(0)
        return source
    except BaseException:
        source.close()
        raise


def create_version(db, storage: IStorageService, owner_id, upload, document_id=None, title=None):
    if document_id is not None:
        owned_document(db, document_id, owner_id)
    try:
        size = validate_pdf(upload.file, upload.filename or '', upload.content_type)
    except OSError as error:
        code = 507 if error.errno in (errno.ENOSPC, errno.EDQUOT) else 503
        raise HTTPException(code, 'Không thể xử lý tệp tạm; vui lòng thử lại') from None
    name = sanitize_filename(upload.filename or '')
    saved = False
    key = None
    try:
        if document_id is None:
            doc = Document(id=str(uuid.uuid4()), owner_id=owner_id, title=sanitize_filename(title.strip()) if title and title.strip() else name)
            db.add(doc)
            db.flush()
        else:
            # First write serializes writers in SQLite BEFORE reading MAX(version_no).
            result = db.execute(update(Document).where(Document.id == str(document_id), Document.owner_id == owner_id).values(updated_at=utc_now()))
            if result.rowcount != 1:
                raise HTTPException(404, 'Không tìm thấy tài liệu')
            doc = owned_document(db, document_id, owner_id)
        number = (db.scalar(select(func.max(DocumentVersion.version_no)).where(DocumentVersion.document_id == doc.id)) or 0) + 1
        version_id = str(uuid.uuid4())
        key = f'{doc.id}/v{number}_{version_id}.pdf'
        before = sha256_stream(upload.file)
        upload.file.seek(0)
        storage.save_file(key, upload.file)
        saved = True
        with storage.get_file(key) as stored:
            digest = sha256_stream(stored)
            if digest != before or stored.tell() != size:
                raise HTTPException(409, 'Lỗi toàn vẹn khi lưu PDF')
        version = DocumentVersion(id=version_id, document_id=doc.id, version_no=number,
                                  original_filename=name, file_sha256=digest, storage_key=key,
                                  file_size_bytes=size, state=VersionState.DRAFT)
        db.add(version)
        doc.updated_at = utc_now()
        db.commit()
        return version
    except BaseException as error:
        db.rollback()
        if saved:
            try:
                storage.delete_file(key)
            except OSError:
                logger.critical('Rollback cleanup failed for operation key %s; run storage reconciliation', key)
        if isinstance(error, SQLAlchemyError):
            raise HTTPException(503, 'Không thể lưu metadata; vui lòng thử lại') from None
        if isinstance(error, OSError):
            code = 507 if error.errno in (errno.ENOSPC, errno.EDQUOT) else 503
            raise HTTPException(code, 'Không thể lưu tệp; vui lòng thử lại') from None
        raise


def lock_version(db, storage: IStorageService, document_id, version_id, owner_id):
    version = owned_version(db, document_id, version_id, owner_id)
    with verified_file(storage, version):
        pass
    try:
        result = db.execute(update(DocumentVersion).where(DocumentVersion.id == version.id, DocumentVersion.state == VersionState.DRAFT).values(state=VersionState.READY_TO_SIGN, locked_at=utc_now()))
        if result.rowcount != 1:
            raise HTTPException(409, 'Chỉ có thể khóa phiên bản DRAFT')
        db.commit()
        db.refresh(version)
        return version
    except BaseException as error:
        db.rollback()
        if isinstance(error, SQLAlchemyError):
            raise HTTPException(409, 'Không thể chuyển trạng thái phiên bản') from None
        raise
