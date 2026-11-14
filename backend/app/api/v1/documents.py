from functools import lru_cache
from uuid import UUID
from fastapi import APIRouter, Depends, File, Form, UploadFile, Query, HTTPException
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask
from sqlalchemy import select, func
from backend.app.auth.dependencies import get_current_user, verify_csrf
from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.models.document import Document, DocumentVersion
from backend.app.schemas.document import DocumentResponse, DocumentList, VersionResponse, UploadResponse
from backend.app.services.document_service import create_version, owned_document, owned_version, verified_file, lock_version
from backend.app.storage.local import LocalStorageService

router = APIRouter(prefix='/documents', tags=['Documents'], dependencies=[Depends(verify_csrf)])


@lru_cache
def get_storage():
    if settings.STORAGE_BACKEND != 'local':
        raise RuntimeError('Only local storage is supported in Phase 2; MinIO is deferred')
    return LocalStorageService(settings.LOCAL_STORAGE_PATH)


def upload_response(version):
    return UploadResponse(**VersionResponse.model_validate(version).model_dump(), version_id=version.id)


@router.post('', response_model=UploadResponse, status_code=201)
def upload_document(file: UploadFile = File(...), title: str | None = Form(None, max_length=255), user=Depends(get_current_user), db=Depends(get_db), storage=Depends(get_storage)):
    try:
        return upload_response(create_version(db, storage, user.id, file, title=title))
    finally:
        file.file.close()


@router.get('', response_model=DocumentList)
def list_documents(limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(get_current_user), db=Depends(get_db)):
    predicate = Document.owner_id == user.id
    return {'items': db.scalars(select(Document).where(predicate).order_by(Document.updated_at.desc(), Document.id).limit(limit).offset(offset)).all(),
            'total': db.scalar(select(func.count()).select_from(Document).where(predicate)), 'limit': limit, 'offset': offset}


@router.get('/limits')
def upload_limits(user=Depends(get_current_user)):
    return {'max_upload_bytes': settings.MAX_UPLOAD_BYTES}


@router.get('/{document_id}', response_model=DocumentResponse)
def detail(document_id: UUID, user=Depends(get_current_user), db=Depends(get_db)):
    return owned_document(db, document_id, user.id)


@router.get('/{document_id}/versions', response_model=list[VersionResponse])
def versions(document_id: UUID, limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0), user=Depends(get_current_user), db=Depends(get_db)):
    owned_document(db, document_id, user.id)
    return db.scalars(select(DocumentVersion).where(DocumentVersion.document_id == str(document_id)).order_by(DocumentVersion.version_no.desc()).limit(limit).offset(offset)).all()


@router.post('/{document_id}/versions', response_model=UploadResponse, status_code=201)
def upload_version(document_id: UUID, file: UploadFile = File(...), user=Depends(get_current_user), db=Depends(get_db), storage=Depends(get_storage)):
    try:
        return upload_response(create_version(db, storage, user.id, file, document_id=document_id))
    finally:
        file.file.close()


@router.get('/{document_id}/versions/{version_id}', response_model=VersionResponse)
def version_detail(document_id: UUID, version_id: UUID, user=Depends(get_current_user), db=Depends(get_db)):
    return owned_version(db, document_id, version_id, user.id)


@router.post('/{document_id}/versions/{version_id}/ready', response_model=VersionResponse)
def ready(document_id: UUID, version_id: UUID, user=Depends(get_current_user), db=Depends(get_db), storage=Depends(get_storage)):
    return lock_version(db, storage, document_id, version_id, user.id)


@router.get('/{document_id}/versions/{version_id}/download')
def download(document_id: UUID, version_id: UUID, user=Depends(get_current_user), db=Depends(get_db), storage=Depends(get_storage)):
    version = owned_version(db, document_id, version_id, user.id)
    source = verified_file(storage, version)

    def chunks():
        try:
            while chunk := source.read(65536):
                yield chunk
        finally:
            source.close()

    # Server-generated attachment name, no user-supplied header interpolation.
    return StreamingResponse(chunks(), media_type='application/pdf', background=BackgroundTask(source.close), headers={
        'Content-Disposition': f'attachment; filename="document-{version.document_id}-v{version.version_no}.pdf"',
        'Content-Length': str(version.file_size_bytes), 'X-Content-Type-Options': 'nosniff',
        'Cache-Control': 'private, no-store',
    })
