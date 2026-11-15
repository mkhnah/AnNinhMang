import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.api.v1.documents import get_storage
from backend.app.auth.dependencies import get_current_user, verify_csrf
from backend.app.core.database import get_db
from backend.app.core.verification_limits import Admission, PUBLIC_SLOTS, check_rate_limit
from backend.app.models.document import Document, DocumentVersion
from backend.app.models.share import ShareToken
from backend.app.schemas.share import (
    PublicShareVerificationResponse,
    ShareCreateRequest,
    ShareCreateResponse,
    ShareListItem,
)
from backend.app.services.share_service import create_share, revoke_share, verify_share
from backend.app.storage.base import IStorageService

logger = logging.getLogger("docsign.share")

router = APIRouter(prefix="/shares", tags=["Shares"], dependencies=[Depends(verify_csrf)])


@router.post("", response_model=ShareCreateResponse, status_code=201)
def create(
    request: ShareCreateRequest,
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
    storage: IStorageService = Depends(get_storage),
):
    return create_share(db, user.id, request.version_id, request.expires_in_days, request.label, storage)


@router.delete("/{share_id}", status_code=204)
def revoke(share_id: UUID, user=Depends(get_current_user), db: Session = Depends(get_db)):
    revoke_share(db, user.id, str(share_id))
    return Response(status_code=204)


@router.post("/{share_id}/revoke", status_code=204)
def revoke_legacy_path(share_id: UUID, user=Depends(get_current_user), db: Session = Depends(get_db)):
    revoke_share(db, user.id, str(share_id))
    return Response(status_code=204)


@router.get("", response_model=list[ShareListItem])
def list_shares(
    document_id: str | None = None,
    version_id: str | None = None,
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = (
        select(ShareToken)
        .join(DocumentVersion, ShareToken.version_id == DocumentVersion.id)
        .join(Document, DocumentVersion.document_id == Document.id)
        .where(Document.owner_id == user.id)
    )
    if version_id:
        query = query.where(ShareToken.version_id == version_id)
    elif document_id:
        query = query.where(DocumentVersion.document_id == document_id)

    tokens = db.scalars(query.order_by(ShareToken.created_at.desc()).limit(limit).offset(offset)).all()
    now = datetime.now(timezone.utc)
    items = []
    for t in tokens:
        exp_utc = t.expires_at.replace(tzinfo=timezone.utc) if t.expires_at.tzinfo is None else t.expires_at
        if t.revoked_at is not None:
            st = "REVOKED"
        elif exp_utc <= now:
            st = "EXPIRED"
        else:
            st = "ACTIVE"
        items.append(
            ShareListItem(
                id=t.id,
                version_id=t.version_id,
                created_at=t.created_at,
                expires_at=t.expires_at,
                revoked_at=t.revoked_at,
                label=t.label,
                status=st,
            )
        )
    return items


public_router = APIRouter(prefix="/verify", tags=["Public Verification"])


@public_router.get("/share/{token}", response_model=PublicShareVerificationResponse)
def public_verify(
    token: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    storage: IStorageService = Depends(get_storage),
):
    client_ip = request.client.host if request.client else "unknown"
    check_rate_limit(client_ip)
    if not PUBLIC_SLOTS.acquire(blocking=False):
        return Response(
            content='{"detail":"Verification jobs busy"}',
            status_code=503,
            media_type="application/json",
            headers={"Retry-After": "1", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )
    admission = Admission(PUBLIC_SLOTS)
    admission.start_job()
    try:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Referrer-Policy"] = "no-referrer"
        return verify_share(db, token, storage, client_ip)
    finally:
        admission.finish_job()
