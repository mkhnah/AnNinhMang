from datetime import datetime, timezone
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import require_role
from backend.app.core.database import get_db
from backend.app.crypto.jcs import parse_strict_json
from backend.app.models.audit import AuditLog
from backend.app.models.enums import UserRole
from backend.app.schemas.audit import AuditChainResponse, AuditLogPage
from backend.app.services.audit_service import (
    DETAIL_FIELDS, begin_read_snapshot, sanitize_details, verify_audit_chain,
)


router = APIRouter(prefix="/audit", tags=["Audit"], dependencies=[Depends(require_role(UserRole.ADMIN))])


def utc_query(value):
    if value is None:
        return None
    if value.tzinfo is None:
        raise HTTPException(422, "Date filters require a timezone")
    return value.astimezone(timezone.utc)


def audit_response(row):
    details = {}
    valid = False
    try:
        if row.action in DETAIL_FIELDS and len(row.details_json) <= 8192:
            parsed = parse_strict_json(row.details_json)
            if isinstance(parsed, dict):
                details = sanitize_details(row.action, parsed)
                valid = details == parsed
    except (ValueError, TypeError, UnicodeError, RecursionError):
        pass
    return {
        **{column.name: getattr(row, column.name) for column in AuditLog.__table__.columns
           if column.name not in {"id", "details_json", "created_at"}},
        "id": str(row.id), "created_at": row.created_at.replace(tzinfo=timezone.utc),
        "details": details, "details_valid": valid,
    }


@router.get("/logs", response_model=AuditLogPage)
def list_audit_logs(
    response: Response,
    action: str | None = Query(None, max_length=40),
    status: str | None = Query(None, pattern="^(SUCCESS|FAILURE|DENIED)$"),
    actor_id: str | None = Query(None, max_length=36, pattern="^[A-Za-z0-9_-]+$"),
    target_id: str | None = Query(None, max_length=36, pattern="^[A-Za-z0-9_-]+$"),
    client_ip: str | None = Query(None, max_length=45),
    since: datetime | None = None, until: datetime | None = None,
    limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=2**63 - 1),
    snapshot_id: int | None = Query(None, ge=0, le=2**63 - 1),
    db: Session = Depends(get_db),
):
    response.headers["Cache-Control"] = "no-store"
    if action is not None and action not in DETAIL_FIELDS:
        raise HTTPException(422, "Unknown audit action")
    if client_ip is not None:
        try:
            client_ip = str(ipaddress.ip_address(client_ip))
        except ValueError:
            raise HTTPException(422, "Invalid peer IP address") from None
    since, until = utc_query(since), utc_query(until)
    if since and until and since > until:
        raise HTTPException(422, "Start date must precede end date")
    begin_read_snapshot(db)
    current = db.scalar(select(func.max(AuditLog.id))) or 0
    anchor = min(snapshot_id, current) if snapshot_id is not None else current
    predicates = [AuditLog.id <= anchor]
    for column, value in ((AuditLog.action, action), (AuditLog.status, status), (AuditLog.actor_id, actor_id),
                          (AuditLog.target_id, target_id), (AuditLog.client_ip, client_ip)):
        if value is not None:
            predicates.append(column == value)
    if since is not None:
        predicates.append(AuditLog.created_at >= since)
    if until is not None:
        predicates.append(AuditLog.created_at <= until)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*predicates))
    rows = db.scalars(select(AuditLog).where(*predicates).order_by(AuditLog.id.desc()).limit(limit).offset(offset))
    return {"items": [audit_response(row) for row in rows], "total": total, "limit": limit,
            "offset": offset, "snapshot_id": str(anchor)}


@router.get("/verify-chain", response_model=AuditChainResponse)
def check_audit_chain(response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    result = verify_audit_chain(db)
    return {"valid": result.valid, "checked_entries": result.checked_entries,
            "error_id": str(result.error_id) if result.error_id is not None else None,
            "reason": result.reason, "verified_at": datetime.now(timezone.utc)}
