"""Read-only security metrics and bounded, database-derived alert summaries."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, literal, select, union_all

from backend.app.models.audit import AuditLog
from backend.app.models.document import Document, DocumentVersion, VersionState
from backend.app.models.enums import KeyStatus
from backend.app.models.key import PublicKey
from backend.app.models.verification import VerificationEvent
from backend.app.schemas.verify import VerificationSummaryStatus
from backend.app.services.audit_service import begin_read_snapshot


ALERT_WINDOW_MINUTES = 15
VERIFICATION_FAILURE_THRESHOLD = 3
ALERT_LIMIT = 20
UNSUCCESSFUL_STATUSES = tuple(
    status.value for status in VerificationSummaryStatus if status != VerificationSummaryStatus.VERIFIED
)


def security_alerts(db, now):
    cutoff = now - timedelta(minutes=ALERT_WINDOW_MINUTES)
    principal = case(
        (AuditLog.actor_id.is_not(None), literal("user:") + AuditLog.actor_id),
        else_=literal("ip:") + AuditLog.client_ip,
    )
    identified = (AuditLog.actor_id.is_not(None) | AuditLog.client_ip.is_not(None))
    # A corrupted details column must remain inspectable through the admin UI.
    summary = case(
        (func.json_valid(AuditLog.details_json) == 1, func.json_extract(AuditLog.details_json, "$.summary_status")),
        else_=None,
    )
    recent_verifications = select(
        principal.label("principal"), AuditLog.actor_id, AuditLog.client_ip, AuditLog.created_at,
        summary.label("summary"),
        func.row_number().over(partition_by=principal, order_by=AuditLog.id.desc()).label("position"),
    ).where(
        AuditLog.action == "DOCUMENT_VERIFY", AuditLog.created_at >= cutoff,
        AuditLog.created_at <= now, identified,
    ).cte("recent_verifications")
    failures = select(
        literal("REPEATED_VERIFICATION_FAILURE").label("code"),
        recent_verifications.c.actor_id,
        func.max(recent_verifications.c.client_ip).label("client_ip"),
        func.count().label("count"),
        func.min(recent_verifications.c.created_at).label("first_at"),
        func.max(recent_verifications.c.created_at).label("last_at"),
    ).where(recent_verifications.c.position <= VERIFICATION_FAILURE_THRESHOLD).group_by(
        recent_verifications.c.principal, recent_verifications.c.actor_id,
    ).having(
        func.count() == VERIFICATION_FAILURE_THRESHOLD,
        func.sum(case((recent_verifications.c.summary.in_(UNSUCCESSFUL_STATUSES), 1), else_=0)) == VERIFICATION_FAILURE_THRESHOLD,
    )
    idor = select(
        literal("IDOR_ATTEMPT").label("code"), AuditLog.actor_id,
        func.max(AuditLog.client_ip).label("client_ip"), func.count().label("count"),
        func.min(AuditLog.created_at).label("first_at"), func.max(AuditLog.created_at).label("last_at"),
    ).where(
        AuditLog.action == "ACCESS_DENIED_IDOR", AuditLog.status == "DENIED",
        AuditLog.created_at >= cutoff, AuditLog.created_at <= now, identified,
    ).group_by(principal, AuditLog.actor_id)
    alerts = union_all(failures, idor).subquery()
    total = db.scalar(select(func.count()).select_from(alerts))
    rows = db.execute(select(alerts).order_by(
        alerts.c.last_at.desc(), alerts.c.code, alerts.c.actor_id, alerts.c.client_ip,
    ).limit(ALERT_LIMIT)).mappings().all()
    return rows, total


def dashboard_stats(db):
    begin_read_snapshot(db)
    now = datetime.now(timezone.utc)
    since = now - timedelta(days=30)
    counts = dict(db.execute(select(
        VerificationEvent.summary_status, func.count(),
    ).where(VerificationEvent.created_at >= since, VerificationEvent.created_at <= now)
      .group_by(VerificationEvent.summary_status)).all())
    total = sum(counts.values())
    verified = counts.get("VERIFIED", 0)
    first_day = now.date() - timedelta(days=6)
    daily = db.execute(select(
        func.date(VerificationEvent.created_at).label("day"),
        func.sum(case((VerificationEvent.summary_status == "VERIFIED", 1), else_=0)).label("verified"),
        func.sum(case((VerificationEvent.summary_status != "VERIFIED", 1), else_=0)).label("unsuccessful"),
    ).where(
        VerificationEvent.created_at >= datetime.combine(first_day, datetime.min.time(), timezone.utc),
        VerificationEvent.created_at <= now,
    ).group_by(func.date(VerificationEvent.created_at))).mappings().all()
    by_day = {row["day"]: row for row in daily}
    days = []
    for offset in range(7):
        day = (first_day + timedelta(days=offset)).isoformat()
        row = by_day.get(day, {})
        days.append({"date": day, "verified": row.get("verified", 0), "unsuccessful": row.get("unsuccessful", 0)})
    alerts, alert_total = security_alerts(db, now)
    verification_counts = []
    for status in VerificationSummaryStatus:
        verification_counts.append({"status": status.value, "count": counts.pop(status.value, 0)})
    if counts:
        verification_counts.append({"status": "OTHER", "count": sum(counts.values())})
    return {
        "generated_at": now,
        "total_documents": db.scalar(select(func.count()).select_from(Document)),
        "total_versions": db.scalar(select(func.count()).select_from(DocumentVersion)),
        "signed_versions": db.scalar(select(func.count()).select_from(DocumentVersion).where(DocumentVersion.state == VersionState.SIGNED)),
        "active_keys": db.scalar(select(func.count()).select_from(PublicKey).where(PublicKey.status == KeyStatus.ACTIVE, PublicKey.revoked_at.is_(None))),
        "verification_since": since,
        "verification_total": total,
        "verification_success_rate": round(verified * 100 / total, 2) if total else None,
        "verification_counts": verification_counts,
        "verification_daily": days,
        "alert_window_minutes": ALERT_WINDOW_MINUTES,
        "verification_failure_threshold": VERIFICATION_FAILURE_THRESHOLD,
        "alerts": alerts,
        "alert_total": alert_total,
    }
