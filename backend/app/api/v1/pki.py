from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from sqlalchemy import select, update, case
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import get_current_user, require_role, verify_csrf
from backend.app.core.database import get_db
from backend.app.models.certificate import IdentityReview, CertificateAuthority
from backend.app.models.enums import UserRole
from backend.app.schemas.certificate import (IdentityRequest, IdentityDecision, CertificateVerifyRequest,
    DetachedVerifyRequest, SignaturePackageVerifyRequest, PossessionRequest, PossessionProof, AuthorityUpdate)
from backend.app.services import identity_service
from backend.app.services.pki_verification import inspect_certificate, verify_detached, verify_signature_package
from backend.app.services.audit_service import append_audit
from backend.app.crypto.jcs import parse_strict_json
from fastapi.routing import APIRoute


class PkiJSONRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()
        async def handler(request):
            if request.method == 'POST':
                body = await request.body()
                if len(body) > 1500000:
                    raise HTTPException(413, 'PKI request too large')
                try:
                    parse_strict_json(body.decode())
                except (ValueError, UnicodeError, RecursionError):
                    raise HTTPException(422, 'Invalid PKI JSON') from None
            return await original(request)
        return handler


router = APIRouter(prefix='/pki', tags=['PKI'], dependencies=[Depends(verify_csrf)], route_class=PkiJSONRoute)
admin_router = APIRouter(prefix='/admin/pki', tags=['PKI Admin'],
    dependencies=[Depends(require_role(UserRole.ADMIN)), Depends(verify_csrf)], route_class=PkiJSONRoute)
public_router = APIRouter(prefix='/verify', tags=['PKI Verification'], route_class=PkiJSONRoute)


@router.post('/identity-requests', status_code=201)
def identity_request(req: IdentityRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return identity_service.request_review(db, user.id, req)


@router.get('/identity-requests')
def my_reviews(response: Response, user=Depends(get_current_user), db: Session = Depends(get_db),
               limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=2**63-1)):
    response.headers['Cache-Control'] = 'no-store'
    rows = db.scalars(select(IdentityReview).where(IdentityReview.user_id == user.id)
        .order_by(IdentityReview.created_at.desc()).limit(limit).offset(offset)).all()
    return [identity_service.review_dto(row) for row in rows]


@admin_router.get('/identity-requests')
def pending_reviews(response: Response, db: Session = Depends(get_db),
                    limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=2**63-1)):
    response.headers['Cache-Control'] = 'no-store'
    return [identity_service.review_dto(row) for row in db.scalars(select(IdentityReview)
        .order_by(case((IdentityReview.status == 'PENDING', 0), else_=1), IdentityReview.created_at.desc()).limit(limit).offset(offset))]


@admin_router.post('/identity-requests/{review_id}/decision')
def review_decision(review_id: str, req: IdentityDecision, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return identity_service.decide(db, user.id, review_id, req)


@router.post('/possession/challenge', status_code=201)
def possession_challenge(req: PossessionRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return identity_service.possession_challenge(db, user, req.certificate_id)


@router.post('/possession/verify')
def possession_verify(req: PossessionProof, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return identity_service.verify_possession(db, user, req)


def public_verification(request, response, db, req, signature=False):
    admission = request.state.verify_admission
    admission.start_job()
    try:
        response.headers['Cache-Control'] = 'no-store'
        if isinstance(req, SignaturePackageVerifyRequest):
            result = verify_signature_package(db, req)
        else:
            result = verify_detached(db, req) if signature else inspect_certificate(db, req.certificate_pem)
        append_audit(db, 'CERTIFICATE_VERIFY', target_type='CERTIFICATE',
            status='SUCCESS' if result['verified'] else 'FAILURE',
            details={'fingerprint': result['fingerprint'], 'outcome': 'VALID' if result['verified'] else 'INVALID'})
        db.commit()
        return result
    finally:
        admission.finish_job()


@public_router.post('/certificate')
def verify_certificate(req: CertificateVerifyRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    return public_verification(request, response, db, req)


@public_router.post('/signature')
def verify_signature(req: SignaturePackageVerifyRequest | DetachedVerifyRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    return public_verification(request, response, db, req, True)


@admin_router.get('/authorities')
def authorities(response: Response, db: Session = Depends(get_db)):
    response.headers['Cache-Control'] = 'no-store'
    return [dict(id=ca.id, fingerprint=ca.fingerprint, subject=ca.subject, not_after=ca.not_after,
        issuance_enabled=ca.issuance_enabled, trust_status=ca.trust_status) for ca in db.scalars(
            select(CertificateAuthority).order_by(CertificateAuthority.created_at.desc()).limit(100))]


@admin_router.post('/authorities/{ca_id}')
def update_authority(ca_id: str, req: AuthorityUpdate, user=Depends(get_current_user), db: Session = Depends(get_db)):
    ca = db.get(CertificateAuthority, ca_id, populate_existing=True)
    if ca is None:
        raise HTTPException(404, 'CA unavailable')
    if req.issuance_enabled and req.trust_status != 'TRUSTED':
        raise HTTPException(422, 'Only trusted CA can issue')
    if ca.compromised_at and (req.trust_status != 'COMPROMISED' or req.issuance_enabled):
        raise HTTPException(409, 'CA_COMPROMISE_IRREVERSIBLE')
    try:
        # Conditional update rechecks concurrent compromise and is protected by the DB guard.
        changed = db.execute(update(CertificateAuthority).where(CertificateAuthority.id == ca_id,
            CertificateAuthority.compromised_at.is_(None)).values(trust_status=req.trust_status,
            issuance_enabled=req.issuance_enabled, compromised_at=datetime.now(timezone.utc) if req.trust_status == 'COMPROMISED' else None))
        if changed.rowcount:
            append_audit(db, 'CA_COMPROMISED' if req.trust_status == 'COMPROMISED' else 'CA_ROTATE',
                actor_id=user.id, target_type='CA', target_id=ca_id, details={'fingerprint': ca.fingerprint})
        db.commit()
        return {'updated': True}
    except Exception:
        db.rollback()
        raise
