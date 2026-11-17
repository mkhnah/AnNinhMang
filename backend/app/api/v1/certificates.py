from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import get_current_user, require_role, verify_csrf
from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.crypto.certificates import load_ca
from backend.app.models.certificate import CertificateAuthority
from backend.app.models.enums import UserRole
from backend.app.schemas.certificate import (
    CertificateChallengeRequest, CertificateChallengeResponse, CertificatePage,
    CertificateProofRequest, CertificateResponse, CertificateRevokeRequest,
)
from backend.app.services import certificate_service


router = APIRouter(prefix="/certificates", tags=["Certificates"], dependencies=[Depends(verify_csrf)])
admin_router = APIRouter(prefix="/admin/pki", tags=["PKI"], dependencies=[Depends(require_role(UserRole.ADMIN))])


@router.post("/challenge", status_code=201, response_model=CertificateChallengeResponse)
def challenge(req: CertificateChallengeRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return certificate_service.create_challenge(db, user.id, req)


@router.post("/issue-for-key", response_model=CertificateResponse, status_code=201)
def issue(req: CertificateProofRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return certificate_service.issue_for_existing_key(db, user.id, req, "ISSUE_CERT")


@router.get("/me", response_model=CertificatePage)
def mine(response: Response, limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=2**63-1),
         key_id: str | None = Query(None, max_length=36),
         user=Depends(get_current_user), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    return certificate_service.list_certificates(db, user.id, limit, offset, key_id)


@router.get("/{certificate_id}", response_model=CertificateResponse)
def detail(certificate_id: str, response: Response, user=Depends(get_current_user), db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    return certificate_service.certificate_response(db, certificate_service.owned_certificate(db, user, certificate_id))


@router.get("/{certificate_id}/download")
def download(certificate_id: str, user=Depends(get_current_user), db: Session = Depends(get_db)):
    cert = certificate_service.owned_certificate(db, user, certificate_id)
    return Response(cert.certificate_pem, media_type="application/x-pem-file", headers={
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Content-Disposition": 'attachment; filename="certificate.pem"',
    })


@router.post("/{certificate_id}/renew", response_model=CertificateResponse, status_code=201)
def renew(certificate_id: str, req: CertificateProofRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    # Proof of ownership always belongs to the owner; ADMIN uses revoke/read APIs.
    cert = certificate_service.owned_certificate(db, user, certificate_id)
    return certificate_service.issue_for_existing_key(db, user.id, req, "RENEW_CERT", cert.id)


@router.post("/{certificate_id}/revoke", response_model=CertificateResponse)
def revoke(certificate_id: str, req: CertificateRevokeRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    return certificate_service.revoke_certificate(db, user, certificate_id, req.reason)


@admin_router.get("/status")
def pki_status(db: Session = Depends(get_db)):
    if not settings.PKI_ENABLED:
        return {"enabled": False, "ready": False, "code": "PKI_DISABLED"}
    ca = load_ca()
    issuer = db.scalar(select(CertificateAuthority).where(CertificateAuthority.fingerprint == ca.fingerprint))
    ready = issuer is None or (issuer.issuance_enabled and issuer.trust_status == "TRUSTED" and issuer.compromised_at is None)
    return {"enabled": True, "ready": ready, "fingerprint": ca.fingerprint,
            "subject": ca.certificate.subject.rfc4514_string(), "not_after": ca.certificate.not_valid_after_utc,
            "code": "READY" if ready else "CA_ISSUANCE_UNAVAILABLE"}


@admin_router.get("/certificates", response_model=CertificatePage)
def admin_certificates(response: Response, user_id: str | None = Query(None, max_length=36),
                       limit: int = Query(20, ge=1, le=100), offset: int = Query(0, ge=0, le=2**63-1),
                       db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    return certificate_service.list_certificates(db, user_id, limit, offset)
