from typing import Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from backend.app.auth.dependencies import get_current_user, security_bearer, verify_csrf
from backend.app.core.database import get_db
from backend.app.core.config import settings
from backend.app.schemas.verify import VerificationReportRequest, VerificationReportResponse, VerificationResultResponse
from backend.app.services.verification_service import VerificationService

router = APIRouter(prefix="/verify", tags=["Verification"])

@router.post('/upload',response_model=VerificationResultResponse)
def verify_independent_upload(
    request: Request, file: UploadFile = File(...), package: Optional[UploadFile] = File(None),
    package_file: Optional[UploadFile] = File(None), package_json: Optional[str] = Form(None),
    certificate_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
):
    # Sync endpoint: FastAPI runs blocking parsing/hash/crypto/SQLite in a worker thread.
    admission = request.state.verify_admission
    admission.start_job()
    try:
        sources = sum(value is not None for value in (package,package_file,package_json))
        if sources != 1:
            raise HTTPException(400,"Provide exactly one signature package source")
        upload = package if package is not None else package_file
        if upload is not None:
            content = upload.file.read(settings.VERIFY_MAX_PACKAGE_BYTES + 1)
            if len(content) > settings.VERIFY_MAX_PACKAGE_BYTES:
                raise HTTPException(413,"Signature package exceeds 512KB limit")
            try:
                raw = content.decode('utf-8')
            except UnicodeDecodeError:
                raise HTTPException(400,"Signature package must be UTF-8")
        else:
            raw = package_json
            if len(raw.encode('utf-8')) > settings.VERIFY_MAX_PACKAGE_BYTES:
                raise HTTPException(413,"Signature package exceeds 512KB limit")
        certificate = None
        if certificate_file is not None:
            content = certificate_file.file.read(16385)
            if len(content) > 16384:
                raise HTTPException(413, 'Certificate exceeds 16KB')
            try:
                certificate = content.decode('utf-8')
            except UnicodeError:
                raise HTTPException(422, 'Certificate must be PEM') from None
        return VerificationService.verify_independent_package(db,file.file,file.filename or 'document.pdf',raw, certificate_override=certificate)
    finally:
        admission.finish_job()


def optional_user(request: Request, db: Session = Depends(get_db),
                  bearer: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)):
    if bearer or request.cookies.get('access_token'):
        return get_current_user(request,db,bearer)
    return None

@router.post('/report',response_model=VerificationReportResponse,dependencies=[Depends(verify_csrf)])
def generate_verification_report(req: VerificationReportRequest, db: Session = Depends(get_db), user=Depends(optional_user)):
    return VerificationService.generate_verification_report(req.receipt_id,db,user.id if user else None)
