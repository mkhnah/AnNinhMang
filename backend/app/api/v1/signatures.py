from uuid import UUID
from fastapi import APIRouter, Depends, status, Request, HTTPException
from fastapi.routing import APIRoute
from backend.app.crypto.jcs import parse_strict_json
import json
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import get_current_user, verify_csrf
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.api.v1.documents import get_storage
from backend.app.schemas.signature import (
    PrepareSignRequest,
    PrepareSignResponse,
    SignatureSubmitRequest,
    SignatureResponse,
)
from backend.app.schemas.verify import (
    VerificationResultResponse,
    SignaturePackage,
    SignaturePackageV2,
)
from backend.app.services.signature_service import SignatureService
from backend.app.services.verification_service import VerificationService
from backend.app.storage.local import LocalStorageService

class StrictJSONRoute(APIRoute):
    def get_route_handler(self):
        original = super().get_route_handler()
        async def handler(request: Request):
            if request.method == "POST":
                body = await request.body()
                if len(body) > 16384:
                    raise HTTPException(413, "Signature request too large")
                try:
                    parse_strict_json(body.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    raise HTTPException(400, "Invalid JSON syntax")
                except (ValueError, RecursionError):
                    raise HTTPException(422, "Invalid JSON values or duplicate keys")
            return await original(request)
        return handler


router = APIRouter(route_class=StrictJSONRoute, tags=["Signatures"], dependencies=[Depends(verify_csrf)])


@router.post(
    "/documents/{document_id}/versions/{version_id}/prepare-sign",
    response_model=PrepareSignResponse,
    status_code=status.HTTP_200_OK,
    summary="Prepare document version for signing by issuing nonce and signed manifest"
)
def prepare_sign_document_version(
    document_id: UUID,
    version_id: UUID,
    req: PrepareSignRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    storage: LocalStorageService = Depends(get_storage),
):
    return SignatureService.prepare_sign(
        db=db,
        user_id=current_user.id,
        document_id=str(document_id),
        version_id=str(version_id),
        req=req,
        storage=storage,
    )


@router.post(
    "/signatures",
    response_model=SignatureResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit and cryptographically verify detached digital signature"
)
def submit_digital_signature(
    req: SignatureSubmitRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    storage: LocalStorageService = Depends(get_storage),
):
    return SignatureService.submit_signature(
        db=db,
        user_id=current_user.id,
        req=req,
        storage=storage,
    )


@router.get(
    "/documents/{document_id}/versions/{version_id}/signature",
    response_model=SignatureResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve digital signature for a document version"
)
def get_version_signature(
    document_id: UUID,
    version_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return SignatureService.get_signature_for_version(
        db=db,
        user_id=current_user.id,
        document_id=str(document_id),
        version_id=str(version_id),
    )


@router.get(
    "/documents/{document_id}/versions/{version_id}/verify",
    response_model=VerificationResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Multi-dimensional internal verification of a stored document version"
)
def verify_document_version_internal(
    document_id: UUID,
    version_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    storage: LocalStorageService = Depends(get_storage),
):
    return VerificationService.verify_internal(
        db=db,
        user_id=current_user.id,
        document_id=str(document_id),
        version_id=str(version_id),
        storage=storage,
    )


@router.get(
    "/documents/{document_id}/versions/{version_id}/signature-package",
    response_model=SignaturePackage | SignaturePackageV2,
    status_code=status.HTTP_200_OK,
    summary="Export detached signature package for independent third-party verification"
)
def export_document_signature_package(
    document_id: UUID,
    version_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return VerificationService.export_signature_package(
        db=db,
        user_id=current_user.id,
        document_id=str(document_id),
        version_id=str(version_id),
    )
