from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import get_current_user, verify_csrf
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.schemas.key import (
    ChallengeCreateRequest,
    ChallengeResponse,
    KeyRegisterRequest,
    PublicKeyResponse,
)
from backend.app.services.key_service import KeyService

router = APIRouter(
    prefix="/keys",
    tags=["Key Management"],
    dependencies=[Depends(verify_csrf)]
)


@router.post("/challenge", response_model=ChallengeResponse, status_code=status.HTTP_201_CREATED)
def create_challenge(
    req: ChallengeCreateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> ChallengeResponse:
    """
    Sinh Signing Challenge tạm thời (TTL 5 phút) để client thực hiện Proof-of-Possession.
    Ràng buộc chặt chẽ với user_id, mục đích REGISTER_KEY và thuật toán dự kiến.
    """
    return KeyService.create_signing_challenge(db=db, user_id=current_user.id, req=req)


@router.post("", response_model=PublicKeyResponse, status_code=status.HTTP_201_CREATED)
def register_public_key(
    req: KeyRegisterRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> PublicKeyResponse:
    """
    Xác minh Proof-of-Possession (PoP) và đăng ký Public Key chuẩn SPKI vào hệ thống.
    - Server tự parse và tính toán SHA-256 fingerprint trên SPKI DER.
    - Kiểm tra kích thước RSA đúng 3072 bits.
    - Xác minh chữ ký RSA-PSS trên canonicalized payload.
    - Tiêu thụ challenge (chống replay attack).
    """
    return KeyService.register_public_key(db=db, user_id=current_user.id, req=req)


@router.get("/my", response_model=List[PublicKeyResponse])
def list_my_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> List[PublicKeyResponse]:
    """
    Lấy danh sách các Public Key của người dùng hiện tại kèm fingerprint và trạng thái ACTIVE/REVOKED.
    Ngăn chặn IDOR (chỉ trả về khóa thuộc quyền sở hữu của user đang xác thực).
    """
    return KeyService.list_my_keys(db=db, user_id=current_user.id)


@router.post("/{key_id}/revoke", response_model=PublicKeyResponse)
def revoke_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> PublicKeyResponse:
    """
    Thu hồi Public Key của người dùng hiện tại (chuyển trạng thái sang REVOKED, ghi nhận revoked_at).
    Khóa bị thu hồi sẽ không thể dùng để tạo chữ ký mới.
    """
    return KeyService.revoke_key(db=db, user_id=current_user.id, key_id=key_id)
