from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from backend.app.core.database import get_db
from backend.app.auth.dependencies import require_role
from backend.app.models.user import User
from backend.app.models.enums import UserRole, UserStatus
from backend.app.schemas.auth import AdminOverviewResponse, UserResponse

router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get(
    "/overview",
    response_model=AdminOverviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Admin overview metrics and user list"
)
def get_admin_overview(
    current_admin: User = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db)
):
    """
    Returns administrative metrics and complete user management overview.
    Strictly restricted to users with role=ADMIN.
    """
    total_users = db.execute(select(func.count(User.id))).scalar() or 0
    active_users = db.execute(select(func.count(User.id)).where(User.status == UserStatus.ACTIVE)).scalar() or 0
    locked_users = db.execute(select(func.count(User.id)).where(User.status == UserStatus.LOCKED)).scalar() or 0
    admin_users = db.execute(select(func.count(User.id)).where(User.role == UserRole.ADMIN)).scalar() or 0

    all_users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()

    return AdminOverviewResponse(
        total_users=total_users,
        active_users=active_users,
        locked_users=locked_users,
        admin_users=admin_users,
        users=[UserResponse.model_validate(u) for u in all_users]
    )
