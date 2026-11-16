from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import require_role
from backend.app.core.database import get_db
from backend.app.models.enums import UserRole
from backend.app.schemas.audit import DashboardStats
from backend.app.services.dashboard_service import dashboard_stats


router = APIRouter(prefix="/dashboard", tags=["Dashboard"], dependencies=[Depends(require_role(UserRole.ADMIN))])


@router.get("/stats", response_model=DashboardStats)
def get_dashboard_stats(response: Response, db: Session = Depends(get_db)):
    response.headers["Cache-Control"] = "no-store"
    return dashboard_stats(db)
