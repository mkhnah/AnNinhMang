from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import get_current_user
from backend.app.core.database import get_db
from backend.app.models.user import User
from backend.app.schemas.user_lookup import UserLookupItem, UserLookupPage

router = APIRouter(prefix='/users', tags=['Users'])


@router.get('/search', response_model=UserLookupPage)
def search_users(
    response: Response,
    q: str = Query(min_length=2, max_length=255),
    limit: int = Query(20, ge=1, le=50),
    offset: int = Query(0, ge=0, le=2**31 - 1),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = q.strip().casefold()
    if len(query) < 2:
        raise HTTPException(422, 'Enter at least two characters')
    # Treat wildcard characters as literal search text, never as a directory dump.
    pattern = '%' + query.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
    fold = func.unicode_casefold if db.get_bind().dialect.name == 'sqlite' else func.lower
    condition = or_(*(fold(column).like(pattern, escape='\\') for column in (User.id, User.full_name, User.email)))
    total = db.scalar(select(func.count()).select_from(User).where(condition)) or 0
    rows = db.scalars(select(User).where(condition)
        .order_by(fold(User.full_name), User.id).limit(limit).offset(offset)).all()
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Referrer-Policy'] = 'no-referrer'
    return UserLookupPage(items=[UserLookupItem.model_validate(row) for row in rows],
        total=total, limit=limit, offset=offset)
