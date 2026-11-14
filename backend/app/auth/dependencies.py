from typing import Callable, Optional, Tuple
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.orm import Session
from sqlalchemy import select
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.auth.jwt import decode_access_token
from backend.app.models.user import User
from backend.app.models.enums import UserRole, UserStatus

security_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
    bearer_auth: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)
) -> User:
    """
    Resolves authenticated user from JWT token.
    Prioritizes explicit Authorization Bearer header, then falls back to HttpOnly cookie.
    Validates token signature, expiration, and user active status.
    """
    bearer_token = bearer_auth.credentials if bearer_auth else None
    cookie_token = request.cookies.get("access_token")

    if bearer_token:
        token = bearer_token
        auth_source = "bearer"
    elif cookie_token:
        token = cookie_token
        auth_source = "cookie"
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please login.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    try:
        payload = decode_access_token(token)
    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired. Please refresh your session.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload is malformed"
        )

    user = db.execute(select(User).where(User.id == user_id)).scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with this token no longer exists"
        )

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account is {user.status.value.lower()}"
        )

    request.state.auth_source = auth_source
    return user


def require_role(required_role: UserRole) -> Callable:
    """
    Dependency factory that checks if current user has the required role.
    Prevents unauthorized privilege escalation.
    """
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: {required_role.value} privileges required."
            )
        return current_user

    return role_checker


def verify_csrf(request: Request) -> None:
    """
    Protects state-changing requests against CSRF when session uses HttpOnly cookies.
    Checks for custom header or Double Submit Cookie pattern.
    """
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        # If client uses cookie auth, verify CSRF header or custom header
        if "access_token" in request.cookies or "refresh_token" in request.cookies:
            x_requested_with = request.headers.get("X-Requested-With")
            x_csrf_token = request.headers.get("X-CSRF-Token")
            cookie_csrf = request.cookies.get("csrf_token")

            if x_requested_with == "XMLHttpRequest":
                return

            if cookie_csrf and x_csrf_token and cookie_csrf == x_csrf_token:
                return

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF validation failed: Missing or invalid CSRF token/header"
            )
