import secrets
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.core.database import get_db
from backend.app.schemas.auth import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    TokenResponse,
    MessageResponse,
)
from backend.app.services.auth_service import AuthService
from backend.app.auth.dependencies import get_current_user, verify_csrf
from backend.app.models.user import User

router = APIRouter(prefix="", tags=["Authentication"])


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    csrf_token: Optional[str] = None
) -> None:
    """Helper to set secure HTTP cookies for session and token management."""
    if not csrf_token:
        csrf_token = secrets.token_hex(32)

    # 1. Access Token Cookie (HttpOnly)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        path="/",
        domain=settings.COOKIE_DOMAIN
    )

    # 2. Refresh Token Cookie (HttpOnly, restricted path)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/api/v1/auth",
        domain=settings.COOKIE_DOMAIN
    )

    # 3. CSRF Token Cookie (Readable by JS for Double Submit Cookie pattern)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=settings.COOKIE_SECURE,
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
        path="/",
        domain=settings.COOKIE_DOMAIN
    )


def _clear_auth_cookies(response: Response) -> None:
    """Helper to clear all authentication cookies."""
    response.delete_cookie(key="access_token", path="/", domain=settings.COOKIE_DOMAIN)
    response.delete_cookie(key="refresh_token", path="/api/v1/auth", domain=settings.COOKIE_DOMAIN)
    response.delete_cookie(key="csrf_token", path="/", domain=settings.COOKIE_DOMAIN)


@router.post(
    "/auth/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account"
)
def register(
    req: UserRegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Registers a new standard user account (role=USER).
    Validates email format, password strength, and uniqueness.
    """
    user = AuthService.register_user(db, req)
    return user


@router.post(
    "/auth/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="User login with email and password"
)
def login(
    req: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticates user, sets HttpOnly cookies, and returns token payload.
    Implements timing attack protection and brute-force account lockout.
    """
    user_agent = request.headers.get("user-agent")
    client_ip = request.client.host if request.client else None

    user = AuthService.authenticate_user(db, req.email, req.password)
    access_token, refresh_token = AuthService.create_session(
        db, user, user_agent=user_agent, ip_address=client_ip
    )

    _set_auth_cookies(response, access_token, refresh_token)

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post(
    "/auth/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Rotate session using refresh token"
)
def refresh_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Exchanges a valid refresh token for a new access token and rotated refresh token.
    Detects token reuse and terminates all sessions upon security violations.
    """
    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh:
        # Fallback to authorization header or custom header if cookie not used
        raw_refresh = request.headers.get("X-Refresh-Token")

    if not raw_refresh:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required in cookie or header"
        )

    user_agent = request.headers.get("user-agent")
    client_ip = request.client.host if request.client else None

    new_access, new_refresh, user = AuthService.rotate_session(
        db, raw_refresh, user_agent=user_agent, ip_address=client_ip
    )

    _set_auth_cookies(response, new_access, new_refresh)

    return TokenResponse(
        access_token=new_access,
        token_type="bearer",
        user=UserResponse.model_validate(user)
    )


@router.post(
    "/auth/logout",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout current session"
)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Revokes the current session and clears authentication cookies.
    """
    raw_refresh = request.cookies.get("refresh_token")
    if raw_refresh:
        AuthService.revoke_session(db, raw_refresh)

    _clear_auth_cookies(response)
    return MessageResponse(message="Logged out successfully")


@router.post(
    "/auth/logout-all",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(verify_csrf)],
    summary="Logout from all devices"
)
def logout_all(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revokes all active sessions for the current user across all devices.
    Protected with CSRF verification.
    """
    count = AuthService.revoke_all_user_sessions(db, current_user.id)
    _clear_auth_cookies(response)
    return MessageResponse(message=f"Successfully logged out from all devices ({count} sessions terminated)")


@router.get(
    "/users/me",
    response_model=UserResponse,
    status_code=status.HTTP_200_OK,
    summary="Get current user profile"
)
def get_me(current_user: User = Depends(get_current_user)):
    """
    Returns the profile of the currently authenticated user.
    """
    return current_user
