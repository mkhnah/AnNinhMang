import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import select, update

from backend.app.core.config import settings
from backend.app.auth.hasher import hash_password, verify_password, needs_rehash, dummy_verify
from backend.app.auth.jwt import (
    create_access_token,
    generate_secure_token,
    hash_token,
    utc_now,
)
from backend.app.models.user import User
from backend.app.models.session import AuthSession
from backend.app.models.enums import UserRole, UserStatus
from backend.app.schemas.auth import UserRegisterRequest
from backend.app.services.audit_service import append_audit, request_context

logger = logging.getLogger(__name__)


class AuthService:
    @staticmethod
    def register_user(db: Session, req: UserRegisterRequest) -> User:
        """
        Registers a new user account with default role USER.
        Prevents duplicate emails and hashes password using Argon2id.
        """
        existing = db.execute(select(User).where(User.email == req.email)).scalar_one_or_none()
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email is already registered"
            )

        hashed = hash_password(req.password)

        new_user = User(
            email=req.email,
            full_name=req.full_name,
            password_hash=hashed,
            role=UserRole.USER,  # Always force default role USER on public registration
            status=UserStatus.ACTIVE,
            failed_login_attempts=0
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        logger.info("New user registered successfully: %s", new_user.email)
        return new_user

    @staticmethod
    def authenticate_user(db: Session, email: str, password: str) -> User:
        """
        Authenticates user with email and password.
        Implements account lockout and dummy verify to prevent account enumeration / timing attacks.
        """
        now = utc_now()
        user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()

        if not user:
            # Mitigation for Timing Attack / Account Enumeration
            dummy_verify()
            append_audit(db, "USER_LOGIN", target_type="USER", status="FAILURE",
                         details={"reason": "INVALID_CREDENTIALS", "http_status": 401})
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )

        # Check if disabled
        if user.status == UserStatus.DISABLED:
            append_audit(db, "USER_LOGIN", actor_id=user.id, target_type="USER", target_id=user.id,
                         status="FAILURE", details={"reason": "DISABLED", "http_status": 403})
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Account has been disabled. Please contact administrator."
            )

        # Check temporary lockout
        if user.locked_until:
            # Handle naive datetime from sqlite by replacing tzinfo if needed
            locked_until_utc = user.locked_until
            if locked_until_utc.tzinfo is None:
                locked_until_utc = locked_until_utc.replace(tzinfo=timezone.utc)

            if now < locked_until_utc:
                remaining_seconds = int((locked_until_utc - now).total_seconds())
                minutes = (remaining_seconds // 60) + 1
                append_audit(db, "USER_LOGIN", actor_id=user.id, target_type="USER", target_id=user.id,
                             status="FAILURE", details={"reason": "LOCKED", "http_status": 423})
                db.commit()
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Account is temporarily locked due to multiple failed login attempts. Please try again after {minutes} minute(s)."
                )
            else:
                # Lockout period expired: reset
                user.locked_until = None
                user.failed_login_attempts = 0
                if user.status == UserStatus.LOCKED:
                    user.status = UserStatus.ACTIVE

        # Verify password
        is_valid = verify_password(password, user.password_hash)

        if not is_valid:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.MAX_LOGIN_ATTEMPTS:
                user.locked_until = now + timedelta(minutes=settings.LOCKOUT_MINUTES)
                user.status = UserStatus.LOCKED
                append_audit(db, "USER_LOGIN", actor_id=user.id, target_type="USER", target_id=user.id,
                             status="FAILURE", details={"reason": "LOCKED", "http_status": 423})
                db.commit()
                logger.warning("Account locked for %s due to %d failed attempts", user.email, user.failed_login_attempts)
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Account has been locked due to {settings.MAX_LOGIN_ATTEMPTS} failed attempts. Please try again after {settings.LOCKOUT_MINUTES} minutes."
                )

            append_audit(db, "USER_LOGIN", actor_id=user.id, target_type="USER", target_id=user.id,
                         status="FAILURE", details={"reason": "INVALID_CREDENTIALS", "http_status": 401})
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )

        # Success: reset failed attempts & update last login
        user.failed_login_attempts = 0
        user.locked_until = None
        user.status = UserStatus.ACTIVE
        user.last_login_at = now

        # Transparent rehash if Argon2id parameters were upgraded
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)

        db.commit()
        db.refresh(user)
        return user

    @staticmethod
    def create_session(
        db: Session,
        user: User,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Creates an authenticated session:
        - Access token (JWT, 15 min)
        - Refresh token (random 256-bit entropy, hashed in DB)
        """
        now = utc_now()
        access_token = create_access_token(user.id, user.role.value)
        raw_refresh_token = generate_secure_token(32)
        token_hashed = hash_token(raw_refresh_token)
        expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        session_record = AuthSession(
            user_id=user.id,
            refresh_token_hash=token_hashed,
            user_agent=user_agent[:500] if user_agent else None,
            ip_address=ip_address[:64] if ip_address else None,
            created_at=now,
            expires_at=expires_at,
            revoked_at=None
        )
        db.add(session_record)
        append_audit(db, "USER_LOGIN", actor_id=user.id, target_type="USER", target_id=user.id,
                     context=request_context(ip_address, user_agent))
        db.commit()
        return access_token, raw_refresh_token

    @staticmethod
    def rotate_session(
        db: Session,
        raw_refresh_token: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None
    ) -> Tuple[str, str, User]:
        """
        Rotates session using Refresh Token Rotation.
        Includes Token Reuse Detection: If an already revoked token is used,
        all active sessions for the user are immediately revoked!
        """
        now = utc_now()
        token_hashed = hash_token(raw_refresh_token)

        session_record = db.execute(
            select(AuthSession).where(AuthSession.refresh_token_hash == token_hashed)
        ).scalar_one_or_none()

        if not session_record:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired session"
            )

        # Token Reuse Detection (Compromise Alert!)
        if session_record.revoked_at is not None:
            logger.critical(
                "TOKEN REUSE DETECTED for user_id=%s. Immediate session revocation triggered!",
                session_record.user_id
            )
            # Revoke all sessions for this user
            db.execute(
                update(AuthSession)
                .where(AuthSession.user_id == session_record.user_id, AuthSession.revoked_at.is_(None))
                .values(revoked_at=now)
            )
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Security violation: Token reuse detected. All sessions have been terminated."
            )

        # Check expiration
        expires_at_utc = session_record.expires_at
        if expires_at_utc.tzinfo is None:
            expires_at_utc = expires_at_utc.replace(tzinfo=timezone.utc)

        if now > expires_at_utc:
            session_record.revoked_at = now
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token has expired. Please log in again."
            )

        # Revoke the used refresh token
        session_record.revoked_at = now

        # Retrieve user
        user = db.execute(select(User).where(User.id == session_record.user_id)).scalar_one_or_none()
        if not user or user.status != UserStatus.ACTIVE:
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive or disabled"
            )

        # Generate new session pair
        new_access_token = create_access_token(user.id, user.role.value)
        new_raw_refresh_token = generate_secure_token(32)
        new_token_hashed = hash_token(new_raw_refresh_token)
        new_expires_at = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

        new_session = AuthSession(
            user_id=user.id,
            refresh_token_hash=new_token_hashed,
            user_agent=user_agent[:500] if user_agent else session_record.user_agent,
            ip_address=ip_address[:64] if ip_address else session_record.ip_address,
            created_at=now,
            expires_at=new_expires_at,
            revoked_at=None
        )
        db.add(new_session)
        db.commit()
        return new_access_token, new_raw_refresh_token, user

    @staticmethod
    def revoke_session(db: Session, raw_refresh_token: str) -> None:
        """Revokes a specific session (Logout)."""
        now = utc_now()
        token_hashed = hash_token(raw_refresh_token)
        session_record = db.execute(
            select(AuthSession).where(AuthSession.refresh_token_hash == token_hashed)
        ).scalar_one_or_none()

        if session_record and session_record.revoked_at is None:
            session_record.revoked_at = now
            db.commit()

    @staticmethod
    def revoke_all_user_sessions(db: Session, user_id: str) -> int:
        """Revokes all active sessions for a user (Logout from all devices)."""
        now = utc_now()
        result = db.execute(
            update(AuthSession)
            .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        db.commit()
        return result.rowcount
