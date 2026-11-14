#!/usr/bin/env python3
"""
Secure Admin Creation Script
Usage:
  python scripts/create_admin.py --email admin@cyber.edu --name "Security Administrator" --password "Admin@Secure2026!"
"""
import sys
import argparse
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from backend.app.core.database import SessionLocal
from backend.app.models.user import User
from backend.app.models.enums import UserRole, UserStatus
from backend.app.auth.hasher import hash_password
from backend.app.schemas.auth import UserRegisterRequest


def create_admin(email: str, full_name: str, password: str) -> None:
    # Validate using Pydantic schema rules
    try:
        UserRegisterRequest(
            email=email,
            full_name=full_name,
            password=password,
            confirm_password=password
        )
    except Exception as e:
        print(f"Validation Error: {e}", file=sys.stderr)
        sys.exit(1)

    db = SessionLocal()
    try:
        existing = db.execute(select(User).where(User.email == email.strip().lower())).scalar_one_or_none()
        if existing:
            print(f"User {email} already exists. Updating role to ADMIN...", file=sys.stderr)
            existing.role = UserRole.ADMIN
            existing.status = UserStatus.ACTIVE
            existing.failed_login_attempts = 0
            existing.locked_until = None
            if password:
                existing.password_hash = hash_password(password)
            db.commit()
            print(f"Successfully upgraded {email} to ADMIN.")
            return

        hashed = hash_password(password)
        admin_user = User(
            email=email.strip().lower(),
            full_name=full_name.strip(),
            password_hash=hashed,
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
            failed_login_attempts=0
        )
        db.add(admin_user)
        db.commit()
        print(f"Admin account created successfully: {email} (Role: ADMIN)")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create an administrative account")
    parser.add_argument("--email", default="admin@cyber.edu", help="Admin email address")
    parser.add_argument("--name", default="Security Admin", help="Full name")
    parser.add_argument("--password", default="Admin@Secure2026!", help="Admin password")
    args = parser.parse_args()

    create_admin(args.email, args.name, args.password)
