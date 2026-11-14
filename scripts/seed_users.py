#!/usr/bin/env python3
"""
Seed Initial Test Users for Native Testing & Demo
Creates:
- admin@cyber.edu (Role: ADMIN)
- alice@cyber.edu (Role: USER)
- bob@cyber.edu (Role: USER)
"""
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from backend.app.core.database import SessionLocal
from backend.app.models.user import User
from backend.app.models.enums import UserRole, UserStatus
from backend.app.auth.hasher import hash_password

SEED_USERS = [
    {
        "email": "admin@cyber.edu",
        "full_name": "Security Admin",
        "role": UserRole.ADMIN,
        "password": "Admin@Secure2026!"
    },
    {
        "email": "alice@cyber.edu",
        "full_name": "Alice Signer",
        "role": UserRole.USER,
        "password": "Alice@Secure2026!"
    },
    {
        "email": "bob@cyber.edu",
        "full_name": "Bob Verifier",
        "role": UserRole.USER,
        "password": "Bob@Secure2026!"
    }
]

def seed():
    db = SessionLocal()
    try:
        print("[*] Seeding default test users for Phase 1...")
        for u in SEED_USERS:
            existing = db.execute(select(User).where(User.email == u["email"])).scalar_one_or_none()
            if existing:
                print(f"  [-] User {u['email']} already exists. Updating password and ensuring ACTIVE...")
                existing.password_hash = hash_password(u["password"])
                existing.role = u["role"]
                existing.status = UserStatus.ACTIVE
                existing.failed_login_attempts = 0
                existing.locked_until = None
            else:
                user = User(
                    email=u["email"],
                    full_name=u["full_name"],
                    password_hash=hash_password(u["password"]),
                    role=u["role"],
                    status=UserStatus.ACTIVE
                )
                db.add(user)
                print(f"  [+] Created user {u['email']} ({u['role'].value})")
        db.commit()
        print("[✓] Seeding completed successfully.")
    except Exception as e:
        db.rollback()
        print(f"[!] Error seeding users: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()

if __name__ == "__main__":
    seed()
