import os
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator


class Settings(BaseSettings):
    # Environment Mode
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Database Configuration
    DATABASE_URL: str = "sqlite:///./data/db/docsign.db"

    # Storage Configuration
    STORAGE_BACKEND: str = "local"
    LOCAL_STORAGE_PATH: str = "./data/storage/documents"

    MAX_UPLOAD_BYTES: int = Field(20 * 1024 * 1024, ge=1, le=100 * 1024 * 1024)
    VERIFY_MAX_PACKAGE_BYTES: int = Field(512 * 1024, ge=1024, le=1024 * 1024)
    VERIFY_MAX_BODY_BYTES: int = Field(21 * 1024 * 1024 + 65536, ge=65536, le=102 * 1024 * 1024)
    VERIFY_CONCURRENCY: int = Field(2, ge=1, le=4)
    VERIFY_RATE_PER_MINUTE: int = Field(60, ge=1, le=600)
    VERIFY_MAX_TRACKED_IPS: int = Field(1024, ge=1, le=10000)
    PDF_TIMEOUT_SECONDS: float = Field(5.0, gt=0, le=30)
    PDF_CPU_SECONDS: int = Field(3, ge=1, le=10)
    PDF_MEMORY_MB: int = Field(256, ge=64, le=512)
    PDF_MAX_OBJECTS: int = Field(50000, ge=100, le=100000)
    PDF_MAX_DEPTH: int = Field(64, ge=8, le=128)

    # Security Keys
    SECRET_KEY: str = Field(..., description="Application secret key for signing")
    JWT_SECRET_KEY: str = Field(..., description="Secret key for JWT generation and verification")
    JWT_ALGORITHM: str = "HS256"

    # Token Lifetimes
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Cookie Security Settings
    COOKIE_SECURE: bool = False
    COOKIE_SAMESITE: str = "lax"
    COOKIE_DOMAIN: Optional[str] = None

    # CORS Settings
    CORS_ORIGINS: str = "http://localhost:5173"

    # Brute-force & Account Protection
    MAX_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_MINUTES: int = 15

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.CORS_ORIGINS.split(",") if origin.strip()]


settings = Settings()
