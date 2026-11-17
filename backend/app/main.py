import time
import tempfile
import re
from backend.app.storage.local import LocalStorageService, REPOSITORY
from backend.app.core.upload_limit import UploadLimitMiddleware
import logging
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.api.v1 import auth, admin, documents, keys, signatures, verify, shares, audit, dashboard
from backend.app.api.v1 import certificates, users

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("docsign.app")


class SensitivePathFilter(logging.Filter):
    _share_path = re.compile(r"(/api/v1/verify/share/)[A-Za-z0-9_-]{43}")

    @classmethod
    def _redact(cls, value):
        return cls._share_path.sub(r"\1<redacted>", value) if isinstance(value, str) else value

    def filter(self, record):
        record.msg = self._redact(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(self._redact(value) for value in record.args)
            elif isinstance(record.args, dict):
                record.args = {key: self._redact(value) for key, value in record.args.items()}
        return True


logging.getLogger("uvicorn.access").addFilter(SensitivePathFilter())

# Multipart spool files stay in the repository, including uploads over 1MB.
tempfile.tempdir = str(LocalStorageService(REPOSITORY / "data" / "tmp").root)

app = FastAPI(
    title="Digital Document Signing & Verification API",
    description="Cybersecurity Capstone API - Research & Development of a Digital Document Signing and Verification System",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None
)

app.add_middleware(UploadLimitMiddleware)

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """Adds essential security headers to every response to protect against common attacks."""
    start_time = time.time()
    response: Response = await call_next(request)
    process_time = time.time() - start_time

    # Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"

    # FIX-P6-05: Ensure public share verification routes enforce no-store and no-referrer
    if request.url.path.startswith(("/api/v1/verify", "/api/v1/certificates", "/api/v1/pki", "/api/v1/admin/pki")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
    else:
        if "Referrer-Policy" not in response.headers:
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    if settings.COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# Include API Routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(users.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(documents.router, prefix="/api/v1")
app.include_router(keys.router, prefix="/api/v1")
app.include_router(signatures.router, prefix="/api/v1")
app.include_router(verify.router, prefix="/api/v1")
app.include_router(shares.router, prefix="/api/v1")
app.include_router(shares.public_router, prefix="/api/v1")
app.include_router(audit.router, prefix="/api/v1")
app.include_router(dashboard.router, prefix="/api/v1")
app.include_router(certificates.router, prefix="/api/v1")
app.include_router(certificates.admin_router, prefix="/api/v1")
from backend.app.api.v1 import pki
app.include_router(pki.router, prefix="/api/v1")
app.include_router(pki.admin_router, prefix="/api/v1")
app.include_router(pki.public_router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint providing deployment mode status."""
    return {
        "status": "healthy",
        "mode": "native-macos",
        "database": "sqlite" if settings.DATABASE_URL.startswith("sqlite") else "postgres",
        "phase": "5-verification-engine"
    }
