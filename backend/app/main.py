import time
import tempfile
from backend.app.storage.local import LocalStorageService, REPOSITORY
from backend.app.core.upload_limit import UploadLimitMiddleware
import logging
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from backend.app.core.config import settings
from backend.app.api.v1 import auth, admin, documents, keys

logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("docsign.app")

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
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Process-Time"] = f"{process_time:.4f}s"

    if settings.COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# Include API Routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(documents.router, prefix="/api/v1")
app.include_router(keys.router, prefix="/api/v1")


@app.get("/health", tags=["Health"])
def health_check():
    """Health check endpoint providing deployment mode status."""
    return {
        "status": "healthy",
        "mode": "native-macos",
        "database": "sqlite" if settings.DATABASE_URL.startswith("sqlite") else "postgres",
        "phase": "3-client-side-keys"
    }
