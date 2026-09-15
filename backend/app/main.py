"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from app.api.router import api_router
from app.api.routes.nessus import router as nessus_router
from app.core.config import settings
from app.services import scan_runner
from app.services.report_generator import reports_dir


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Prepare shared resources on startup and stop scan tasks on shutdown."""

    reports_dir()

    logger.info(
        "%s API started in %s mode",
        settings.APP_NAME,
        settings.ENVIRONMENT,
    )

    yield

    await scan_runner.shutdown()


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title=f"{settings.APP_NAME} API",
    description="Enterprise vulnerability management platform API",
    version="1.0.0",
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

print("CORS_ORIGINS =", settings.CORS_ORIGINS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Attach baseline security headers to every response."""

    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )

    return response


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def unhandled_exception_handler(
    _request: Request,
    exc: Exception,
) -> JSONResponse:
    """Return a generic error payload instead of leaking stack traces."""

    logger.exception(
        "Unhandled application error",
        exc_info=exc,
    )

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    """Lightweight liveness probe."""

    return {
        "status": "ok",
        "app": settings.APP_NAME,
    }


# ---------------------------------------------------------------------------
# API routers
# ---------------------------------------------------------------------------

# Existing VulnGuard API
app.include_router(
    api_router,
    prefix=settings.API_PREFIX,
)

# Nessus API
app.include_router(
    nessus_router,
    prefix=settings.API_PREFIX,
)

# ---------------------------------------------------------------------------
# Frontend page routes
# ---------------------------------------------------------------------------
# The frontend is kept in ../frontend while FastAPI exposes clean browser
# routes. Static assets are mounted separately at /assets.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
FRONTEND_DIR = PROJECT_ROOT / "frontend"
PAGES_DIR = FRONTEND_DIR / "pages"

app.mount("/assets", StaticFiles(directory=FRONTEND_DIR / "assets"), name="assets")
# JavaScript modules are imported by browser pages using absolute URLs.
# Expose their source directories at matching URL prefixes.
app.mount("/services", StaticFiles(directory=FRONTEND_DIR / "services"), name="services")
app.mount("/components", StaticFiles(directory=FRONTEND_DIR / "components"), name="components")
app.mount("/utils", StaticFiles(directory=FRONTEND_DIR / "utils"), name="utils")
app.mount("/layout", StaticFiles(directory=FRONTEND_DIR / "layout"), name="layout")

PAGE_FILES = {
    "login": "login.html",
    "dashboard": "dashboard.html",
    "assets": "assets.html",
    "asset-detail": "asset-detail.html",
    "scans": "scans.html",
    "scan-detail": "scan-detail.html",
    "vulnerabilities": "vulnerabilities.html",
    "vulnerability-detail": "vulnerability-detail.html",
    "reports": "reports.html",
    "users": "users.html",
    "settings": "settings.html",
}


@app.get("/", include_in_schema=False)
async def serve_index() -> FileResponse:
    return FileResponse(PROJECT_ROOT / "index.html")


@app.get("/{page}", include_in_schema=False)
async def serve_page(page: str):
    # Keep /api/* and non-page paths out of the frontend fallback.
    if page in PAGE_FILES:
        response = FileResponse(PAGES_DIR / PAGE_FILES[page])
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response
    from fastapi import HTTPException
    raise HTTPException(status_code=404, detail="Page not found")
