from fastapi import APIRouter

from app.api.routes import (
    assets,
    auth,
    dashboard,
    reports,
    scans,
    settings,
    users,
    vulnerabilities,
    nessus,
)

api_router = APIRouter()

api_router.include_router(auth.router, tags=["auth"])
api_router.include_router(dashboard.router, tags=["dashboard"])
api_router.include_router(assets.router, tags=["assets"])
api_router.include_router(scans.router, tags=["scans"])
api_router.include_router(reports.router, tags=["reports"])
api_router.include_router(users.router, tags=["users"])
api_router.include_router(settings.router, tags=["settings"])
api_router.include_router(vulnerabilities.router , prefix="/vulnerabilities", tags=["vulnerabilities"])
api_router.include_router(nessus.router, prefix="/nessus", tags=["nessus"])