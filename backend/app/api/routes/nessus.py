"""
Nessus API routes.

Provides endpoints for:
- Checking Nessus connectivity
- Listing Nessus scans
- Getting a specific scan
- Launching a scan
- Stopping a scan
- Deleting a scan
"""

from __future__ import annotations

from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.core.config import settings


router = APIRouter(
    prefix="/nessus",
    tags=["Nessus"],
)


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _nessus_headers() -> dict[str, str]:
    """Build Nessus API authentication headers."""

    if not settings.NESSUS_ACCESS_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nessus access key is not configured.",
        )

    if not settings.NESSUS_SECRET_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Nessus secret key is not configured.",
        )

    return {
        "X-ApiKeys": (
            f"accessKey={settings.NESSUS_ACCESS_KEY};"
            f"secretKey={settings.NESSUS_SECRET_KEY}"
        ),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }


def _nessus_url(path: str = "") -> str:
    """Build a Nessus API URL."""

    base = settings.NESSUS_URL.rstrip("/")

    if not path:
        return base

    return f"{base}/{path.lstrip('/')}"


async def _nessus_request(
    method: str,
    path: str,
    *,
    json: dict[str, Any] | None = None,
) -> Any:
    """Execute an authenticated Nessus API request."""

    url = _nessus_url(path)

    try:
        async with httpx.AsyncClient(
            verify=settings.NESSUS_VERIFY_SSL,
            timeout=settings.NESSUS_TIMEOUT_SECONDS,
        ) as client:

            response = await client.request(
                method,
                url,
                headers=_nessus_headers(),
                json=json,
            )

    except httpx.ConnectError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "Unable to connect to Nessus. "
                f"Check that Nessus is running at {settings.NESSUS_URL}."
            ),
        ) from exc

    except httpx.TimeoutException as exc:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail="Nessus request timed out.",
        ) from exc

    except httpx.RequestError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Nessus request failed: {exc}",
        ) from exc

    try:
        data = response.json()
    except ValueError:
        data = {
            "raw": response.text,
        }

    if not response.is_success:
        detail = data.get("error") if isinstance(data, dict) else None

        raise HTTPException(
            status_code=response.status_code,
            detail=detail or f"Nessus returned HTTP {response.status_code}",
        )

    return data


# ---------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------

class LaunchScanRequest(BaseModel):
    """Request body for launching a Nessus scan."""

    scan_id: int


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------

@router.get("/status")
async def nessus_status(
    current_user=Depends(get_current_user),
):
    """
    Check whether Nessus is reachable.

    GET /api/nessus/status
    """

    data = await _nessus_request(
        "GET",
        "/server/status",
    )

    return {
        "connected": True,
        "nessus": data,
    }


@router.get("/scans")
async def list_nessus_scans(
    current_user=Depends(get_current_user),
):
    """
    Return all Nessus scans.

    GET /api/nessus/scans
    """

    return await _nessus_request(
        "GET",
        "/scans",
    )


@router.get("/scans/{scan_id}")
async def get_nessus_scan(
    scan_id: int,
    current_user=Depends(get_current_user),
):
    """
    Get information about one Nessus scan.

    GET /api/nessus/scans/{scan_id}
    """

    return await _nessus_request(
        "GET",
        f"/scans/{scan_id}",
    )


@router.post("/scans/{scan_id}/launch")
async def launch_nessus_scan(
    scan_id: int,
    current_user=Depends(get_current_user),
):
    """
    Launch an existing Nessus scan.

    POST /api/nessus/scans/{scan_id}/launch
    """

    return await _nessus_request(
        "POST",
        f"/scans/{scan_id}/launch",
    )


@router.post("/scans/{scan_id}/stop")
async def stop_nessus_scan(
    scan_id: int,
    current_user=Depends(get_current_user),
):
    """
    Stop a running Nessus scan.

    POST /api/nessus/scans/{scan_id}/stop
    """

    return await _nessus_request(
        "POST",
        f"/scans/{scan_id}/stop",
    )


@router.delete("/scans/{scan_id}")
async def delete_nessus_scan(
    scan_id: int,
    current_user=Depends(get_current_user),
):
    """
    Delete a Nessus scan.

    DELETE /api/nessus/scans/{scan_id}
    """

    return await _nessus_request(
        "DELETE",
        f"/scans/{scan_id}",
    )


@router.get("/scans/{scan_id}/results")
async def get_nessus_scan_results(
    scan_id: int,
    current_user=Depends(get_current_user),
):
    """
    Get the results/details of a Nessus scan.

    GET /api/nessus/scans/{scan_id}/results
    """

    return await _nessus_request(
        "GET",
        f"/scans/{scan_id}",
    )