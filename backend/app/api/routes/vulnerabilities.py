"""Vulnerability listing, detail and triage endpoints."""
 
from __future__ import annotations
 
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.orm import selectinload
from sqlalchemy.ext.asyncio import AsyncSession
 
from app.api.deps import get_current_user, require_operator
from app.api.serializers import serialize_vulnerability
from app.db.session import get_session
from app.models.user import User
from app.models.vulnerability import Severity, Vulnerability, VulnerabilityStatus
from app.schemas.common import Page
from app.schemas.vulnerability import VulnerabilityRead, VulnerabilityUpdate
 
router = APIRouter()
 
SORTABLE = {
    "cvss_score": Vulnerability.cvss_score,
    "cve_id": Vulnerability.cve_id,
    "severity": Vulnerability.severity,
    "created_at": Vulnerability.created_at,
    "package_name": Vulnerability.package_name,
}
 
 
@router.get("", response_model=Page[VulnerabilityRead])
async def list_vulnerabilities(
    search: str | None = Query(default=None, description="Match CVE, package or title"),
    severity: Severity | None = None,
    vuln_status: VulnerabilityStatus | None = Query(default=None, alias="status"),
    asset_id: int | None = None,
    scan_id: int | None = None,
    min_cvss: float | None = Query(default=None, ge=0, le=10),
    max_cvss: float | None = Query(default=None, ge=0, le=10),
    exploit_available: bool | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    sort_by: str = Query(default="cvss_score"),
    sort_dir: str = Query(default="desc", pattern="^(asc|desc)$"),
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> Page[VulnerabilityRead]:
    """List vulnerabilities with full text search, filters, sorting and pagination."""
    query = select(Vulnerability).options(selectinload(Vulnerability.asset))
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(
            or_(
                Vulnerability.cve_id.ilike(pattern),
                Vulnerability.package_name.ilike(pattern),
                Vulnerability.title.ilike(pattern),
            )
        )
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if vuln_status:
        query = query.where(Vulnerability.status == vuln_status)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if scan_id:
        query = query.where(Vulnerability.scan_id == scan_id)
    if min_cvss is not None:
        query = query.where(Vulnerability.cvss_score >= min_cvss)
    if max_cvss is not None:
        query = query.where(Vulnerability.cvss_score <= max_cvss)
    if exploit_available is not None:
        query = query.where(Vulnerability.exploit_available == exploit_available)
 
    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
 
    column = SORTABLE.get(sort_by, Vulnerability.cvss_score)
    query = query.order_by(column.desc() if sort_dir == "desc" else column.asc())
    query = query.offset((page - 1) * page_size).limit(page_size)
 
    rows = (await session.scalars(query)).all()
    return Page[VulnerabilityRead](
        items=[serialize_vulnerability(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
 
 
@router.get("/{vulnerability_id}", response_model=VulnerabilityRead)
async def get_vulnerability(
    vulnerability_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> VulnerabilityRead:
    """Return every detail known about a single finding."""
    row = await session.scalar(
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
        .where(Vulnerability.id == vulnerability_id)
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    return serialize_vulnerability(row)
 
 
@router.patch("/{vulnerability_id}", response_model=VulnerabilityRead)
async def update_vulnerability(
    vulnerability_id: int,
    payload: VulnerabilityUpdate,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_operator),
) -> VulnerabilityRead:
    """Update the triage status of a finding."""
    row = await session.scalar(
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
        .where(Vulnerability.id == vulnerability_id)
    )
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Vulnerability not found")
    row.status = payload.status
    await session.flush()
    return serialize_vulnerability(row)