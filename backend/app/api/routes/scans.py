"""Scan job endpoints: create, start, stop, inspect and delete."""
 
from __future__ import annotations
 
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
 
from app.api.deps import get_current_user, require_admin, require_operator
from app.api.serializers import serialize_scan, serialize_scan_detail
from app.db.session import get_session
from app.models.asset import Asset
from app.models.scan import Scan, ScannerType, ScanStatus
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.common import Message, Page
from app.schemas.scan import ScanCreate, ScanDetail, ScanLogRead, ScanRead
from app.services import scan_runner
 
router = APIRouter(prefix="/scans", tags=["scans"])
 
ACTIVE_STATUSES = (ScanStatus.PENDING, ScanStatus.RUNNING)
 
 
async def _vuln_counts(session: AsyncSession, scan_ids: list[int]) -> dict[int, int]:
    """Return ``{scan_id: finding_count}`` for the given scans."""
    if not scan_ids:
        return {}
    rows = await session.execute(
        select(Vulnerability.scan_id, func.count(Vulnerability.id))
        .where(Vulnerability.scan_id.in_(scan_ids))
        .group_by(Vulnerability.scan_id)
    )
    return {row[0]: int(row[1]) for row in rows}
 
 
async def _get_scan_or_404(session: AsyncSession, scan_id: int, with_logs: bool = False) -> Scan:
    """Fetch a scan with its asset (and optionally its logs) or raise 404."""
    options = [selectinload(Scan.asset)]
    if with_logs:
        options.append(selectinload(Scan.logs))
    scan = await session.scalar(select(Scan).options(*options).where(Scan.id == scan_id))
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan
 
 
@router.get("", response_model=Page[ScanRead])
async def list_scans(
    search: str | None = None,
    scan_status: ScanStatus | None = Query(default=None, alias="status"),
    scanner: ScannerType | None = None,
    asset_id: int | None = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> Page[ScanRead]:
    """List scan jobs, most recent first."""
    query = select(Scan).options(selectinload(Scan.asset))
    if search:
        pattern = f"%{search.strip()}%"
        query = query.where(or_(Scan.name.ilike(pattern), Scan.target.ilike(pattern)))
    if scan_status:
        query = query.where(Scan.status == scan_status)
    if scanner:
        query = query.where(Scan.scanner == scanner)
    if asset_id:
        query = query.where(Scan.asset_id == asset_id)
 
    total = await session.scalar(select(func.count()).select_from(query.subquery())) or 0
    query = query.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
    scans = list((await session.scalars(query)).all())
    counts = await _vuln_counts(session, [scan.id for scan in scans])
    return Page[ScanRead](
        items=[serialize_scan(scan, counts.get(scan.id, 0)) for scan in scans],
        total=total,
        page=page,
        page_size=page_size,
    )
 
 
@router.post("", response_model=ScanDetail, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_operator),
) -> ScanDetail:
    """Create a scan job and optionally start it right away."""
    if payload.asset_id is not None and await session.get(Asset, payload.asset_id) is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
 
    scan = Scan(
        name=payload.name,
        scanner=payload.scanner,
        target=payload.target,
        asset_id=payload.asset_id,
        created_by_id=current_user.id,
        status=ScanStatus.PENDING,
    )
    session.add(scan)
    await session.flush()
    scan_id = scan.id
    await session.commit()
 
    if payload.start_immediately:
        scan_runner.start_scan(scan_id)
 
    scan = await _get_scan_or_404(session, scan_id, with_logs=True)
    return serialize_scan_detail(scan)
 
 
@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> ScanDetail:
    """Return a scan with its full log stream (polled by the frontend)."""
    scan = await _get_scan_or_404(session, scan_id, with_logs=True)
    counts = await _vuln_counts(session, [scan.id])
    return serialize_scan_detail(scan, counts.get(scan.id, 0))
 
 
@router.get("/{scan_id}/logs", response_model=list[ScanLogRead])
async def get_scan_logs(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> list[ScanLogRead]:
    """Return only the log lines of a scan."""
    scan = await _get_scan_or_404(session, scan_id, with_logs=True)
    return [ScanLogRead.model_validate(log) for log in scan.logs]
 
 
@router.post("/{scan_id}/start", response_model=ScanDetail)
async def start_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_operator),
) -> ScanDetail:
    """Start (or restart) a scan job."""
    scan = await _get_scan_or_404(session, scan_id, with_logs=True)
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Scan is already running"
        )
    scan_runner.start_scan(scan.id)
    scan.status = ScanStatus.PENDING
    scan.progress = 0
    await session.flush()
    return serialize_scan_detail(scan)
 
 
@router.post("/{scan_id}/stop", response_model=ScanDetail)
async def stop_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_operator),
) -> ScanDetail:
    """Stop a running scan."""
    scan = await _get_scan_or_404(session, scan_id, with_logs=True)
    if scan.status not in ACTIVE_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Scan is not running"
        )
    if not scan_runner.cancel_scan(scan.id):
        # No live task (for example after an application restart): mark it stopped.
        scan.status = ScanStatus.CANCELLED
        await session.flush()
    return serialize_scan_detail(scan)
 
 
@router.delete("/{scan_id}", response_model=Message)
async def delete_scan(
    scan_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_admin),
) -> Message:
    """Delete a scan and every finding it produced."""
    scan = await _get_scan_or_404(session, scan_id)
    scan_runner.cancel_scan(scan.id)
    await session.delete(scan)
    return Message(detail="Scan deleted")