"""Report generation, listing and download endpoints."""
 
from __future__ import annotations
 
from pathlib import Path
 
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
 
from app.api.deps import get_current_user, require_operator
from app.db.session import get_session
from app.models.report import Report, ReportStatus
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.common import Message, Page
from app.schemas.report import CorrelationCandidateRead, ReportCreate, ReportRead
from app.services.correlation_engine import build_correlation_report, list_candidate_assets
from app.services.report_generator import generate_correlation_report, generate_report
 
router = APIRouter(prefix="/reports", tags=["reports"])
 
MEDIA_TYPES = {"pdf": "application/pdf", "csv": "text/csv", "json": "application/json"}
 
 
@router.get("", response_model=Page[ReportRead])
async def list_reports(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=200),
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> Page[ReportRead]:
    """List previously generated reports, most recent first."""
    total = await session.scalar(select(func.count(Report.id))) or 0
    rows = (
        await session.scalars(
            select(Report)
            .order_by(Report.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).all()
    return Page[ReportRead](
        items=[ReportRead.model_validate(row) for row in rows],
        total=total,
        page=page,
        page_size=page_size,
    )
 
 
@router.get("/correlation/candidates", response_model=list[CorrelationCandidateRead])
async def get_correlation_candidates(
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> list[CorrelationCandidateRead]:
    """List assets that have findings from both Wazuh and Nessus.

    Used by the report form to populate the target dropdown when the
    "Correlation (Wazuh + Nessus)" scope is selected.
    """
    assets = await list_candidate_assets(session)
    results: list[CorrelationCandidateRead] = []
    for asset in assets:
        correlation = await build_correlation_report(session, asset_id=asset.id)
        summary = correlation.assets[0] if correlation.assets else None
        results.append(
            CorrelationCandidateRead(
                id=asset.id,
                hostname=asset.hostname,
                ip_address=asset.ip_address,
                matched_count=len(summary.matched) if summary else 0,
                wazuh_only_count=len(summary.wazuh_only) if summary else 0,
                nessus_only_count=len(summary.nessus_only) if summary else 0,
                critical_high_count=len(summary.critical_high) if summary else 0,
            )
        )
    return results


@router.post("", response_model=ReportRead, status_code=status.HTTP_201_CREATED)
async def create_report(
    payload: ReportCreate,
    session: AsyncSession = Depends(get_session),
    current_user: User = Depends(require_operator),
) -> ReportRead:
    """Generate a report over all findings, one asset, one scan, or a
    Wazuh/Nessus correlation."""
    if payload.scope == "correlation":
        return await _create_correlation_report(payload, session, current_user)

    query = select(Vulnerability).options(selectinload(Vulnerability.asset))
    if payload.scope == "asset":
        if payload.scope_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="scope_id is required when scope is 'asset'",
            )
        query = query.where(Vulnerability.asset_id == payload.scope_id)
    elif payload.scope == "scan":
        if payload.scope_id is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="scope_id is required when scope is 'scan'",
            )
        query = query.where(Vulnerability.scan_id == payload.scope_id)
 
    findings = list((await session.scalars(query)).all())
 
    report = Report(
        name=payload.name,
        format=payload.format,
        scope=payload.scope,
        scope_id=payload.scope_id,
        created_by_id=current_user.id,
        status=ReportStatus.PENDING,
    )
    session.add(report)
    await session.flush()
 
    try:
        path = generate_report(payload.name, payload.format, findings)
    except Exception as exc:  # pragma: no cover - reported to the user verbatim
        report.status = ReportStatus.FAILED
        report.error_message = str(exc)[:512]
        await session.flush()
        return ReportRead.model_validate(report)
 
    report.file_path = str(path)
    report.file_size = path.stat().st_size
    report.status = ReportStatus.READY
    await session.flush()
    return ReportRead.model_validate(report)


async def _create_correlation_report(
    payload: ReportCreate,
    session: AsyncSession,
    current_user: User,
) -> ReportRead:
    """Generate a Wazuh/Nessus correlation report.

    ``scope_id`` is optional here: ``None`` correlates every asset that has
    findings from both scanners, an explicit asset id scopes the report to
    that single host.
    """
    correlation = await build_correlation_report(session, asset_id=payload.scope_id)

    report = Report(
        name=payload.name,
        format=payload.format,
        scope=payload.scope,
        scope_id=payload.scope_id,
        created_by_id=current_user.id,
        status=ReportStatus.PENDING,
    )
    session.add(report)
    await session.flush()

    try:
        path = generate_correlation_report(payload.name, payload.format, correlation)
    except Exception as exc:  # pragma: no cover - reported to the user verbatim
        report.status = ReportStatus.FAILED
        report.error_message = str(exc)[:512]
        await session.flush()
        return ReportRead.model_validate(report)

    report.file_path = str(path)
    report.file_size = path.stat().st_size
    report.status = ReportStatus.READY
    await session.flush()
    return ReportRead.model_validate(report)


@router.get("/{report_id}/download")
async def download_report(
    report_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> FileResponse:
    """Download the file produced for ``report_id``."""
    report = await session.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if report.status is not ReportStatus.READY or not report.file_path:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Report file is not available"
        )
    path = Path(report.file_path)
    if not path.exists():
        raise HTTPException(
            status_code=status.HTTP_410_GONE, detail="Report file has been removed from disk"
        )
    return FileResponse(
        path,
        media_type=MEDIA_TYPES.get(report.format.value, "application/octet-stream"),
        filename=path.name,
    )
 
 
@router.delete("/{report_id}", response_model=Message)
async def delete_report(
    report_id: int,
    session: AsyncSession = Depends(get_session),
    _: User = Depends(require_operator),
) -> Message:
    """Delete a report entry and its file on disk."""
    report = await session.get(Report, report_id)
    if report is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
    if report.file_path:
        Path(report.file_path).unlink(missing_ok=True)
    await session.delete(report)
    return Message(detail="Report deleted")