"""Dashboard aggregation endpoint."""
 
from __future__ import annotations
 
from datetime import timedelta
 
from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
 
from app.api.deps import get_current_user
from app.api.serializers import serialize_asset, serialize_scan, serialize_vulnerability
from app.db.base import utcnow
from app.db.session import get_session
from app.models.asset import Asset
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.models.vulnerability import Severity, Vulnerability
from app.schemas.dashboard import ChartSeries, DashboardResponse, DashboardStats
 
router = APIRouter(prefix="/dashboard", tags=["dashboard"])
 
#: CVSS buckets displayed by the dashboard histogram.
CVSS_BUCKETS: list[tuple[str, float, float]] = [
    ("0-2", 0.0, 2.0),
    ("2-4", 2.0, 4.0),
    ("4-6", 4.0, 6.0),
    ("6-8", 6.0, 8.0),
    ("8-10", 8.0, 10.01),
]
 
 
@router.get("", response_model=DashboardResponse)
async def get_dashboard(
    session: AsyncSession = Depends(get_session),
    _: User = Depends(get_current_user),
) -> DashboardResponse:
    """Return every figure rendered by the dashboard in a single round trip."""
    severity_rows = await session.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id)).group_by(
            Vulnerability.severity
        )
    )
    by_severity = {severity: int(count) for severity, count in severity_rows}
 
    stats = DashboardStats(
        total_assets=int(await session.scalar(select(func.count(Asset.id))) or 0),
        total_vulnerabilities=sum(by_severity.values()),
        critical=by_severity.get(Severity.CRITICAL, 0),
        high=by_severity.get(Severity.HIGH, 0),
        medium=by_severity.get(Severity.MEDIUM, 0),
        low=by_severity.get(Severity.LOW, 0),
        info=by_severity.get(Severity.INFO, 0),
        running_scans=int(
            await session.scalar(
                select(func.count(Scan.id)).where(
                    Scan.status.in_([ScanStatus.RUNNING, ScanStatus.PENDING])
                )
            )
            or 0
        ),
        finished_scans=int(
            await session.scalar(
                select(func.count(Scan.id)).where(Scan.status == ScanStatus.COMPLETED)
            )
            or 0
        ),
    )
 
    severity_distribution = ChartSeries(
        labels=[severity.value for severity in Severity],
        values=[float(by_severity.get(severity, 0)) for severity in Severity],
    )
 
    cvss_values: list[float] = []
    for _label, low, high in CVSS_BUCKETS:
        count = await session.scalar(
            select(func.count(Vulnerability.id)).where(
                Vulnerability.cvss_score >= low, Vulnerability.cvss_score < high
            )
        )
        cvss_values.append(float(count or 0))
    cvss_distribution = ChartSeries(
        labels=[label for label, _low, _high in CVSS_BUCKETS], values=cvss_values
    )
 
    monthly_scans = await _monthly_scan_history(session)
 
    recent_assets = (
        await session.scalars(select(Asset).order_by(Asset.created_at.desc()).limit(5))
    ).all()
    recent_vulnerabilities = (
        await session.scalars(
            select(Vulnerability)
            .options(selectinload(Vulnerability.asset))
            .order_by(Vulnerability.cvss_score.desc(), Vulnerability.created_at.desc())
            .limit(5)
        )
    ).all()
    recent_scans = (
        await session.scalars(
            select(Scan).options(selectinload(Scan.asset)).order_by(Scan.created_at.desc()).limit(5)
        )
    ).all()
 
    return DashboardResponse(
        stats=stats,
        severity_distribution=severity_distribution,
        cvss_distribution=cvss_distribution,
        monthly_scans=monthly_scans,
        recent_assets=[serialize_asset(asset) for asset in recent_assets],
        recent_vulnerabilities=[serialize_vulnerability(row) for row in recent_vulnerabilities],
        recent_scans=[serialize_scan(scan) for scan in recent_scans],
    )
 
 
async def _monthly_scan_history(session: AsyncSession, months: int = 6) -> ChartSeries:
    """Count scans created during each of the last ``months`` calendar months."""
    now = utcnow()
    labels: list[str] = []
    values: list[float] = []
 
    # Walk backwards month by month, normalising each window to its first day.
    cursor = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    windows: list[tuple[str, object, object]] = []
    for _ in range(months):
        next_month = (cursor + timedelta(days=32)).replace(day=1)
        windows.append((cursor.strftime("%Y-%m"), cursor, next_month))
        cursor = (cursor - timedelta(days=1)).replace(day=1)
 
    for label, start, end in reversed(windows):
        count = await session.scalar(
            select(func.count(Scan.id)).where(Scan.created_at >= start, Scan.created_at < end)
        )
        labels.append(label)
        values.append(float(count or 0))
 
    return ChartSeries(labels=labels, values=values)