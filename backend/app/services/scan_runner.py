"""Background execution of scan jobs.
 
Scans run as asyncio tasks owned by the application process. Each run streams
its log lines and progress into the database so the frontend can poll
``GET /api/scans/{id}`` and render live updates.
"""
 
from __future__ import annotations
 
import asyncio
import logging
 
from sqlalchemy import select
from sqlalchemy.orm import selectinload
 
from app.db.base import utcnow
from app.db.session import AsyncSessionLocal
from app.models.asset import Asset
from app.models.scan import Scan, ScanLog, ScanStatus
from app.models.vulnerability import Vulnerability
from app.services.scanners.base import ScannerError, ScanResult
from app.services.scanners.registry import get_scanner
 
logger = logging.getLogger(__name__)
 
#: Currently running scan tasks, keyed by scan id, used to support cancellation.
_RUNNING_TASKS: dict[int, asyncio.Task[None]] = {}
 
 
def is_running(scan_id: int) -> bool:
    """Return whether a scan task is currently tracked for ``scan_id``."""
    task = _RUNNING_TASKS.get(scan_id)
    return task is not None and not task.done()
 
 
def start_scan(scan_id: int) -> None:
    """Schedule ``scan_id`` for background execution (idempotent)."""
    if is_running(scan_id):
        return
    task = asyncio.create_task(_execute_scan(scan_id), name=f"scan-{scan_id}")
    _RUNNING_TASKS[scan_id] = task
    task.add_done_callback(lambda _t: _RUNNING_TASKS.pop(scan_id, None))
 
 
def cancel_scan(scan_id: int) -> bool:
    """Request cancellation of a running scan. Returns ``True`` when signalled."""
    task = _RUNNING_TASKS.get(scan_id)
    if task is None or task.done():
        return False
    task.cancel()
    return True
 
 
async def shutdown() -> None:
    """Cancel every in-flight scan task; called on application shutdown."""
    for task in list(_RUNNING_TASKS.values()):
        task.cancel()
    if _RUNNING_TASKS:
        await asyncio.gather(*_RUNNING_TASKS.values(), return_exceptions=True)
    _RUNNING_TASKS.clear()
 
 
async def _append_log(scan_id: int, level: str, message: str) -> None:
    """Persist a single log line for ``scan_id`` in its own transaction."""
    async with AsyncSessionLocal() as session:
        session.add(ScanLog(scan_id=scan_id, level=level, message=message[:4000]))
        await session.commit()
 
 
async def _set_progress(scan_id: int, progress: int) -> None:
    """Persist scan progress (clamped to 0-100)."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            scan.progress = max(0, min(100, progress))
            await session.commit()
 
 
async def _execute_scan(scan_id: int) -> None:
    """Run a scan end to end, persisting status, logs and findings."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = ScanStatus.RUNNING
        scan.started_at = utcnow()
        scan.finished_at = None
        scan.error_message = None
        scan.progress = 5
        await session.commit()
        scanner_type, target, asset_id = scan.scanner, scan.target, scan.asset_id
 
    await _append_log(scan_id, "info", f"Scan started with {scanner_type.value} on {target}")
 
    try:
        scanner = get_scanner(scanner_type)
        result = await scanner.run(
            target,
            lambda level, message: _append_log(scan_id, level, message),
            lambda progress: _set_progress(scan_id, progress),
        )
    except asyncio.CancelledError:
        await _finalise_cancelled(scan_id)
        raise
    except ScannerError as exc:
        await _finalise_failed(scan_id, str(exc))
        return
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.exception("Unexpected scanner failure for scan %s", scan_id)
        await _finalise_failed(scan_id, f"Unexpected scanner failure: {exc}")
        return
 
    await _persist_results(scan_id, asset_id, result)
    await _append_log(scan_id, "info", "Scan completed successfully")
 
 
async def _persist_results(scan_id: int, asset_id: int | None, result: ScanResult) -> None:
    """Replace the findings of ``scan_id`` with the freshly produced ones."""
    async with AsyncSessionLocal() as session:
        scan = await session.scalar(
            select(Scan).options(selectinload(Scan.vulnerabilities)).where(Scan.id == scan_id)
        )
        if scan is None:
            return
 
        for existing in list(scan.vulnerabilities):
            await session.delete(existing)
 
        for finding in result.findings:
            session.add(
                Vulnerability(
                    cve_id=finding.cve_id,
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    cvss_score=finding.cvss_score,
                    cvss_vector=finding.cvss_vector,
                    package_name=finding.package_name,
                    installed_version=finding.installed_version,
                    fixed_version=finding.fixed_version,
                    remediation=finding.remediation,
                    references="\n".join(finding.references),
                    exploit_available=finding.exploit_available,
                    asset_id=asset_id,
                    scan_id=scan_id,
                )
            )
 
        scan.status = ScanStatus.COMPLETED
        scan.progress = 100
        scan.finished_at = utcnow()
        scan.packages_found = result.packages_found
 
        if asset_id is not None:
            asset = await session.get(Asset, asset_id)
            if asset is not None:
                asset.last_scan_at = scan.finished_at
 
        await session.commit()
 
 
async def _finalise_failed(scan_id: int, message: str) -> None:
    """Mark a scan as failed with ``message``."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            scan.status = ScanStatus.FAILED
            scan.finished_at = utcnow()
            scan.error_message = message[:2000]
            session.add(ScanLog(scan_id=scan_id, level="error", message=message[:4000]))
            await session.commit()
 
 
async def _finalise_cancelled(scan_id: int) -> None:
    """Mark a scan as cancelled after a stop request."""
    async with AsyncSessionLocal() as session:
        scan = await session.get(Scan, scan_id)
        if scan is not None:
            scan.status = ScanStatus.CANCELLED
            scan.finished_at = utcnow()
            session.add(ScanLog(scan_id=scan_id, level="warning", message="Scan stopped by user"))
            await session.commit()