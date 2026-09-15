"""ORM -> Pydantic serialisation helpers.
 
Keeping the mapping in one place avoids duplicating the derived fields
(``tag_list``, counters, related hostnames) across the route modules.
"""
 
from __future__ import annotations
 
from app.models.asset import Asset
from app.models.scan import Scan
from app.models.vulnerability import Vulnerability
from app.schemas.asset import AssetRead
from app.schemas.scan import ScanDetail, ScanLogRead, ScanRead
from app.schemas.vulnerability import VulnerabilityRead
 
 
def serialize_asset(
    asset: Asset, vulnerability_count: int = 0, critical_count: int = 0
) -> AssetRead:
    """Convert an ``Asset`` ORM row into its API representation."""
    return AssetRead(
        id=asset.id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
        operating_system=asset.operating_system,
        owner=asset.owner,
        tags=asset.tag_list,
        agent_status=asset.agent_status,
        description=asset.description,
        last_scan_at=asset.last_scan_at,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        vulnerability_count=vulnerability_count,
        critical_count=critical_count,
    )
 
 
def serialize_scan(scan: Scan, vulnerability_count: int = 0) -> ScanRead:
    """Convert a ``Scan`` ORM row into its API representation."""
    return ScanRead(
        id=scan.id,
        name=scan.name,
        scanner=scan.scanner,
        target=scan.target,
        status=scan.status,
        progress=scan.progress,
        asset_id=scan.asset_id,
        asset_hostname=scan.asset.hostname if scan.asset else None,
        started_at=scan.started_at,
        finished_at=scan.finished_at,
        duration_seconds=scan.duration_seconds,
        error_message=scan.error_message,
        packages_found=scan.packages_found,
        vulnerability_count=vulnerability_count,
        created_at=scan.created_at,
    )
 
 
def serialize_scan_detail(scan: Scan, vulnerability_count: int = 0) -> ScanDetail:
    """Convert a ``Scan`` row into the detailed representation with logs."""
    base = serialize_scan(scan, vulnerability_count)
    return ScanDetail(
        **base.model_dump(),
        logs=[ScanLogRead.model_validate(log) for log in scan.logs],
    )
 
 
def serialize_vulnerability(vulnerability: Vulnerability) -> VulnerabilityRead:
    """Convert a ``Vulnerability`` ORM row into its API representation."""
    return VulnerabilityRead(
        id=vulnerability.id,
        cve_id=vulnerability.cve_id,
        title=vulnerability.title,
        description=vulnerability.description,
        severity=vulnerability.severity,
        cvss_score=vulnerability.cvss_score,
        cvss_vector=vulnerability.cvss_vector,
        epss_score=vulnerability.epss_score,
        package_name=vulnerability.package_name,
        installed_version=vulnerability.installed_version,
        fixed_version=vulnerability.fixed_version,
        remediation=vulnerability.remediation,
        references=vulnerability.reference_list,
        exploit_available=bool(vulnerability.exploit_available),
        status=vulnerability.status,
        asset_id=vulnerability.asset_id,
        asset_hostname=vulnerability.asset.hostname if vulnerability.asset else None,
        scan_id=vulnerability.scan_id,
        created_at=vulnerability.created_at,
    )