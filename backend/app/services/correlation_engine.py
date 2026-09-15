"""Wazuh <-> Nessus correlation engine.

VulnGuard ingests findings from several scanners into the same
``vulnerabilities`` table. Each finding is linked to the ``scans`` row that
produced it, and every scan carries a ``scanner`` (TRIVY / WAZUH / NESSUS).

This module cross-references findings reported by an **agent-based** source
(Wazuh) against findings reported by a **network/credentialed** source
(Nessus) for the same asset. A CVE observed by both engines is a strong,
cross-validated signal: two independent detection methods agree the host is
exposed, which is exactly the kind of noise-reduction a SOC wants from a
correlation engine.

No new database tables are introduced: correlation is computed on demand
from the existing ``Scan`` and ``Vulnerability`` rows, so it works for any
asset that has at least one Wazuh-sourced and one Nessus-sourced finding
(see ``seed.py::seed_demo_nessus_data`` for a ready-to-use demo dataset on
the ``172.20.10.2`` / "dell" host).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.asset import Asset
from app.models.scan import Scan, ScannerType
from app.models.vulnerability import Severity, Vulnerability
from app.utils.severity import SEVERITY_ORDER

#: The two engines the correlation report cross-references.
CORRELATED_SCANNERS = (ScannerType.WAZUH, ScannerType.NESSUS)


# ============================================================================
# DATA STRUCTURES
# ============================================================================


@dataclass(slots=True)
class ScannerObservation:
    """One scanner's view of a single CVE on a single asset."""

    scanner: ScannerType
    vulnerability_id: int
    severity: Severity
    cvss_score: float
    title: str | None
    package_name: str | None
    scan_id: int | None
    scan_name: str | None
    detected_at: datetime | None


@dataclass(slots=True)
class CorrelatedFinding:
    """A CVE reported by *both* Wazuh and Nessus for the same asset."""

    cve_id: str
    severity: Severity
    max_cvss: float
    wazuh: ScannerObservation
    nessus: ScannerObservation

    @property
    def confidence(self) -> str:
        """Cross-validated findings are always "high confidence"."""
        return "high"


@dataclass(slots=True)
class SingleSourceFinding:
    """A CVE reported by only one of the two correlated scanners."""

    cve_id: str
    severity: Severity
    cvss_score: float
    title: str | None
    package_name: str | None
    scanner: ScannerType


@dataclass(slots=True)
class AssetCorrelation:
    """Correlation result for a single asset."""

    asset_id: int
    hostname: str
    ip_address: str
    matched: list[CorrelatedFinding] = field(default_factory=list)
    wazuh_only: list[SingleSourceFinding] = field(default_factory=list)
    nessus_only: list[SingleSourceFinding] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.matched) + len(self.wazuh_only) + len(self.nessus_only)

    @property
    def critical_high(self) -> list[dict[str, object]]:
        """Flatten every critical/high finding for this asset, tagged by source."""
        rows: list[dict[str, object]] = []
        for item in self.matched:
            if item.severity in (Severity.CRITICAL, Severity.HIGH):
                rows.append(
                    {
                        "cve_id": item.cve_id,
                        "severity": item.severity,
                        "cvss_score": item.max_cvss,
                        "source": "wazuh+nessus",
                    }
                )
        for pool, label in ((self.wazuh_only, "wazuh"), (self.nessus_only, "nessus")):
            for item in pool:
                if item.severity in (Severity.CRITICAL, Severity.HIGH):
                    rows.append(
                        {
                            "cve_id": item.cve_id,
                            "severity": item.severity,
                            "cvss_score": item.cvss_score,
                            "source": label,
                        }
                    )
        rows.sort(key=lambda row: (SEVERITY_ORDER[row["severity"]], -row["cvss_score"]))
        return rows


@dataclass(slots=True)
class CorrelationReport:
    """Full correlation dataset, ready to be handed to the report renderer."""

    assets: list[AssetCorrelation] = field(default_factory=list)

    @property
    def matched_count(self) -> int:
        return sum(len(item.matched) for item in self.assets)

    @property
    def wazuh_only_count(self) -> int:
        return sum(len(item.wazuh_only) for item in self.assets)

    @property
    def nessus_only_count(self) -> int:
        return sum(len(item.nessus_only) for item in self.assets)

    @property
    def critical_high_count(self) -> int:
        return sum(len(item.critical_high) for item in self.assets)

    @property
    def asset_count(self) -> int:
        return len(self.assets)


# ============================================================================
# QUERIES
# ============================================================================


async def candidate_asset_ids(session: AsyncSession) -> list[int]:
    """Return ids of assets that have findings from *both* Wazuh and Nessus."""

    per_scanner: list[set[int]] = []
    for scanner in CORRELATED_SCANNERS:
        rows = await session.scalars(
            select(Vulnerability.asset_id)
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .where(Scan.scanner == scanner, Vulnerability.asset_id.is_not(None))
            .distinct()
        )
        per_scanner.append({row for row in rows.all() if row is not None})

    if not per_scanner:
        return []

    intersection = per_scanner[0]
    for ids in per_scanner[1:]:
        intersection &= ids

    return sorted(intersection)


async def _asset_scanner_observations(
    session: AsyncSession, asset_id: int
) -> dict[str, dict[ScannerType, ScannerObservation]]:
    """Group every Wazuh/Nessus finding of ``asset_id`` by CVE then scanner."""

    rows = (
        await session.execute(
            select(Vulnerability, Scan)
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .where(
                Vulnerability.asset_id == asset_id,
                Scan.scanner.in_(CORRELATED_SCANNERS),
            )
            .order_by(Vulnerability.created_at.desc())
        )
    ).all()

    grouped: dict[str, dict[ScannerType, ScannerObservation]] = {}

    for vulnerability, scan in rows:
        observation = ScannerObservation(
            scanner=scan.scanner,
            vulnerability_id=vulnerability.id,
            severity=vulnerability.severity,
            cvss_score=vulnerability.cvss_score,
            title=vulnerability.title,
            package_name=vulnerability.package_name,
            scan_id=scan.id,
            scan_name=scan.name,
            detected_at=vulnerability.created_at,
        )
        # First observation wins per (cve, scanner) pair - newest first thanks
        # to the ORDER BY above, which also self-heals if a scanner reported
        # the same CVE more than once.
        grouped.setdefault(vulnerability.cve_id, {}).setdefault(scan.scanner, observation)

    return grouped


def _worse_severity(a: Severity, b: Severity) -> Severity:
    """Return whichever severity is more urgent."""
    return a if SEVERITY_ORDER[a] <= SEVERITY_ORDER[b] else b


async def correlate_asset(session: AsyncSession, asset: Asset) -> AssetCorrelation:
    """Build the Wazuh/Nessus correlation result for a single asset."""

    grouped = await _asset_scanner_observations(session, asset.id)

    result = AssetCorrelation(
        asset_id=asset.id,
        hostname=asset.hostname,
        ip_address=asset.ip_address,
    )

    for cve_id, by_scanner in sorted(grouped.items()):
        wazuh_observation = by_scanner.get(ScannerType.WAZUH)
        nessus_observation = by_scanner.get(ScannerType.NESSUS)

        if wazuh_observation and nessus_observation:
            result.matched.append(
                CorrelatedFinding(
                    cve_id=cve_id,
                    severity=_worse_severity(
                        wazuh_observation.severity, nessus_observation.severity
                    ),
                    max_cvss=max(wazuh_observation.cvss_score, nessus_observation.cvss_score),
                    wazuh=wazuh_observation,
                    nessus=nessus_observation,
                )
            )
        elif wazuh_observation:
            result.wazuh_only.append(
                SingleSourceFinding(
                    cve_id=cve_id,
                    severity=wazuh_observation.severity,
                    cvss_score=wazuh_observation.cvss_score,
                    title=wazuh_observation.title,
                    package_name=wazuh_observation.package_name,
                    scanner=ScannerType.WAZUH,
                )
            )
        elif nessus_observation:
            result.nessus_only.append(
                SingleSourceFinding(
                    cve_id=cve_id,
                    severity=nessus_observation.severity,
                    cvss_score=nessus_observation.cvss_score,
                    title=nessus_observation.title,
                    package_name=nessus_observation.package_name,
                    scanner=ScannerType.NESSUS,
                )
            )

    for pool in (result.matched, result.wazuh_only, result.nessus_only):
        pool.sort(
            key=lambda item: (
                SEVERITY_ORDER[item.severity],
                -(item.max_cvss if isinstance(item, CorrelatedFinding) else item.cvss_score),
            )
        )

    return result


async def build_correlation_report(
    session: AsyncSession, asset_id: int | None = None
) -> CorrelationReport:
    """Build the full correlation dataset.

    ``asset_id=None`` correlates every asset that has both Wazuh and Nessus
    findings. Passing an explicit ``asset_id`` scopes the report to that one
    asset (used by the "single asset" style scope, but for the correlation
    mode).
    """

    if asset_id is not None:
        asset = await session.get(Asset, asset_id)
        if asset is None:
            return CorrelationReport(assets=[])
        return CorrelationReport(assets=[await correlate_asset(session, asset)])

    ids = await candidate_asset_ids(session)
    if not ids:
        return CorrelationReport(assets=[])

    assets = (
        await session.scalars(select(Asset).where(Asset.id.in_(ids)).order_by(Asset.hostname))
    ).all()

    return CorrelationReport(
        assets=[await correlate_asset(session, asset) for asset in assets]
    )


async def list_candidate_assets(session: AsyncSession) -> list[Asset]:
    """Return the assets eligible for a correlation report (for the UI dropdown)."""

    ids = await candidate_asset_ids(session)
    if not ids:
        return []
    return list(
        (
            await session.scalars(
                select(Asset)
                .where(Asset.id.in_(ids))
                .options(selectinload(Asset.scans))
                .order_by(Asset.hostname)
            )
        ).all()
    )
