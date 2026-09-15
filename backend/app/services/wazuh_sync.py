"""
Synchronize real Wazuh agents and vulnerabilities into VulnGuard.

Source:
    Wazuh API      -> agents
    OpenSearch     -> vulnerability inventory

Destination:
    PostgreSQL     -> assets, scans, vulnerabilities
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import httpx

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.asset import Asset, AgentStatus
from app.models.scan import Scan, ScannerType, ScanStatus
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityStatus,
    Severity,
)


class WazuhSyncError(Exception):
    """Raised when Wazuh synchronization fails."""


class WazuhSync:
    def __init__(self) -> None:
        self.wazuh_url = settings.WAZUH_API_URL.rstrip("/")
        self.wazuh_user = settings.WAZUH_API_USER
        self.wazuh_password = settings.WAZUH_API_PASSWORD

        self.opensearch_url = settings.OPENSEARCH_URL.rstrip("/")
        self.opensearch_user = settings.OPENSEARCH_USER
        self.opensearch_password = settings.OPENSEARCH_PASSWORD

    async def authenticate(self, client: httpx.AsyncClient) -> str:
        response = await client.post(
            f"{self.wazuh_url}/security/user/authenticate",
            auth=(self.wazuh_user, self.wazuh_password),
        )

        response.raise_for_status()

        data = response.json()

        token = data.get("data", {}).get("token")

        if not token:
            raise WazuhSyncError("Wazuh token not returned")

        return token

    async def get_agents(
        self,
        client: httpx.AsyncClient,
        token: str,
    ) -> list[dict[str, Any]]:

        response = await client.get(
            f"{self.wazuh_url}/agents",
            headers={
                "Authorization": f"Bearer {token}",
            },
            params={
                "limit": 500,
            },
        )

        response.raise_for_status()

        return response.json().get("data", {}).get(
            "affected_items",
            [],
        )

    async def get_vulnerabilities(
        self,
        client: httpx.AsyncClient,
        agent_id: str,
    ) -> list[dict[str, Any]]:

        query = {
            "size": 2000,
            "query": {
                "term": {
                    "agent.id": agent_id
                }
            }
        }

        response = await client.post(
            f"{self.opensearch_url}/wazuh-states-vulnerabilities-*/_search",
            auth=(
                self.opensearch_user,
                self.opensearch_password,
            ),
            json=query,
        )

        response.raise_for_status()

        data = response.json()

        return [
            hit.get("_source", {})
            for hit in data.get("hits", {}).get("hits", [])
        ]
    # ------------------------------------------------------------------
    # WAZUH AUTHENTICATION
    # ------------------------------------------------------------------

    async def authenticate_wazuh(
        self,
        client: httpx.AsyncClient,
    ) -> str:

        response = await client.post(
            f"{self.wazuh_url}/security/user/authenticate",
            auth=(
                self.wazuh_user,
                self.wazuh_password,
            ),
        )

        if response.status_code != 200:
            raise WazuhSyncError(
                f"Wazuh authentication failed: "
                f"HTTP {response.status_code}: {response.text}"
            )

        data = response.json()

        token = (
            data
            .get("data", {})
            .get("token")
        )

        if not token:
            raise WazuhSyncError(
                "Wazuh authentication response does not contain a token."
            )

        return token

    # ------------------------------------------------------------------
    # GET AGENTS
    # ------------------------------------------------------------------

    async def get_agents(
        self,
        client: httpx.AsyncClient,
        token: str,
    ) -> list[dict[str, Any]]:

        response = await client.get(
            f"{self.wazuh_url}/agents",
            headers={
                "Authorization": f"Bearer {token}",
            },
            params={
                "select": (
                    "id,name,ip,status,"
                    "os_name,os_version,"
                    "version,lastKeepAlive"
                ),
                "limit": 1000,
            },
        )

        if response.status_code != 200:
            raise WazuhSyncError(
                f"Unable to retrieve Wazuh agents: "
                f"HTTP {response.status_code}: {response.text}"
            )

        payload = response.json()

        return (
            payload
            .get("data", {})
            .get("affected_items", [])
        )

    # ------------------------------------------------------------------
    # OPENSEARCH VULNERABILITIES
    # ------------------------------------------------------------------

    async def get_vulnerabilities(
        self,
        client: httpx.AsyncClient,
        agent_id: str | None = None,
    ) -> list[dict[str, Any]]:

        query: dict[str, Any]

        if agent_id:
            query = {
                "term": {
                    "agent.id": agent_id,
                }
            }
        else:
            query = {
                "match_all": {}
            }

        body = {
            "size": 10000,
            "query": query,
        }

        response = await client.post(
            f"{self.opensearch_url}/wazuh-states-vulnerabilities-*/_search",
            auth=(
                self.opensearch_user,
                self.opensearch_password,
            ),
            headers={
                "Content-Type": "application/json",
            },
            json=body,
        )

        if response.status_code != 200:
            raise WazuhSyncError(
                f"OpenSearch vulnerability request failed: "
                f"HTTP {response.status_code}: {response.text}"
            )

        payload = response.json()

        hits = (
            payload
            .get("hits", {})
            .get("hits", [])
        )

        return [
            hit.get("_source", {})
            for hit in hits
        ]

    # ------------------------------------------------------------------
    # AGENT -> ASSET
    # ------------------------------------------------------------------

    async def upsert_asset(
        self,
        db: AsyncSession,
        agent: dict[str, Any],
    ) -> Asset:

        agent_id = str(agent.get("id", ""))

        hostname = (
            agent.get("name")
            or f"Wazuh Agent {agent_id}"
        )

        ip_address = (
            agent.get("ip")
            or "0.0.0.0"
        )

        os_name = agent.get("os_name") or ""
        os_version = agent.get("os_version") or ""

        operating_system = " ".join(
            value
            for value in [os_name, os_version]
            if value
        )

        status = str(
            agent.get("status", "")
        ).lower()

        if status == "active":
            agent_status = AgentStatus.ONLINE

        elif status in {
            "disconnected",
            "never_connected",
        }:
            agent_status = AgentStatus.OFFLINE

        else:
            agent_status = AgentStatus.OFFLINE

        # We use the Wazuh agent ID as a tag because your Asset model
        # currently doesn't have a wazuh_agent_id column.
        wazuh_tag = f"wazuh-agent:{agent_id}"

        result = await db.execute(
            select(Asset).where(
                Asset.tags.contains(wazuh_tag)
            )
        )

        asset = result.scalar_one_or_none()

        if asset is None:

            asset = Asset(
                hostname=hostname,
                ip_address=ip_address,
                operating_system=operating_system or None,
                owner="Wazuh",
                tags=f"wazuh,{wazuh_tag}",
                agent_status=agent_status,
                description=(
                    f"Imported from Wazuh agent {agent_id}"
                ),
            )

            db.add(asset)

        else:

            asset.hostname = hostname
            asset.ip_address = ip_address
            asset.operating_system = (
                operating_system or None
            )
            asset.agent_status = agent_status

        await db.flush()

        return asset

    # ------------------------------------------------------------------
    # VULNERABILITY -> DATABASE
    # ------------------------------------------------------------------

    async def upsert_vulnerability(
        self,
        db: AsyncSession,
        asset: Asset,
        finding: dict[str, Any],
        scan: Scan,
    ) -> Vulnerability | None:

        vulnerability = finding.get(
            "vulnerability",
            {},
        )

        package = finding.get(
            "package",
            {},
        )

        cve_id = vulnerability.get("id")

        if not cve_id:
            return None

        score_data = vulnerability.get(
            "score",
            {},
        )

        score = float(
            score_data.get("base") or 0.0
        )

        severity = self.normalize_severity(
            vulnerability.get("severity"),
            score,
        )

        reference = vulnerability.get(
            "reference"
        )

        scanner_data = vulnerability.get(
            "scanner",
            {},
        )

        remediation = scanner_data.get(
            "condition"
        )

        # Search existing finding for this asset + CVE.
        result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.asset_id == asset.id,
                Vulnerability.cve_id == cve_id,
            )
        )

        existing = result.scalar_one_or_none()

        if existing:

            existing.title = vulnerability.get(
                "description"
            )

            existing.description = vulnerability.get(
                "description"
            )

            existing.severity = severity

            existing.cvss_score = score

            existing.package_name = package.get(
                "name"
            )

            existing.installed_version = package.get(
                "version"
            )

            existing.fixed_version = self.extract_fixed_version(
                remediation
            )

            existing.remediation = remediation

            existing.references = (
                reference or ""
            )

            existing.scan_id = scan.id

            return existing

        new_vulnerability = Vulnerability(
            cve_id=cve_id,

            title=vulnerability.get(
                "description"
            ),

            description=vulnerability.get(
                "description"
            ),

            severity=severity,

            cvss_score=score,

            package_name=package.get(
                "name"
            ),

            installed_version=package.get(
                "version"
            ),

            fixed_version=self.extract_fixed_version(
                remediation
            ),

            remediation=remediation,

            references=reference or "",

            exploit_available=False,

            status=VulnerabilityStatus.OPEN,

            asset_id=asset.id,

            scan_id=scan.id,
        )

        db.add(new_vulnerability)

        return new_vulnerability

    # ------------------------------------------------------------------
    # SEVERITY
    # ------------------------------------------------------------------

    @staticmethod
    def normalize_severity(
        value: Any,
        score: float,
    ) -> Severity:

        if isinstance(value, str):

            value = value.lower().strip()

            mapping = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }

            if value in mapping:
                return mapping[value]

        # Fallback to CVSS
        if score >= 9.0:
            return Severity.CRITICAL

        if score >= 7.0:
            return Severity.HIGH

        if score >= 4.0:
            return Severity.MEDIUM

        if score > 0:
            return Severity.LOW

        return Severity.INFO

    # ------------------------------------------------------------------
    # FIXED VERSION
    # ------------------------------------------------------------------

    @staticmethod
    def extract_fixed_version(
        condition: str | None,
    ) -> str | None:

        if not condition:
            return None

        # Example:
        # Package less than 10.0.19045.7417
        parts = condition.split()

        if parts:
            return parts[-1]

        return None

    # ------------------------------------------------------------------
    # MAIN SYNCHRONIZATION
    # ------------------------------------------------------------------

    async def sync(
        self,
        db: AsyncSession,
    ) -> dict[str, int]:

        statistics = {
            "agents": 0,
            "assets_created_or_updated": 0,
            "scans": 0,
            "vulnerabilities_created_or_updated": 0,
        }

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=60.0,
        ) as client:

            print("[WAZUH] Authenticating...")

            token = await self.authenticate_wazuh(
                client
            )

            print("[OK] Wazuh authentication successful")

            print("[WAZUH] Retrieving agents...")

            agents = await self.get_agents(
                client,
                token,
            )

            print(
                f"[OK] Wazuh returned {len(agents)} agents"
            )

            statistics["agents"] = len(agents)

            for index, agent in enumerate(
                agents,
                start=1,
            ):

                agent_id = str(
                    agent.get("id")
                )

                agent_name = agent.get(
                    "name",
                    f"Agent {agent_id}",
                )

                print(
                    f"[{index}/{len(agents)}] "
                    f"Agent {agent_id} - {agent_name}"
                )

                try:

                    asset = await self.upsert_asset(
                        db,
                        agent,
                    )

                    statistics[
                        "assets_created_or_updated"
                    ] += 1

                    # Get only this agent's vulnerabilities.
                    findings = await self.get_vulnerabilities(
                        client,
                        agent_id,
                    )

                    print(
                        f"    [WAZUH] "
                        f"{len(findings)} vulnerabilities"
                    )

                    # Create a scan representing this synchronization.
                    scan = Scan(
                        name=(
                            f"Wazuh synchronization - "
                            f"{agent_name}"
                        ),
                        scanner=ScannerType.WAZUH,
                        target=agent_id,
                        status=ScanStatus.RUNNING,
                        progress=0,
                        asset_id=asset.id,
                        started_at=datetime.now(
                            timezone.utc
                        ),
                    )

                    db.add(scan)

                    await db.flush()

                    statistics["scans"] += 1

                    for finding in findings:

                        vulnerability = (
                            await self.upsert_vulnerability(
                                db,
                                asset,
                                finding,
                                scan,
                            )
                        )

                        if vulnerability:
                            statistics[
                                "vulnerabilities_created_or_updated"
                            ] += 1

                    scan.status = ScanStatus.COMPLETED
                    scan.progress = 100
                    scan.packages_found = len(
                        {
                            item.get("package", {}).get(
                                "name"
                            )
                            for item in findings
                            if item.get(
                                "package", {}
                            ).get("name")
                        }
                    )

                    scan.finished_at = datetime.now(
                        timezone.utc
                    )

                    asset.last_scan_at = scan.finished_at

                    await db.commit()

                except Exception as exc:

                    await db.rollback()

                    print(
                        f"    [ERROR] Agent {agent_id}: "
                        f"{exc}"
                    )

        return statistics