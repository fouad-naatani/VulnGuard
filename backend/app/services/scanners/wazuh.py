"""
Wazuh scanner integration.

Agents are retrieved from the Wazuh Manager API.
Vulnerabilities are retrieved from the Wazuh Indexer/OpenSearch.
"""

from __future__ import annotations

from typing import Any

import httpx

from app.core.config import settings

from app.services.scanners.base import (
    BaseScanner,
    Finding,
    LogCallback,
    ProgressCallback,
    ScannerError,
    ScanResult,
)

from app.utils.severity import (
    normalise_severity,
    severity_from_cvss,
)


class WazuhScanner(BaseScanner):
    """
    Retrieve vulnerabilities from Wazuh Indexer.

    target is the Wazuh agent ID, for example:
        000
        001
        002
    """

    name = "wazuh"

    def __init__(
        self,
        indexer_url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify_ssl: bool | None = None,
    ) -> None:

        self.indexer_url = (
            indexer_url or settings.WAZUH_INDEXER_URL
        ).rstrip("/")

        self.username = (
            username or settings.WAZUH_INDEXER_USER
        )

        self.password = (
            password or settings.WAZUH_INDEXER_PASSWORD
        )

        self.verify_ssl = (
            settings.WAZUH_INDEXER_VERIFY_SSL
            if verify_ssl is None
            else verify_ssl
        )

        self.index = settings.WAZUH_VULNERABILITY_INDEX

    async def run(
        self,
        target: str,
        log: LogCallback,
        progress: ProgressCallback,
    ) -> ScanResult:

        # ------------------------------------------------------------
        # Validate configuration
        # ------------------------------------------------------------

        if not self.indexer_url:
            raise ScannerError(
                "Wazuh Indexer is not configured. "
                "Set WAZUH_INDEXER_URL."
            )

        if not self.username:
            raise ScannerError(
                "Wazuh Indexer username is not configured. "
                "Set WAZUH_INDEXER_USER."
            )

        if not self.password:
            raise ScannerError(
                "Wazuh Indexer password is not configured. "
                "Set WAZUH_INDEXER_PASSWORD."
            )

        # ------------------------------------------------------------
        # Build the CORRECT URL
        # ------------------------------------------------------------

        search_url = (
            f"{self.indexer_url}/{self.index}/_search"
        )

        await log(
            "info",
            f"Connecting to Wazuh Indexer at {self.indexer_url}"
        )

        await log(
            "info",
            f"Searching vulnerabilities for agent {target}"
        )

        await progress(10)

        # ------------------------------------------------------------
        # Elasticsearch / OpenSearch query
        # ------------------------------------------------------------

        query = {
            "size": 2000,
            "query": {
                "term": {
                    "agent.id": target
                }
            },
        }

        # ------------------------------------------------------------
        # Request
        # ------------------------------------------------------------

        try:

            async with httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=60.0,
            ) as client:

                response = await client.post(
                    search_url,
                    auth=(
                        self.username,
                        self.password,
                    ),
                    headers={
                        "Content-Type": "application/json"
                    },
                    json=query,
                )

        except httpx.HTTPError as exc:

            raise ScannerError(
                f"Unable to connect to Wazuh Indexer: {exc}"
            ) from exc

        # ------------------------------------------------------------
        # Check HTTP status
        # ------------------------------------------------------------

        if response.status_code != httpx.codes.OK:

            raise ScannerError(
                "Wazuh Indexer vulnerability request failed: "
                f"HTTP {response.status_code}: "
                f"{response.text}"
            )

        # ------------------------------------------------------------
        # Parse response
        # ------------------------------------------------------------

        try:
            payload = response.json()

        except ValueError as exc:

            raise ScannerError(
                "Wazuh Indexer returned invalid JSON."
            ) from exc

        await progress(60)

        hits = (
            payload
            .get("hits", {})
            .get("hits", [])
        )

        total = (
            payload
            .get("hits", {})
            .get("total", {})
            .get("value", len(hits))
        )

        await log(
            "info",
            f"Wazuh Indexer returned {total} "
            f"vulnerabilities for agent {target}"
        )

        # ------------------------------------------------------------
        # Convert Wazuh findings to VulnGuard findings
        # ------------------------------------------------------------

        findings: list[Finding] = []

        for hit in hits:

            source = hit.get("_source", {})

            try:

                finding = self._to_finding(source)

                if finding:
                    findings.append(finding)

            except Exception as exc:

                await log(
                    "warning",
                    f"Could not parse vulnerability "
                    f"{hit.get('_id')}: {exc}"
                )

        await progress(90)

        # ------------------------------------------------------------
        # Count packages
        # ------------------------------------------------------------

        packages = set()

        for hit in hits:

            source = hit.get("_source", {})

            package = source.get("package") or {}

            package_name = package.get("name")

            if package_name:
                packages.add(package_name)

        await progress(100)

        return ScanResult(
            findings=findings,
            packages_found=len(packages),
        )

    # ================================================================
    # Convert Wazuh document -> VulnGuard Finding
    # ================================================================

    @staticmethod
    def _to_finding(
        source: dict[str, Any],
    ) -> Finding | None:

        vulnerability = (
            source.get("vulnerability") or {}
        )

        package = (
            source.get("package") or {}
        )

        # ------------------------------------------------------------
        # CVE
        # ------------------------------------------------------------

        cve_id = (
            vulnerability.get("id")
            or vulnerability.get("cve")
        )

        if not cve_id:
            return None

        # ------------------------------------------------------------
        # CVSS
        # ------------------------------------------------------------

        score_data = (
            vulnerability.get("score") or {}
        )

        raw_score = score_data.get("base")

        try:
            score = float(raw_score or 0.0)
        except (TypeError, ValueError):
            score = 0.0

        # ------------------------------------------------------------
        # Severity
        # ------------------------------------------------------------

        raw_severity = vulnerability.get("severity")

        severity = normalise_severity(
            raw_severity
        )

        # If Wazuh didn't provide a usable severity,
        # calculate it from CVSS.

        if severity.value == "info" and score > 0:
            severity = severity_from_cvss(score)

        # ------------------------------------------------------------
        # Scanner information
        # ------------------------------------------------------------

        scanner = (
            vulnerability.get("scanner") or {}
        )

        fixed_version = None

        condition = scanner.get("condition")

        if condition:
            fixed_version = condition

        # ------------------------------------------------------------
        # References
        # ------------------------------------------------------------

        references: list[str] = []

        reference = vulnerability.get("reference")

        if reference:
            references.append(reference)

        scanner_reference = scanner.get("reference")

        if scanner_reference:
            references.append(scanner_reference)

        # ------------------------------------------------------------
        # Description
        # ------------------------------------------------------------

        description = (
            vulnerability.get("description")
            or "No description provided by Wazuh."
        )

        # ------------------------------------------------------------
        # Finding
        # ------------------------------------------------------------

        return Finding(
            cve_id=cve_id,

            severity=severity,

            title=description,

            description=description,

            cvss_score=score,

            package_name=package.get("name"),

            installed_version=package.get("version"),

            fixed_version=fixed_version,

            remediation=(
                "Apply the vendor security update "
                "reported by Wazuh."
            ),

            references=references[:20],
        )