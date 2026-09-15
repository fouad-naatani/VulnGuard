"""
Nessus scanner integration.

Creates a Nessus scan dynamically from a target supplied by VulnGuard,
launches it, waits for completion, exports the .nessus results, and
converts CVE findings into VulnGuard Finding objects.
"""

from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET

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
from app.utils.severity import normalise_severity


class NessusScanner(BaseScanner):
    """Scanner implementation for Tenable Nessus."""

    name = "nessus"

    def __init__(
        self,
        base_url: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        verify_ssl: bool | None = None,
    ) -> None:

        self.base_url = (
            base_url or settings.NESSUS_URL
        ).rstrip("/")

        self.access_key = (
            access_key or settings.NESSUS_ACCESS_KEY
        )

        self.secret_key = (
            secret_key or settings.NESSUS_SECRET_KEY
        )

        self.verify_ssl = (
            settings.NESSUS_VERIFY_SSL
            if verify_ssl is None
            else verify_ssl
        )

        self.timeout = settings.NESSUS_TIMEOUT_SECONDS
        self.poll_interval = (
            settings.NESSUS_POLL_INTERVAL_SECONDS
        )
        self.scan_timeout = (
            settings.NESSUS_SCAN_TIMEOUT_SECONDS
        )

        # UUID of the Nessus scan template.
        #
        # You should configure this in .env:
        #
        # NESSUS_TEMPLATE_UUID=...
        #
        self.template_uuid = getattr(
            settings,
            "NESSUS_TEMPLATE_UUID",
            None,
        )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-ApiKeys": (
                f"accessKey={self.access_key};"
                f"secretKey={self.secret_key}"
            ),
        }

    # ------------------------------------------------------------------
    # Main scanner entry point
    # ------------------------------------------------------------------

    async def run(
        self,
        target: str,
        log: LogCallback,
        progress: ProgressCallback,
    ) -> ScanResult:

        if not self.base_url:
            raise ScannerError(
                "Nessus is not configured. "
                "Set NESSUS_URL."
            )

        if not self.access_key or not self.secret_key:
            raise ScannerError(
                "Nessus API credentials are not configured. "
                "Set NESSUS_ACCESS_KEY and "
                "NESSUS_SECRET_KEY."
            )

        target = target.strip()

        if not target:
            raise ScannerError(
                "Nessus target cannot be empty."
            )

        if not self.template_uuid:
            raise ScannerError(
                "NESSUS_TEMPLATE_UUID is not configured. "
                "Create or select a Nessus scan template "
                "and add its UUID to the .env file."
            )

        await log(
            "info",
            f"Connecting to Nessus at {self.base_url}",
        )

        async with httpx.AsyncClient(
            verify=self.verify_ssl,
            timeout=self.timeout,
            headers=self._headers(),
        ) as client:

            # ----------------------------------------------------------
            # 1. Test connection
            # ----------------------------------------------------------

            await self._test_connection(
                client,
                log,
            )

            await progress(5)

            # ----------------------------------------------------------
            # 2. Create Nessus scan
            # ----------------------------------------------------------

            scan_id = await self._create_scan(
                client=client,
                target=target,
                log=log,
            )

            await progress(15)

            # ----------------------------------------------------------
            # 3. Launch Nessus scan
            # ----------------------------------------------------------

            history_id = await self._launch_scan(
                client=client,
                scan_id=scan_id,
                log=log,
            )

            await progress(20)

            # ----------------------------------------------------------
            # 4. Wait for completion
            # ----------------------------------------------------------

            await self._wait_for_completion(
                client=client,
                scan_id=scan_id,
                history_id=history_id,
                log=log,
                progress=progress,
            )

            await log(
                "info",
                f"Nessus scan {scan_id} completed.",
            )

            await progress(75)

            # ----------------------------------------------------------
            # 5. Export results
            # ----------------------------------------------------------

            findings = await self._export_findings(
                client=client,
                scan_id=scan_id,
                history_id=history_id,
                log=log,
            )

            await progress(100)

            await log(
                "info",
                f"Nessus returned {len(findings)} CVE findings.",
            )

            return ScanResult(
                findings=findings,
                packages_found=0,
            )

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    async def _test_connection(
        self,
        client: httpx.AsyncClient,
        log: LogCallback,
    ) -> None:

        response = await client.get(
            f"{self.base_url}/server/status",
        )

        if response.status_code != httpx.codes.OK:
            raise ScannerError(
                "Nessus connection failed: "
                f"HTTP {response.status_code}: "
                f"{response.text}"
            )

        await log(
            "info",
            "Successfully connected to Nessus.",
        )

    # ------------------------------------------------------------------
    # Create scan
    # ------------------------------------------------------------------

    async def _create_scan(
        self,
        client: httpx.AsyncClient,
        target: str,
        log: LogCallback,
    ) -> int:

        scan_name = (
            f"VulnGuard - {target}"
        )

        payload = {
            "uuid": self.template_uuid,
            "settings": {
                "name": scan_name,
                "text_targets": target,
                "enabled": False,
                "launch_now": False,
            },
        }

        await log(
            "info",
            f"Creating Nessus scan for target {target}",
        )

        response = await client.post(
            f"{self.base_url}/scans",
            json=payload,
        )

        if response.status_code not in (
            httpx.codes.OK,
            httpx.codes.CREATED,
        ):
            raise ScannerError(
                "Failed to create Nessus scan: "
                f"HTTP {response.status_code}: "
                f"{response.text}"
            )

        try:
            payload_response = response.json()
        except ValueError as exc:
            raise ScannerError(
                "Nessus returned an invalid JSON response "
                "when creating the scan."
            ) from exc

        scan_id = payload_response.get("scan", {}).get("id")

        if scan_id is None:
            scan_id = payload_response.get("id")

        if scan_id is None:
            raise ScannerError(
                "Nessus created the scan but did not return "
                "a scan ID."
            )

        scan_id = int(scan_id)

        await log(
            "info",
            f"Nessus scan created successfully: ID {scan_id}",
        )

        return scan_id

    # ------------------------------------------------------------------
    # Launch scan
    # ------------------------------------------------------------------

    async def _launch_scan(
        self,
        client: httpx.AsyncClient,
        scan_id: int,
        log: LogCallback,
    ) -> int | None:

        await log(
            "info",
            f"Launching Nessus scan {scan_id}",
        )

        response = await client.post(
            f"{self.base_url}/scans/{scan_id}/launch",
        )

        if response.status_code not in (
            httpx.codes.OK,
            httpx.codes.ACCEPTED,
        ):
            raise ScannerError(
                "Failed to launch Nessus scan: "
                f"HTTP {response.status_code}: "
                f"{response.text}"
            )

        try:
            payload = response.json()
        except ValueError:
            payload = {}

        history_id = payload.get("history_id")

        if history_id is not None:
            history_id = int(history_id)

        await log(
            "info",
            f"Nessus scan {scan_id} launched.",
        )

        return history_id

    # ------------------------------------------------------------------
    # Get latest history
    # ------------------------------------------------------------------

    async def _get_latest_history(
        self,
        client: httpx.AsyncClient,
        scan_id: int,
    ) -> int:

        response = await client.get(
            f"{self.base_url}/scans/{scan_id}",
        )

        if response.status_code != httpx.codes.OK:
            raise ScannerError(
                "Unable to retrieve Nessus scan history: "
                f"HTTP {response.status_code}: "
                f"{response.text}"
            )

        payload = response.json()

        history = payload.get("history", [])

        if not history:
            raise ScannerError(
                "Nessus scan was launched but no history "
                "was returned."
            )

        first = history[0]

        history_id = (
            first.get("history_id")
            or first.get("id")
        )

        if history_id is None:
            raise ScannerError(
                "Nessus history does not contain a history ID."
            )

        return int(history_id)

    # ------------------------------------------------------------------
    # Wait for scan completion
    # ------------------------------------------------------------------

    async def _wait_for_completion(
        self,
        client: httpx.AsyncClient,
        scan_id: int,
        history_id: int | None,
        log: LogCallback,
        progress: ProgressCallback,
    ) -> None:

        elapsed = 0

        while elapsed < self.scan_timeout:

            response = await client.get(
                f"{self.base_url}/scans/{scan_id}",
            )

            if response.status_code != httpx.codes.OK:
                raise ScannerError(
                    "Failed to retrieve Nessus scan status: "
                    f"HTTP {response.status_code}: "
                    f"{response.text}"
                )

            payload = response.json()

            history = payload.get("history", [])

            if not history:
                await asyncio.sleep(
                    self.poll_interval
                )

                elapsed += self.poll_interval
                continue

            current = None

            # If launch returned a history ID, use it.
            if history_id is not None:

                for item in history:

                    item_id = (
                        item.get("history_id")
                        or item.get("id")
                    )

                    if item_id is not None and int(item_id) == int(
                        history_id
                    ):
                        current = item
                        break

            # Otherwise use the newest history entry.
            if current is None:
                current = history[0]

                current_id = (
                    current.get("history_id")
                    or current.get("id")
                )

                if current_id is not None:
                    history_id = int(current_id)

            status = str(
                current.get("status", "")
            ).lower()

            await log(
                "info",
                f"Nessus scan status: {status}",
            )

            # ----------------------------------------------------------
            # Completed
            # ----------------------------------------------------------

            if status in {
                "completed",
                "complete",
            }:
                return

            # ----------------------------------------------------------
            # Failed
            # ----------------------------------------------------------

            if status in {
                "aborted",
                "canceled",
                "cancelled",
                "error",
                "failed",
            }:
                raise ScannerError(
                    "Nessus scan failed with status: "
                    f"{status}"
                )

            # ----------------------------------------------------------
            # Progress
            # ----------------------------------------------------------

            scan_progress = min(
                70,
                20
                + int(
                    elapsed
                    / max(self.scan_timeout, 1)
                    * 50
                ),
            )

            await progress(scan_progress)

            await asyncio.sleep(
                self.poll_interval
            )

            elapsed += self.poll_interval

        raise ScannerError(
            "Nessus scan timed out."
        )

    # ------------------------------------------------------------------
    # Export results
    # ------------------------------------------------------------------

    async def _export_findings(
        self,
        client: httpx.AsyncClient,
        scan_id: int,
        history_id: int | None,
        log: LogCallback,
    ) -> list[Finding]:

        await log(
            "info",
            "Requesting Nessus scan export.",
        )

        params = {}

        if history_id is not None:
            params["history_id"] = history_id

        # IMPORTANT:
        # Nessus export is POST, not GET.
        response = await client.post(
            f"{self.base_url}/scans/{scan_id}/export",
            params=params,
            json={
                "format": "nessus",
            },
        )

        if response.status_code not in (
            httpx.codes.OK,
            httpx.codes.ACCEPTED,
        ):
            raise ScannerError(
                "Failed to request Nessus export: "
                f"HTTP {response.status_code}: "
                f"{response.text}"
            )

        try:
            export_payload = response.json()
        except ValueError as exc:
            raise ScannerError(
                "Nessus returned invalid JSON while "
                "creating the export."
            ) from exc

        file_id = export_payload.get("file")

        if not file_id:
            raise ScannerError(
                "Nessus export did not return a file ID."
            )

        await log(
            "info",
            f"Nessus export created: {file_id}",
        )

        await self._wait_for_export(
            client=client,
            scan_id=scan_id,
            file_id=str(file_id),
        )

        await log(
            "info",
            "Downloading Nessus export.",
        )

        download = await client.get(
            f"{self.base_url}/scans/"
            f"{scan_id}/export/"
            f"{file_id}/download",
        )

        if download.status_code != httpx.codes.OK:
            raise ScannerError(
                "Failed to download Nessus export: "
                f"HTTP {download.status_code}: "
                f"{download.text}"
            )

        return self._parse_nessus_xml(
            download.content
        )

    # ------------------------------------------------------------------
    # Wait for export
    # ------------------------------------------------------------------

    async def _wait_for_export(
        self,
        client: httpx.AsyncClient,
        scan_id: int,
        file_id: str,
    ) -> None:

        elapsed = 0

        while elapsed < self.scan_timeout:

            response = await client.get(
                f"{self.base_url}/scans/"
                f"{scan_id}/export/"
                f"{file_id}/status",
            )

            if response.status_code != httpx.codes.OK:
                raise ScannerError(
                    "Failed to check Nessus export status: "
                    f"HTTP {response.status_code}: "
                    f"{response.text}"
                )

            payload = response.json()

            status = str(
                payload.get("status", "")
            ).lower()

            if status in {
                "ready",
                "completed",
            }:
                return

            if status in {
                "error",
                "failed",
            }:
                raise ScannerError(
                    "Nessus export failed with status: "
                    f"{status}"
                )

            await asyncio.sleep(
                self.poll_interval
            )

            elapsed += self.poll_interval

        raise ScannerError(
            "Nessus export timed out."
        )

    # ------------------------------------------------------------------
    # Parse .nessus XML
    # ------------------------------------------------------------------

    @classmethod
    def _parse_nessus_xml(
        cls,
        content: bytes,
    ) -> list[Finding]:

        findings: list[Finding] = []

        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ScannerError(
                f"Invalid Nessus export: {exc}"
            ) from exc

        for report_host in root.findall(
            ".//ReportHost"
        ):

            host = report_host.attrib.get(
                "name"
            )

            for item in report_host.findall(
                "ReportItem"
            ):

                plugin_id = item.attrib.get(
                    "pluginID"
                )

                plugin_name = item.attrib.get(
                    "pluginName"
                )

                severity_raw = item.attrib.get(
                    "severity",
                    "0",
                )

                try:
                    severity_number = int(
                        severity_raw
                    )
                except (TypeError, ValueError):
                    severity_number = 0

                severity = cls._nessus_severity(
                    severity_number
                )

                cve = cls._text(
                    item,
                    "cve",
                )

                # ------------------------------------------------------
                # Ignore non-CVE findings
                # ------------------------------------------------------

                if not cve:
                    continue

                cvss = cls._float(
                    item,
                    "cvss3_base_score",
                )

                if cvss <= 0:
                    cvss = cls._float(
                        item,
                        "cvss_base_score",
                    )

                description = cls._text(
                    item,
                    "description",
                )

                solution = cls._text(
                    item,
                    "solution",
                )

                synopsis = cls._text(
                    item,
                    "synopsis",
                )

                port = item.attrib.get(
                    "port"
                )

                protocol = item.attrib.get(
                    "protocol"
                )

                references: list[str] = []

                if plugin_id:
                    references.append(
                        f"Nessus plugin: {plugin_id}"
                    )

                if host:
                    references.append(
                        f"Host: {host}"
                    )

                if port:
                    references.append(
                        f"Port: "
                        f"{port}/"
                        f"{protocol or 'tcp'}"
                    )

                findings.append(
                    Finding(
                        cve_id=cve,
                        severity=severity,
                        title=(
                            synopsis
                            or plugin_name
                            or cve
                        ),
                        description=(
                            description
                            or ""
                        ),
                        cvss_score=cvss or 0.0,
                        package_name=None,
                        installed_version=None,
                        fixed_version=None,
                        remediation=solution,
                        references=references[:20],
                    )
                )

        return findings

    # ------------------------------------------------------------------
    # XML helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _text(
        item: ET.Element,
        tag: str,
    ) -> str | None:

        value = item.findtext(tag)

        if value:
            return value.strip()

        return None

    @staticmethod
    def _float(
        item: ET.Element,
        tag: str,
    ) -> float:

        value = item.findtext(tag)

        if not value:
            return 0.0

        try:
            return float(value)
        except (TypeError, ValueError):
            return 0.0

    @staticmethod
    def _nessus_severity(
        value: int,
    ):

        mapping = {
            0: "info",
            1: "low",
            2: "medium",
            3: "high",
            4: "critical",
        }

        return normalise_severity(
            mapping.get(
                value,
                "info",
            )
        )