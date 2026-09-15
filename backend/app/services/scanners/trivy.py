"""Trivy scanner integration.
 
Trivy is invoked as a subprocess in JSON mode; its report is then normalised
into :class:`~app.services.scanners.base.Finding` objects.
"""
 
from __future__ import annotations
 
import asyncio
import json
import shutil
from typing import Any
 
from app.core.config import settings
from app.services.scanners.base import (
    BaseScanner,
    Finding,
    LogCallback,
    ProgressCallback,
    ScannerError,
    ScanResult,
)
from app.utils.severity import normalise_severity, severity_from_cvss
 
 
class TrivyScanner(BaseScanner):
    """Runs ``trivy`` against a container image, filesystem path or repository."""
 
    name = "trivy"
 
    def __init__(self, binary: str | None = None, timeout: int | None = None) -> None:
        self.binary = binary or settings.TRIVY_BINARY
        self.timeout = timeout or settings.TRIVY_TIMEOUT_SECONDS
 
    def _build_command(self, target: str) -> list[str]:
        """Return the argv used to scan ``target``.
 
        Local paths are scanned in ``fs`` mode, everything else is treated as a
        container image reference.
        """
        subcommand = "fs" if target.startswith((".", "/")) else "image"
        return [
            self.binary,
            subcommand,
            "--quiet",
            "--scanners",
            "vuln",
            "--format",
            "json",
            target,
        ]
 
    async def run(self, target: str, log: LogCallback, progress: ProgressCallback) -> ScanResult:
        """Execute Trivy and parse its JSON report."""
        if shutil.which(self.binary) is None:
            raise ScannerError(
                f"Trivy binary '{self.binary}' was not found on the scanner host. "
                "Install Trivy or update the TRIVY_BINARY setting."
            )
 
        command = self._build_command(target)
        await log("info", f"Executing: {' '.join(command)}")
        await progress(10)
 
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)
        except TimeoutError as exc:
            process.kill()
            raise ScannerError(f"Trivy timed out after {self.timeout}s") from exc
 
        await progress(70)
        if stderr:
            for line in stderr.decode(errors="replace").splitlines()[-20:]:
                await log("warning", line)
        if process.returncode != 0:
            raise ScannerError(f"Trivy exited with code {process.returncode}")
 
        report = self._parse_report(stdout.decode(errors="replace"))
        await log("info", f"Trivy reported {len(report.findings)} vulnerabilities")
        await progress(95)
        return report
 
    def _parse_report(self, raw: str) -> ScanResult:
        """Normalise a Trivy JSON report."""
        try:
            document: dict[str, Any] = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerError("Trivy returned a malformed JSON report") from exc
 
        findings: list[Finding] = []
        packages: set[str] = set()
        for result in document.get("Results") or []:
            for vulnerability in result.get("Vulnerabilities") or []:
                findings.append(self._to_finding(vulnerability))
                if pkg := vulnerability.get("PkgName"):
                    packages.add(pkg)
            for package in result.get("Packages") or []:
                if name := package.get("Name"):
                    packages.add(name)
 
        return ScanResult(findings=findings, packages_found=len(packages))
 
    @staticmethod
    def _to_finding(vulnerability: dict[str, Any]) -> Finding:
        """Convert one Trivy vulnerability entry into a normalised finding."""
        cvss_score = 0.0
        cvss_vector: str | None = None
        for vendor_data in (vulnerability.get("CVSS") or {}).values():
            score = vendor_data.get("V3Score") or vendor_data.get("V2Score")
            if score and float(score) > cvss_score:
                cvss_score = float(score)
                cvss_vector = vendor_data.get("V3Vector") or vendor_data.get("V2Vector")
 
        severity = normalise_severity(vulnerability.get("Severity"))
        if severity.value == "info" and cvss_score:
            severity = severity_from_cvss(cvss_score)
 
        fixed_version = vulnerability.get("FixedVersion")
        remediation = (
            f"Upgrade {vulnerability.get('PkgName')} to {fixed_version} or later."
            if fixed_version
            else (
                "No fixed version published yet: apply vendor mitigations "
                "and monitor the advisory."
            )
        )
 
        return Finding(
            cve_id=vulnerability.get("VulnerabilityID", "UNKNOWN"),
            severity=severity,
            title=vulnerability.get("Title"),
            description=vulnerability.get("Description"),
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            package_name=vulnerability.get("PkgName"),
            installed_version=vulnerability.get("InstalledVersion"),
            fixed_version=fixed_version,
            remediation=remediation,
            references=list(vulnerability.get("References") or [])[:20],
        )