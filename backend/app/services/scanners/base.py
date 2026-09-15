"""Scanner abstraction shared by every integration.
 
Adding a new engine only requires implementing :class:`BaseScanner` and
registering it in :mod:`app.services.scanners.registry`.
"""
 
from __future__ import annotations
 
import abc
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
 
from app.models.vulnerability import Severity
 
#: Callback used by scanners to stream log lines back to the caller.
LogCallback = Callable[[str, str], Awaitable[None]]
#: Callback used by scanners to report progress as a percentage (0-100).
ProgressCallback = Callable[[int], Awaitable[None]]
 
 
@dataclass(slots=True)
class Finding:
    """A normalised vulnerability finding produced by any scanner."""
 
    cve_id: str
    severity: Severity
    title: str | None = None
    description: str | None = None
    cvss_score: float = 0.0
    cvss_vector: str | None = None
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    remediation: str | None = None
    references: list[str] = field(default_factory=list)
    exploit_available: bool = False
 
 
@dataclass(slots=True)
class ScanResult:
    """Outcome of a scanner run."""
 
    findings: list[Finding] = field(default_factory=list)
    packages_found: int = 0
 
 
class ScannerError(RuntimeError):
    """Raised when a scanner cannot complete its run."""
 
 
class BaseScanner(abc.ABC):
    """Common interface implemented by every scanner integration."""
 
    #: Human readable name used in logs.
    name: str = "scanner"
 
    @abc.abstractmethod
    async def run(
        self, target: str, log: LogCallback, progress: ProgressCallback
    ) -> ScanResult:
        """Execute the scan against ``target`` and return normalised findings."""
        raise NotImplementedError