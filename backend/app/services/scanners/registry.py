"""Scanner registry mapping the ScannerType enum onto implementations."""

from __future__ import annotations

from app.models.scan import ScannerType
from app.services.scanners.base import BaseScanner, ScannerError
from app.services.scanners.trivy import TrivyScanner
from app.services.scanners.wazuh import WazuhScanner
from app.services.scanners.nessus import NessusScanner


_SCANNERS: dict[ScannerType, type[BaseScanner]] = {
    ScannerType.TRIVY: TrivyScanner,
    ScannerType.WAZUH: WazuhScanner,
    ScannerType.NESSUS: NessusScanner,
}


def get_scanner(scanner_type: ScannerType) -> BaseScanner:
    """Instantiate the scanner implementation for scanner_type."""

    scanner_class = _SCANNERS.get(scanner_type)

    if scanner_class is None:
        raise ScannerError(
            f"The {scanner_type.value} integration is planned "
            "but not available yet."
        )

    return scanner_class()