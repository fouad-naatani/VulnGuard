"""Severity helpers shared by scanner integrations and reporting."""
 
from __future__ import annotations
 
from app.models.vulnerability import Severity
 
#: Ordering used when sorting findings from most to least urgent.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
 
 
def normalise_severity(raw: str | None) -> Severity:
    """Map a scanner specific severity string onto the platform enum."""
    if not raw:
        return Severity.INFO
    value = raw.strip().lower()
    aliases = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "moderate": Severity.MEDIUM,
        "low": Severity.LOW,
        "negligible": Severity.LOW,
        "unknown": Severity.INFO,
        "none": Severity.INFO,
        "informational": Severity.INFO,
        "info": Severity.INFO,
    }
    return aliases.get(value, Severity.INFO)
 
 
def severity_from_cvss(score: float) -> Severity:
    """Derive a severity bucket from a CVSS v3 base score."""
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.INFO