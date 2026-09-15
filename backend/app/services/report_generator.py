"""Report generation in PDF, CSV and JSON."""
 
from __future__ import annotations
 
import csv
import io
import json
from datetime import datetime, timezone
from pathlib import Path
 
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
 
from app.core.config import settings
from app.models.report import ReportFormat
from app.models.vulnerability import Severity, Vulnerability
from app.services.correlation_engine import AssetCorrelation, CorrelationReport
from app.utils.severity import SEVERITY_ORDER
 
#: Colour used in the PDF severity column, matching the frontend palette.
SEVERITY_COLOURS: dict[Severity, colors.Color] = {
    Severity.CRITICAL: colors.HexColor("#DC2626"),
    Severity.HIGH: colors.HexColor("#EA580C"),
    Severity.MEDIUM: colors.HexColor("#F59E0B"),
    Severity.LOW: colors.HexColor("#10B981"),
    Severity.INFO: colors.HexColor("#3B82F6"),
}
 
CSV_COLUMNS = [
    "cve_id",
    "severity",
    "cvss_score",
    "package_name",
    "installed_version",
    "fixed_version",
    "status",
    "asset",
    "title",
]
 
 
def reports_dir() -> Path:
    """Return (and create) the directory where report files are stored."""
    path = Path(settings.REPORTS_DIR)
    path.mkdir(parents=True, exist_ok=True)
    return path
 
 
def _row(vulnerability: Vulnerability) -> dict[str, object]:
    """Flatten a finding into a serialisable row."""
    return {
        "cve_id": vulnerability.cve_id,
        "severity": vulnerability.severity.value,
        "cvss_score": vulnerability.cvss_score,
        "package_name": vulnerability.package_name or "",
        "installed_version": vulnerability.installed_version or "",
        "fixed_version": vulnerability.fixed_version or "",
        "status": vulnerability.status.value,
        "asset": vulnerability.asset.hostname if vulnerability.asset else "",
        "title": (vulnerability.title or "")[:200],
    }
 
 
def _sorted(vulnerabilities: list[Vulnerability]) -> list[Vulnerability]:
    """Sort findings by severity then descending CVSS."""
    return sorted(
        vulnerabilities,
        key=lambda item: (SEVERITY_ORDER[item.severity], -item.cvss_score),
    )
 
 
def generate_report(
    name: str, report_format: ReportFormat, vulnerabilities: list[Vulnerability]
) -> Path:
    """Render ``vulnerabilities`` into a report file and return its path."""
    findings = _sorted(vulnerabilities)
    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_name = "".join(char if char.isalnum() or char in "-_" else "-" for char in name)[:60]
    path = reports_dir() / f"{safe_name}-{stamp}.{report_format.value}"
 
    if report_format is ReportFormat.JSON:
        path.write_text(
            json.dumps(
                {
                    "name": name,
                    "generated_at": datetime.now(tz=timezone.utc).isoformat(),
                    "total": len(findings),
                    "findings": [_row(item) for item in findings],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    elif report_format is ReportFormat.CSV:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        for item in findings:
            writer.writerow(_row(item))
        path.write_text(buffer.getvalue(), encoding="utf-8")
    else:
        _render_pdf(path, name, findings)
 
    return path
 
 
def _render_pdf(path: Path, name: str, findings: list[Vulnerability]) -> None:
    """Render a paginated PDF report with a summary table and findings table."""
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        title=name,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )
 
    counters = {severity: 0 for severity in Severity}
    for finding in findings:
        counters[finding.severity] += 1
 
    story: list[object] = [
        Paragraph(f"VulnGuard report - {name}", styles["Title"]),
        Paragraph(
            f"Generated on {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} - "
            f"{len(findings)} findings",
            styles["Normal"],
        ),
        Spacer(1, 8 * mm),
        Paragraph("Severity summary", styles["Heading2"]),
    ]
 
    summary_data = [["Severity", "Count"]] + [
        [severity.value.capitalize(), str(counters[severity])] for severity in Severity
    ]
    summary_table = Table(summary_data, colWidths=[60 * mm, 30 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94A3B8")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
            ]
            + [
                ("TEXTCOLOR", (0, index + 1), (0, index + 1), SEVERITY_COLOURS[severity])
                for index, severity in enumerate(Severity)
            ]
        )
    )
    story += [summary_table, Spacer(1, 8 * mm), Paragraph("Findings", styles["Heading2"])]
 
    table_data: list[list[str]] = [
        ["CVE", "Severity", "CVSS", "Package", "Installed", "Fixed", "Asset"]
    ]
    for finding in findings[:1000]:
        table_data.append(
            [
                finding.cve_id,
                finding.severity.value,
                f"{finding.cvss_score:.1f}",
                (finding.package_name or "")[:24],
                (finding.installed_version or "")[:18],
                (finding.fixed_version or "-")[:18],
                (finding.asset.hostname if finding.asset else "")[:20],
            ]
        )
 
    findings_table = Table(table_data, repeatRows=1, colWidths=[32 * mm] + [None] * 6)
    findings_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story.append(findings_table)
    document.build(story)


# ============================================================================
# CORRELATION REPORT (Wazuh <-> Nessus)
# ============================================================================

CORRELATION_CSV_COLUMNS = [
    "asset",
    "ip_address",
    "cve_id",
    "severity",
    "source",
    "wazuh_cvss",
    "nessus_cvss",
]


def _correlation_stamp_name(name: str, report_format: ReportFormat) -> Path:
    """Build the on-disk path for a correlation report, mirroring ``generate_report``."""
    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d-%H%M%S")
    safe_name = "".join(char if char.isalnum() or char in "-_" else "-" for char in name)[:60]
    return reports_dir() / f"{safe_name}-{stamp}.{report_format.value}"


def _correlation_row(
    asset: AssetCorrelation, cve_id: str, severity: Severity, source: str,
    wazuh_cvss: float | None = None, nessus_cvss: float | None = None,
) -> dict[str, object]:
    return {
        "asset": asset.hostname,
        "ip_address": asset.ip_address,
        "cve_id": cve_id,
        "severity": severity.value,
        "source": source,
        "wazuh_cvss": wazuh_cvss if wazuh_cvss is not None else "",
        "nessus_cvss": nessus_cvss if nessus_cvss is not None else "",
    }


def _correlation_rows(data: CorrelationReport) -> list[dict[str, object]]:
    """Flatten every matched/wazuh-only/nessus-only finding into report rows."""
    rows: list[dict[str, object]] = []
    for asset in data.assets:
        for item in asset.matched:
            rows.append(
                _correlation_row(
                    asset, item.cve_id, item.severity, "wazuh+nessus",
                    wazuh_cvss=item.wazuh.cvss_score, nessus_cvss=item.nessus.cvss_score,
                )
            )
        for item in asset.wazuh_only:
            rows.append(
                _correlation_row(asset, item.cve_id, item.severity, "wazuh", wazuh_cvss=item.cvss_score)
            )
        for item in asset.nessus_only:
            rows.append(
                _correlation_row(asset, item.cve_id, item.severity, "nessus", nessus_cvss=item.cvss_score)
            )
    rows.sort(key=lambda row: (SEVERITY_ORDER[Severity(row["severity"])], row["asset"]))
    return rows


def generate_correlation_report(
    name: str, report_format: ReportFormat, data: CorrelationReport
) -> Path:
    """Render a Wazuh/Nessus correlation dataset into a report file."""
    path = _correlation_stamp_name(name, report_format)
    rows = _correlation_rows(data)

    if report_format is ReportFormat.JSON:
        payload = {
            "name": name,
            "generated_at": datetime.now(tz=timezone.utc).isoformat(),
            "summary": {
                "assets_correlated": data.asset_count,
                "matched_findings": data.matched_count,
                "wazuh_only_findings": data.wazuh_only_count,
                "nessus_only_findings": data.nessus_only_count,
                "critical_high_findings": data.critical_high_count,
            },
            "assets": [
                {
                    "asset_id": asset.asset_id,
                    "hostname": asset.hostname,
                    "ip_address": asset.ip_address,
                    "matched": [
                        {
                            "cve_id": item.cve_id,
                            "severity": item.severity.value,
                            "max_cvss": item.max_cvss,
                            "wazuh_cvss": item.wazuh.cvss_score,
                            "nessus_cvss": item.nessus.cvss_score,
                            "wazuh_title": item.wazuh.title,
                            "nessus_title": item.nessus.title,
                        }
                        for item in asset.matched
                    ],
                    "wazuh_only": [
                        {
                            "cve_id": item.cve_id,
                            "severity": item.severity.value,
                            "cvss_score": item.cvss_score,
                            "title": item.title,
                        }
                        for item in asset.wazuh_only
                    ],
                    "nessus_only": [
                        {
                            "cve_id": item.cve_id,
                            "severity": item.severity.value,
                            "cvss_score": item.cvss_score,
                            "title": item.title,
                        }
                        for item in asset.nessus_only
                    ],
                    "critical_high": asset.critical_high,
                }
                for asset in data.assets
            ],
        }
        path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    elif report_format is ReportFormat.CSV:
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=CORRELATION_CSV_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
        path.write_text(buffer.getvalue(), encoding="utf-8")
    else:
        _render_correlation_pdf(path, name, data, rows)

    return path


def _render_correlation_pdf(
    path: Path, name: str, data: CorrelationReport, rows: list[dict[str, object]]
) -> None:
    """Render the correlation report as a paginated PDF."""
    styles = getSampleStyleSheet()
    document = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        title=name,
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    story: list[object] = [
        Paragraph(f"VulnGuard correlation report - {name}", styles["Title"]),
        Paragraph(
            f"Generated on {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} - "
            "Wazuh (agent-based) vs Nessus (network-based) cross-analysis",
            styles["Normal"],
        ),
        Spacer(1, 8 * mm),
        Paragraph("Correlation summary", styles["Heading2"]),
    ]

    summary_data = [
        ["Metric", "Count"],
        ["Assets correlated", str(data.asset_count)],
        ["Confirmed by both Wazuh and Nessus", str(data.matched_count)],
        ["Detected by Wazuh only", str(data.wazuh_only_count)],
        ["Detected by Nessus only", str(data.nessus_only_count)],
        ["Critical / High severity findings", str(data.critical_high_count)],
    ]
    summary_table = Table(summary_data, colWidths=[100 * mm, 40 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94A3B8")),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#DCFCE7")),
                ("BACKGROUND", (0, 5), (-1, 5), colors.HexColor("#FEE2E2")),
            ]
        )
    )
    story += [summary_table, Spacer(1, 8 * mm)]

    if not data.assets:
        story.append(
            Paragraph(
                "No asset currently has findings from both Wazuh and Nessus. "
                "Run a Wazuh sync and a Nessus scan (or the demo seed) against "
                "the same asset to populate this report.",
                styles["Normal"],
            )
        )
        document.build(story)
        return

    # ------------------------------------------------------------------
    # Cross-validated findings (matched by both scanners)
    # ------------------------------------------------------------------
    story.append(Paragraph("Cross-validated findings (Wazuh + Nessus)", styles["Heading2"]))
    matched_data: list[list[str]] = [
        ["Asset", "CVE", "Severity", "Wazuh CVSS", "Nessus CVSS"]
    ]
    for asset in data.assets:
        for item in asset.matched:
            matched_data.append(
                [
                    asset.hostname[:24],
                    item.cve_id,
                    item.severity.value,
                    f"{item.wazuh.cvss_score:.1f}",
                    f"{item.nessus.cvss_score:.1f}",
                ]
            )
    if len(matched_data) == 1:
        matched_data.append(["-", "No overlapping detections", "-", "-", "-"])
    matched_table = Table(matched_data, repeatRows=1)
    matched_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story += [matched_table, Spacer(1, 8 * mm)]

    # ------------------------------------------------------------------
    # Critical / High severity findings (either source)
    # ------------------------------------------------------------------
    story.append(Paragraph("Critical & High severity findings", styles["Heading2"]))
    crit_data: list[list[str]] = [["Asset", "CVE", "Severity", "CVSS", "Source"]]
    for asset in data.assets:
        for item in asset.critical_high:
            crit_data.append(
                [
                    asset.hostname[:24],
                    str(item["cve_id"]),
                    str(item["severity"].value if hasattr(item["severity"], "value") else item["severity"]),
                    f"{float(item['cvss_score']):.1f}",
                    str(item["source"]),
                ]
            )
    if len(crit_data) == 1:
        crit_data.append(["-", "No critical/high findings", "-", "-", "-"])
    crit_table = Table(crit_data, repeatRows=1)
    crit_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7F1D1D")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                ("FONTSIZE", (0, 0), (-1, -1), 7),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    story += [crit_table, Spacer(1, 8 * mm)]

    # ------------------------------------------------------------------
    # Single-source findings
    # ------------------------------------------------------------------
    for title, attr, colour in (
        ("Detected by Wazuh only", "wazuh_only", "#B45309"),
        ("Detected by Nessus only", "nessus_only", "#1D4ED8"),
    ):
        story.append(Paragraph(title, styles["Heading2"]))
        table_data: list[list[str]] = [["Asset", "CVE", "Severity", "CVSS", "Package / Title"]]
        for asset in data.assets:
            for item in getattr(asset, attr):
                table_data.append(
                    [
                        asset.hostname[:24],
                        item.cve_id,
                        item.severity.value,
                        f"{item.cvss_score:.1f}",
                        (item.package_name or item.title or "")[:40],
                    ]
                )
        if len(table_data) == 1:
            table_data.append(["-", "None", "-", "-", "-"])
        single_table = Table(table_data, repeatRows=1)
        single_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(colour)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#CBD5E1")),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        story += [single_table, Spacer(1, 6 * mm)]

    document.build(story)