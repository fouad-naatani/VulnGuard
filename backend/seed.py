"""
VulnGuard database bootstrap + Wazuh/OpenSearch synchronization.

Usage:

    python seed.py
        Create schema, admin, settings and synchronize Wazuh data.

    python seed.py --no-wazuh
        Only create schema, admin and settings.

    python seed.py --clean-demo
        Remove demo assets/data before synchronizing Wazuh.

    python seed.py --no-nessus-demo
        Skip seeding the demo Nessus scan used by the correlation
        engine demo (dell / 172.20.10.2).
"""

from __future__ import annotations

import argparse
import asyncio
from typing import Any

import httpx
from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_password
from app.db.base import Base, utcnow
from app.db.session import AsyncSessionLocal, engine

from app.models.asset import Asset, AgentStatus
from app.models.scan import (
    Scan,
    ScanLog,
    ScannerType,
    ScanStatus,
)
from app.models.setting import Setting
from app.models.user import User, UserRole
from app.models.vulnerability import (
    Vulnerability,
    VulnerabilityStatus,
    Severity,
)


# ============================================================================
# DEFAULT SETTINGS
# ============================================================================

DEFAULT_SETTINGS = [
    (
        "api_url",
        "http://localhost:8000/api",
        "general",
        False,
    ),
    (
        "jwt_access_token_minutes",
        str(settings.ACCESS_TOKEN_EXPIRE_MINUTES),
        "security",
        False,
    ),
    (
        "jwt_refresh_token_minutes",
        str(settings.REFRESH_TOKEN_EXPIRE_MINUTES),
        "security",
        False,
    ),
    (
        "smtp_host",
        "",
        "smtp",
        False,
    ),
    (
        "smtp_port",
        "587",
        "smtp",
        False,
    ),
    (
        "smtp_username",
        "",
        "smtp",
        False,
    ),
    (
        "smtp_password",
        "",
        "smtp",
        True,
    ),
    (
        "theme",
        "dark",
        "general",
        False,
    ),
    (
        "integration_trivy_enabled",
        "true",
        "integrations",
        False,
    ),
    (
        "integration_wazuh_url",
        settings.WAZUH_API_URL,
        "integrations",
        False,
    ),
    (
        "integration_wazuh_token",
        "",
        "integrations",
        True,
    ),
]


# ============================================================================
# DATABASE
# ============================================================================

async def create_schema() -> None:
    """Create all database tables if they do not exist."""

    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    print("[OK] Database schema ready")


# ============================================================================
# ADMIN
# ============================================================================

async def ensure_admin() -> None:
    """Create the initial administrator."""

    email = settings.FIRST_ADMIN_EMAIL.lower()

    async with AsyncSessionLocal() as session:

        existing = await session.scalar(
            select(User).where(User.email == email)
        )

        if existing:
            print(f"[OK] Admin already exists: {email}")
            return

        admin = User(
            email=email,
            full_name="Platform Administrator",
            role=UserRole.ADMIN,
            hashed_password=hash_password(
                settings.FIRST_ADMIN_PASSWORD
            ),
        )

        session.add(admin)
        await session.commit()

        print(f"[OK] Created admin: {email}")


# ============================================================================
# SETTINGS
# ============================================================================

async def ensure_settings() -> None:
    """Create default application settings."""

    async with AsyncSessionLocal() as session:

        for key, value, category, is_secret in DEFAULT_SETTINGS:

            existing = await session.scalar(
                select(Setting).where(
                    Setting.key == key
                )
            )

            if existing:
                continue

            session.add(
                Setting(
                    key=key,
                    value=value,
                    category=category,
                    is_secret=is_secret,
                )
            )

        await session.commit()

    print("[OK] Application settings ready")


# ============================================================================
# WAZUH AUTHENTICATION
# ============================================================================

async def wazuh_authenticate(
    client: httpx.AsyncClient,
) -> str:

    url = (
        f"{settings.WAZUH_API_URL.rstrip('/')}"
        "/security/user/authenticate"
    )

    print("[WAZUH] Authenticating...")

    response = await client.post(
        url,
        auth=(
            settings.WAZUH_API_USER,
            settings.WAZUH_API_PASSWORD,
        ),
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Wazuh authentication failed: "
            f"HTTP {response.status_code}\n"
            f"{response.text}"
        )

    payload = response.json()

    token = (
        payload
        .get("data", {})
        .get("token")
    )

    if not token:
        raise RuntimeError(
            "Wazuh authentication response "
            "did not contain a token."
        )

    print("[OK] Wazuh authentication successful")

    return token


# ============================================================================
# WAZUH AGENTS
# ============================================================================

async def get_wazuh_agents(
    client: httpx.AsyncClient,
    token: str,
) -> list[dict[str, Any]]:

    url = (
        f"{settings.WAZUH_API_URL.rstrip('/')}"
        "/agents"
    )

    print("[WAZUH] Retrieving agents...")

    response = await client.get(
        url,
        headers={
            "Authorization": f"Bearer {token}",
        },
        params={
            "limit": 5000,
        },
    )

    if response.status_code != 200:
        raise RuntimeError(
            f"Unable to retrieve Wazuh agents: "
            f"HTTP {response.status_code}\n"
            f"{response.text}"
        )

    payload = response.json()

    agents = (
        payload
        .get("data", {})
        .get("affected_items", [])
    )

    print(
        f"[OK] Wazuh returned {len(agents)} agents"
    )

    return agents


# ============================================================================
# OPENSEARCH / WAZUH VULNERABILITIES
# ============================================================================

async def get_agent_vulnerabilities(
    client: httpx.AsyncClient,
    agent_id: str,
) -> list[dict[str, Any]]:

    url = (
        f"{settings.WAZUH_INDEXER_URL.rstrip('/')}"
        f"/{settings.WAZUH_VULNERABILITY_INDEX}/_search"
    )

    query = {
        "size": 10000,
        "query": {
            "term": {
                "agent.id": agent_id
            }
        }
    }

    print(
        f"    [INDEXER] Searching vulnerabilities "
        f"for agent {agent_id}..."
    )

    response = await client.post(
        url,
        auth=(
            settings.WAZUH_INDEXER_USER,
            settings.WAZUH_INDEXER_PASSWORD,
        ),
        headers={
            "Content-Type": "application/json",
        },
        json=query,
    )

    if response.status_code != 200:
        raise RuntimeError(
            "Unable to retrieve vulnerabilities "
            f"from Wazuh Indexer for agent {agent_id}: "
            f"HTTP {response.status_code}\n"
            f"{response.text}"
        )

    payload = response.json()

    hits = (
        payload
        .get("hits", {})
        .get("hits", [])
    )

    findings = [
        hit.get("_source", {})
        for hit in hits
        if hit.get("_source")
    ]

    print(
        f"    [OK] Indexer returned "
        f"{len(findings)} vulnerabilities "
        f"for agent {agent_id}"
    )

    return findings


# ============================================================================
# AGENT HELPERS
# ============================================================================

def map_agent_status(
    status: str | None,
) -> AgentStatus:

    value = (status or "").lower()

    if value == "active":
        return AgentStatus.ONLINE

    if value in {
        "disconnected",
        "pending",
        "never_connected",
    }:
        return AgentStatus.OFFLINE

    return AgentStatus.NEVER_CONNECTED


def extract_agent_ip(
    agent: dict[str, Any],
) -> str:

    ip = (
        agent.get("ip")
        or agent.get("ip_address")
        or agent.get("registerIP")
        or "0.0.0.0"
    )

    return str(ip)[:45]


def extract_agent_os(
    agent: dict[str, Any],
) -> str | None:

    # Wazuh API may return:
    #
    # os_name
    # os_version
    #
    # or:
    #
    # os: {
    #   name,
    #   version
    # }

    os_name = agent.get("os_name")
    os_version = agent.get("os_version")

    if os_name or os_version:
        return " ".join(
            str(value)
            for value in (
                os_name,
                os_version,
            )
            if value
        )

    os_data = agent.get("os")

    if isinstance(os_data, dict):

        name = os_data.get("name")
        version = os_data.get("version")

        if name and version:
            return f"{name} {version}"

        if name:
            return str(name)

    if isinstance(os_data, str):
        return os_data

    return None


# ============================================================================
# ASSET
# ============================================================================

async def get_or_create_asset(
    session,
    agent: dict[str, Any],
) -> Asset:

    agent_id = str(
        agent.get("id")
        or agent.get("agent_id")
    )

    hostname = (
        agent.get("name")
        or agent.get("hostname")
        or f"wazuh-agent-{agent_id}"
    )

    ip_address = extract_agent_ip(agent)

    operating_system = extract_agent_os(agent)

    status = map_agent_status(
        agent.get("status")
    )

    # IMPORTANT:
    # Do NOT use Asset.wazuh_agent_id.
    #
    # Your Asset model stores Wazuh information
    # in the tags field.

    wazuh_tag = f"wazuh-agent:{agent_id}"

    existing = await session.scalar(
        select(Asset).where(
            Asset.tags.contains(wazuh_tag)
        )
    )

    if existing:

        existing.hostname = str(hostname)[:255]
        existing.ip_address = ip_address
        existing.operating_system = operating_system
        existing.agent_status = status
        existing.tags = f"wazuh,{wazuh_tag}"

        return existing

    asset = Asset(
        hostname=str(hostname)[:255],
        ip_address=ip_address,
        operating_system=operating_system,
        owner="Wazuh",
        tags=f"wazuh,{wazuh_tag}",
        agent_status=status,
        description=(
            f"Wazuh managed agent {agent_id}"
        ),
    )

    session.add(asset)

    await session.flush()

    return asset


# ============================================================================
# CVSS
# ============================================================================

def extract_cvss(
    vulnerability: dict[str, Any],
) -> float:

    score = vulnerability.get(
        "score",
        {}
    )

    if isinstance(score, dict):

        value = (
            score.get("base")
            or score.get("base_score")
            or score.get("value")
            or 0
        )

    else:
        value = score or 0

    try:
        return float(value)

    except (TypeError, ValueError):
        return 0.0


# ============================================================================
# SEVERITY
# ============================================================================

def normalise_severity(
    value: Any,
    cvss: float,
) -> Severity:

    text = str(
        value or ""
    ).lower().strip()

    if text == "critical":
        return Severity.CRITICAL

    if text == "high":
        return Severity.HIGH

    if text == "medium":
        return Severity.MEDIUM

    if text == "low":
        return Severity.LOW

    if text == "info":
        return Severity.INFO

    # CVSS fallback

    if cvss >= 9.0:
        return Severity.CRITICAL

    if cvss >= 7.0:
        return Severity.HIGH

    if cvss >= 4.0:
        return Severity.MEDIUM

    if cvss > 0:
        return Severity.LOW

    return Severity.INFO


# ============================================================================
# REFERENCES
# ============================================================================

def extract_references(
    vulnerability: dict[str, Any],
) -> str | None:

    reference = vulnerability.get(
        "reference"
    )

    if isinstance(reference, str):
        return reference

    if isinstance(reference, list):

        values = []

        for item in reference:

            if isinstance(item, str):
                values.append(item)

            elif isinstance(item, dict):

                value = (
                    item.get("url")
                    or item.get("href")
                    or item.get("reference")
                )

                if value:
                    values.append(str(value))

        return "\n".join(values[:20]) or None

    return None


# ============================================================================
# FIXED VERSION
# ============================================================================

def extract_fixed_version(
    vulnerability: dict[str, Any],
) -> str | None:

    scanner = vulnerability.get(
        "scanner",
        {}
    )

    if not isinstance(scanner, dict):
        return None

    condition = scanner.get(
        "condition"
    )

    if not condition:
        return None

    condition = str(condition)

    # Example:
    #
    # Package less than 10.0.19045.7417
    #
    # Store the condition because this is
    # exactly what Wazuh reports.

    return condition[:128]


# ============================================================================
# SAVE VULNERABILITIES
# ============================================================================

async def save_vulnerabilities(
    session,
    asset: Asset,
    scan: Scan,
    findings: list[dict[str, Any]],
) -> int:

    saved = 0

    for item in findings:

        # ---------------------------------------------------------------
        # IMPORTANT:
        # Actual Wazuh OpenSearch structure:
        #
        # item["vulnerability"]["id"]
        # item["vulnerability"]["description"]
        # item["vulnerability"]["severity"]
        # item["vulnerability"]["score"]["base"]
        #
        # item["package"]["name"]
        # item["package"]["version"]
        # ---------------------------------------------------------------

        vulnerability_data = item.get(
            "vulnerability",
            {}
        )

        package_data = item.get(
            "package",
            {}
        )

        if not isinstance(
            vulnerability_data,
            dict,
        ):
            continue

        if not isinstance(
            package_data,
            dict,
        ):
            package_data = {}

        # ---------------------------------------------------------------
        # CVE
        # ---------------------------------------------------------------

        cve_id = (
            vulnerability_data.get("id")
            or vulnerability_data.get("cve")
            or vulnerability_data.get("cve_id")
        )

        # Do NOT create UNKNOWN records.
        # If Wazuh has no vulnerability ID,
        # skip the record instead.

        if not cve_id:
            print(
                "    [WARN] Vulnerability without CVE/ID skipped"
            )
            continue

        cve_id = str(cve_id)[:64]

        # ---------------------------------------------------------------
        # PACKAGE
        # ---------------------------------------------------------------

        package_name = package_data.get(
            "name"
        )

        installed_version = package_data.get(
            "version"
        )

        # ---------------------------------------------------------------
        # CVSS
        # ---------------------------------------------------------------

        cvss = extract_cvss(
            vulnerability_data
        )

        # ---------------------------------------------------------------
        # SEVERITY
        # ---------------------------------------------------------------

        severity = normalise_severity(
            vulnerability_data.get("severity"),
            cvss,
        )

        # ---------------------------------------------------------------
        # DESCRIPTION
        # ---------------------------------------------------------------

        description = (
            vulnerability_data.get("description")
            or f"Vulnerability {cve_id}"
        )

        description = str(description)

        # ---------------------------------------------------------------
        # TITLE
        # ---------------------------------------------------------------

        title = (
            f"{cve_id} - "
            f"{package_name or 'Vulnerability'}"
        )

        # ---------------------------------------------------------------
        # REFERENCE
        # ---------------------------------------------------------------

        references = extract_references(
            vulnerability_data
        )

        # ---------------------------------------------------------------
        # FIXED VERSION
        # ---------------------------------------------------------------

        fixed_version = extract_fixed_version(
            vulnerability_data
        )

        # ---------------------------------------------------------------
        # REMEDIATION
        # ---------------------------------------------------------------

        scanner_data = vulnerability_data.get(
            "scanner",
            {}
        )

        if isinstance(scanner_data, dict):

            remediation = (
                scanner_data.get("condition")
                or "Apply the vendor patch reported by Wazuh."
            )

        else:

            remediation = (
                "Apply the vendor patch reported by Wazuh."
            )

        # ---------------------------------------------------------------
        # EXISTING VULNERABILITY
        # ---------------------------------------------------------------

        existing = await session.scalar(
            select(Vulnerability).where(
                Vulnerability.asset_id == asset.id,
                Vulnerability.cve_id == cve_id,
            )
        )

        if existing:

            existing.title = title[:512]

            existing.description = description

            existing.severity = severity

            existing.cvss_score = cvss

            existing.package_name = (
                str(package_name)[:255]
                if package_name
                else None
            )

            existing.installed_version = (
                str(installed_version)[:128]
                if installed_version
                else None
            )

            existing.fixed_version = fixed_version

            existing.remediation = (
                str(remediation)[:1000]
                if remediation
                else None
            )

            existing.references = references

            existing.scan_id = scan.id

            # If an old UNKNOWN record exists with this
            # CVE, this update also fixes its information.

            continue

        # ---------------------------------------------------------------
        # NEW VULNERABILITY
        # ---------------------------------------------------------------

        vulnerability = Vulnerability(
            cve_id=cve_id,

            title=title[:512],

            description=description,

            severity=severity,

            cvss_score=cvss,

            package_name=(
                str(package_name)[:255]
                if package_name
                else None
            ),

            installed_version=(
                str(installed_version)[:128]
                if installed_version
                else None
            ),

            fixed_version=fixed_version,

            remediation=(
                str(remediation)[:1000]
                if remediation
                else None
            ),

            references=references,

            exploit_available=False,

            status=VulnerabilityStatus.OPEN,

            asset_id=asset.id,

            scan_id=scan.id,
        )

        session.add(vulnerability)

        saved += 1

    return saved


# ============================================================================
# WAZUH SYNCHRONIZATION
# ============================================================================

async def sync_wazuh() -> None:

    print()
    print("=" * 70)
    print("VULNGUARD - WAZUH SYNCHRONIZATION")
    print("=" * 70)
    print()

    async with httpx.AsyncClient(
        verify=settings.WAZUH_VERIFY_SSL,
        timeout=60.0,
    ) as client:

        token = await wazuh_authenticate(
            client
        )

        agents = await get_wazuh_agents(
            client,
            token,
        )

        if not agents:

            print(
                "[WARN] Wazuh returned zero agents"
            )

            return

        total_assets = 0
        total_vulnerabilities = 0

        async with AsyncSessionLocal() as session:

            for index, agent in enumerate(
                agents,
                start=1,
            ):

                agent_id = str(
                    agent.get("id")
                    or agent.get("agent_id")
                )

                hostname = (
                    agent.get("name")
                    or agent.get("hostname")
                    or agent_id
                )

                print()
                print(
                    f"[{index}/{len(agents)}] "
                    f"Agent {agent_id} - {hostname}"
                )

                try:

                    # =====================================================
                    # ASSET
                    # =====================================================

                    asset = await get_or_create_asset(
                        session,
                        agent,
                    )

                    total_assets += 1

                    # =====================================================
                    # SCAN
                    # =====================================================

                    scan = Scan(
                        name=(
                            f"Wazuh vulnerability sync - "
                            f"{hostname}"
                        ),
                        scanner=ScannerType.WAZUH,
                        target=agent_id,
                        status=ScanStatus.RUNNING,
                        progress=20,
                        asset_id=asset.id,
                        started_at=utcnow(),
                    )

                    session.add(scan)

                    await session.flush()

                    session.add(
                        ScanLog(
                            scan_id=scan.id,
                            level="info",
                            message=(
                                f"Started Wazuh synchronization "
                                f"for agent {agent_id}"
                            ),
                        )
                    )

                    # =====================================================
                    # VULNERABILITIES
                    # =====================================================

                    findings = await get_agent_vulnerabilities(
                        client,
                        agent_id,
                    )

                    print(
                        f"    Vulnerabilities returned: "
                        f"{len(findings)}"
                    )

                    scan.progress = 80

                    # Count unique packages
                    scan.packages_found = len(
                        {
                            item.get(
                                "package",
                                {},
                            ).get("name")
                            for item in findings
                            if item.get(
                                "package",
                                {},
                            ).get("name")
                        }
                    )

                    saved = await save_vulnerabilities(
                        session,
                        asset,
                        scan,
                        findings,
                    )

                    # =====================================================
                    # COMPLETE SCAN
                    # =====================================================

                    scan.status = ScanStatus.COMPLETED

                    scan.progress = 100

                    scan.finished_at = utcnow()

                    asset.last_scan_at = (
                        scan.finished_at
                    )

                    session.add(
                        ScanLog(
                            scan_id=scan.id,
                            level="info",
                            message=(
                                f"Wazuh returned "
                                f"{len(findings)} findings; "
                                f"{saved} vulnerabilities "
                                f"created/updated"
                            ),
                        )
                    )

                    total_vulnerabilities += saved

                    print(
                        f"    New vulnerabilities stored: "
                        f"{saved}"
                    )

                    await session.commit()

                except Exception as exc:

                    await session.rollback()

                    print(
                        f"    [ERROR] Agent {agent_id}: "
                        f"{exc}"
                    )

                    continue

        print()
        print("=" * 70)
        print("WAZUH SYNCHRONIZATION COMPLETE")
        print("=" * 70)
        print(
            f"Assets processed: {total_assets}"
        )
        print(
            f"Vulnerabilities created/updated: "
            f"{total_vulnerabilities}"
        )
        print("=" * 70)


# ============================================================================
# NESSUS DEMO DATA (correlation engine demo)
# ============================================================================
#
# Goal: give the correlation engine something to correlate out of the box,
# without requiring a real Nessus scanner to be reachable.
#
# We target the same host Wazuh already monitors ("dell", 172.20.10.2).
# If that asset already exists (e.g. because sync_wazuh() ran first and a
# real Wazuh agent registered from that IP), we attach the demo Nessus scan
# to it and, whenever possible, reuse a handful of CVE IDs that Wazuh
# genuinely reported for that host - this produces real, non-fabricated
# cross-scanner matches. If the asset does not exist yet, we create it and
# fall back to a curated pool of realistic CVEs so the demo still works
# standalone (e.g. before the first Wazuh sync, or with --no-wazuh).

DELL_DEMO_IP = "172.20.10.2"
DELL_DEMO_HOSTNAME = "DELL-WKS-01"

#: CVEs used as the "guaranteed overlap" pool when the target asset has no
#: real Wazuh findings yet to reuse. Realistic, well known Windows CVEs that
#: a network/credentialed scan (Nessus) and an agent-based scan (Wazuh)
#: would both plausibly flag on a Windows workstation.
NESSUS_OVERLAP_FALLBACK = [
    {
        "cve_id": "CVE-2021-34527",
        "title": "Windows Print Spooler Remote Code Execution (PrintNightmare)",
        "severity": Severity.CRITICAL,
        "cvss_score": 8.8,
        "description": (
            "The Windows Print Spooler service improperly performs "
            "privileged file operations, allowing a remote authenticated "
            "attacker to execute arbitrary code with SYSTEM privileges."
        ),
        "remediation": "Apply the vendor patch and restrict Print Spooler exposure.",
    },
    {
        "cve_id": "CVE-2020-1472",
        "title": "Netlogon Elevation of Privilege Vulnerability (Zerologon)",
        "severity": Severity.CRITICAL,
        "cvss_score": 10.0,
        "description": (
            "An elevation of privilege vulnerability exists when an "
            "attacker establishes a vulnerable Netlogon secure channel "
            "connection to a domain controller."
        ),
        "remediation": "Apply the vendor patch and enforce secure RPC for Netlogon.",
    },
    {
        "cve_id": "CVE-2023-23397",
        "title": "Microsoft Outlook Elevation of Privilege Vulnerability",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "description": (
            "A specially crafted message can trigger automatic connection "
            "from the victim to an external UNC location, leaking NTLM "
            "credentials without user interaction."
        ),
        "remediation": "Apply the vendor patch and block outbound SMB (TCP 445).",
    },
]

#: Findings that only a network/credentialed scanner such as Nessus would
#: typically surface (exposed services, protocol/config weaknesses).
NESSUS_ONLY_POOL = [
    {
        "cve_id": "CVE-2019-0708",
        "title": "Remote Desktop Services Remote Code Execution (BlueKeep)",
        "severity": Severity.CRITICAL,
        "cvss_score": 9.8,
        "description": (
            "A pre-authentication remote code execution vulnerability in "
            "Remote Desktop Services, exploitable over RDP without user "
            "interaction."
        ),
        "remediation": "Apply the vendor patch and disable RDP if not required.",
        "port": "3389",
        "protocol": "tcp",
    },
    {
        "cve_id": "CVE-2017-0144",
        "title": "SMBv1 Remote Code Execution (EternalBlue)",
        "severity": Severity.CRITICAL,
        "cvss_score": 8.1,
        "description": (
            "The SMBv1 server mishandles specially crafted packets, "
            "allowing remote code execution."
        ),
        "remediation": "Disable SMBv1 and apply the vendor patch.",
        "port": "445",
        "protocol": "tcp",
    },
    {
        "cve_id": "CVE-2022-30190",
        "title": "Microsoft Windows Support Diagnostic Tool RCE (Follina)",
        "severity": Severity.HIGH,
        "cvss_score": 7.8,
        "description": (
            "MSDT can be invoked via the URL protocol from a calling "
            "application such as Word, allowing remote code execution."
        ),
        "remediation": "Apply the vendor patch and disable the MSDT URL protocol.",
        "port": "445",
        "protocol": "tcp",
    },
    {
        "cve_id": "CVE-2023-38831",
        "title": "WinRAR Remote Code Execution via crafted archive",
        "severity": Severity.HIGH,
        "cvss_score": 7.8,
        "description": (
            "WinRAR can be tricked into executing a file inside a "
            "specially crafted archive when the user opens a decoy file "
            "with the same name."
        ),
        "remediation": "Update WinRAR to the latest version.",
        "port": None,
        "protocol": None,
    },
    {
        "cve_id": "CVE-2024-21412",
        "title": "Windows SmartScreen Security Feature Bypass",
        "severity": Severity.HIGH,
        "cvss_score": 8.1,
        "description": (
            "Internet Shortcut Files can bypass SmartScreen checks, "
            "allowing an attacker to deliver malicious payloads."
        ),
        "remediation": "Apply the vendor patch.",
        "port": None,
        "protocol": None,
    },
]


async def get_or_create_dell_demo_asset(session) -> Asset:
    """Return the "dell" asset (172.20.10.2), creating it if necessary."""

    existing = await session.scalar(
        select(Asset).where(Asset.ip_address == DELL_DEMO_IP)
    )

    if existing:
        return existing

    asset = Asset(
        hostname=DELL_DEMO_HOSTNAME,
        ip_address=DELL_DEMO_IP,
        operating_system="Microsoft Windows 10 Enterprise",
        owner="IT Operations",
        tags="demo,nessus-target,correlation-demo",
        agent_status=AgentStatus.ONLINE,
        description=(
            "Demo asset - Dell workstation used to showcase the "
            "Wazuh/Nessus correlation engine"
        ),
    )

    session.add(asset)
    await session.flush()

    print(
        f"[OK] Created demo asset {DELL_DEMO_HOSTNAME} "
        f"({DELL_DEMO_IP}) for the correlation demo"
    )

    return asset


async def _build_nessus_finding(
    session,
    asset: Asset,
    scan: Scan,
    spec: dict[str, Any],
) -> Vulnerability:
    """Build a single Vulnerability row for the Nessus demo scan.

    Deliberately does NOT reuse the generic "existing (asset, cve) ->
    update" logic used by the Wazuh sync: the whole point of this demo is
    to preserve both scanners' independent detections of the same CVE so
    the correlation engine can prove they agree. A Nessus row is always
    inserted fresh and tied to this scan.
    """

    references: list[str] = [f"Nessus plugin (demo): {spec['cve_id']}"]

    port = spec.get("port")
    if port:
        references.append(f"Port: {port}/{spec.get('protocol') or 'tcp'}")

    return Vulnerability(
        cve_id=spec["cve_id"],
        title=spec["title"][:512],
        description=spec["description"],
        severity=spec["severity"],
        cvss_score=spec["cvss_score"],
        package_name=None,
        installed_version=None,
        fixed_version=None,
        remediation=spec["remediation"],
        references="\n".join(references),
        exploit_available=spec["severity"] == Severity.CRITICAL,
        status=VulnerabilityStatus.OPEN,
        asset_id=asset.id,
        scan_id=scan.id,
    )


async def seed_demo_nessus_data() -> None:
    """Seed a demo Nessus scan that correlates with the Wazuh "dell" host.

    Creates a COMPLETED Nessus scan against 172.20.10.2 with a handful of
    findings: a few CVEs that overlap with whatever Wazuh already reported
    for that asset (guaranteed cross-scanner matches for the correlation
    engine), plus network-only findings that only Nessus would surface.
    """

    print()
    print("=" * 70)
    print("VULNGUARD - NESSUS DEMO DATA (correlation engine)")
    print("=" * 70)
    print()

    async with AsyncSessionLocal() as session:

        asset = await get_or_create_dell_demo_asset(session)

        # ------------------------------------------------------------------
        # Reuse real Wazuh CVEs for this asset when available, so the
        # correlation is genuine rather than purely synthetic.
        # ------------------------------------------------------------------

        wazuh_vulnerabilities = (
            await session.scalars(
                select(Vulnerability)
                .join(Scan, Vulnerability.scan_id == Scan.id)
                .where(
                    Vulnerability.asset_id == asset.id,
                    Scan.scanner == ScannerType.WAZUH,
                )
                .order_by(Vulnerability.cvss_score.desc())
                .limit(3)
            )
        ).all()

        if wazuh_vulnerabilities:
            overlap_specs = [
                {
                    "cve_id": vulnerability.cve_id,
                    "title": vulnerability.title or vulnerability.cve_id,
                    "severity": vulnerability.severity,
                    "cvss_score": vulnerability.cvss_score,
                    "description": (
                        vulnerability.description
                        or f"Vulnerability {vulnerability.cve_id} confirmed via network scan."
                    ),
                    "remediation": (
                        vulnerability.remediation
                        or "Apply the vendor patch reported by Nessus."
                    ),
                    "port": None,
                    "protocol": None,
                }
                for vulnerability in wazuh_vulnerabilities
            ]
            print(
                f"[OK] Reusing {len(overlap_specs)} real Wazuh CVE(s) "
                f"from {asset.hostname} for cross-scanner correlation"
            )
        else:
            overlap_specs = NESSUS_OVERLAP_FALLBACK
            print(
                "[WARN] No existing Wazuh findings for "
                f"{asset.hostname} ({DELL_DEMO_IP}) - using the built-in "
                "overlap CVE pool instead"
            )

        # ------------------------------------------------------------------
        # SCAN
        # ------------------------------------------------------------------

        scan = Scan(
            name=f"Nessus vulnerability scan - {asset.hostname} (demo)",
            scanner=ScannerType.NESSUS,
            target=DELL_DEMO_IP,
            status=ScanStatus.RUNNING,
            progress=20,
            asset_id=asset.id,
            started_at=utcnow(),
        )

        session.add(scan)
        await session.flush()

        session.add(
            ScanLog(
                scan_id=scan.id,
                level="info",
                message=f"Started demo Nessus scan against {DELL_DEMO_IP}",
            )
        )

        # ------------------------------------------------------------------
        # FINDINGS
        # ------------------------------------------------------------------

        specs = list(overlap_specs) + list(NESSUS_ONLY_POOL)

        saved = 0
        for spec in specs:
            vulnerability = await _build_nessus_finding(session, asset, scan, spec)
            session.add(vulnerability)
            saved += 1

        scan.progress = 90
        scan.status = ScanStatus.COMPLETED
        scan.finished_at = utcnow()
        asset.last_scan_at = scan.finished_at

        session.add(
            ScanLog(
                scan_id=scan.id,
                level="info",
                message=(
                    f"Nessus demo scan completed; {saved} findings created "
                    f"({len(overlap_specs)} overlapping with Wazuh, "
                    f"{len(NESSUS_ONLY_POOL)} Nessus-only)"
                ),
            )
        )

        await session.commit()

        print(f"    Findings created: {saved}")
        print(f"    Overlapping with Wazuh (matched): {len(overlap_specs)}")
        print(f"    Nessus-only: {len(NESSUS_ONLY_POOL)}")

    print()
    print("=" * 70)
    print("NESSUS DEMO DATA COMPLETE")
    print("=" * 70)
    print(
        "Run a correlation report from the Reports page "
        "(scope: Correlation - Wazuh + Nessus) to see the results."
    )
    print("=" * 70)


# ============================================================================
# CLEAN DEMO DATA
# ============================================================================

async def clean_demo_data() -> None:

    async with AsyncSessionLocal() as session:

        result = await session.execute(
            select(Asset).where(
                Asset.description.like(
                    "Demo asset %"
                )
            )
        )

        assets = result.scalars().all()

        if not assets:

            print(
                "[OK] No demo assets found"
            )

            return

        count = len(assets)

        for asset in assets:
            await session.delete(asset)

        await session.commit()

        print(
            f"[OK] Removed {count} demo assets "
            "and their cascaded records"
        )


# ============================================================================
# MAIN
# ============================================================================

async def main(
    sync_wazuh_data: bool,
    clean_demo: bool,
    seed_nessus_demo: bool,
) -> None:

    try:

        await create_schema()

        await ensure_admin()

        await ensure_settings()

        if clean_demo:
            await clean_demo_data()

        if sync_wazuh_data:
            await sync_wazuh()

        if seed_nessus_demo:
            await seed_demo_nessus_data()

        print()
        print("[OK] Bootstrap completed")

    finally:

        await engine.dispose()


# ============================================================================
# CLI
# ============================================================================

if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        description=(
            "VulnGuard database bootstrap "
            "and Wazuh synchronization"
        )
    )

    parser.add_argument(
        "--no-wazuh",
        action="store_true",
        help=(
            "Do not synchronize Wazuh data"
        ),
    )

    parser.add_argument(
        "--clean-demo",
        action="store_true",
        help=(
            "Remove old demo assets before "
            "synchronization"
        ),
    )

    parser.add_argument(
        "--no-nessus-demo",
        action="store_true",
        help=(
            "Do not seed the demo Nessus scan used "
            "by the correlation engine demo"
        ),
    )

    args = parser.parse_args()

    asyncio.run(
        main(
            sync_wazuh_data=not args.no_wazuh,
            clean_demo=args.clean_demo,
            seed_nessus_demo=not args.no_nessus_demo,
        )
    )