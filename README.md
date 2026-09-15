# 🛡️ VulnGuard

**VulnGuard** is an intelligent vulnerability management platform designed to centralize, analyze, prioritize, and track security vulnerabilities across an organization's assets.

The platform bridges the gap between **SOC analysts and penetration testers** by providing a centralized security workflow for vulnerability discovery, analysis, prioritization, remediation tracking, and reporting.

> **Project:** Intelligent Vulnerability Management Platform
> **Focus:** Cybersecurity · Vulnerability Management · Purple Team · SOC · Pentesting
> **Backend:** FastAPI + PostgreSQL
> **Frontend:** HTML · CSS · JavaScript
> **Security Integrations:** Wazuh · Trivy · Nessus

---

## 📌 Overview

Security teams often use several independent security tools to identify vulnerabilities.

For example:

* **Wazuh** → endpoint security and vulnerability detection
* **Nessus** → vulnerability assessment
* **Trivy** → container and software vulnerability scanning
* **Pentesting tools** → manual security validation

VulnGuard provides a centralized platform where these findings can be collected and managed.

The goal is to transform raw security findings into actionable information for security teams.

### Main workflow

```text
                    ┌─────────────────┐
                    │     Assets      │
                    │ Servers / Hosts │
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
          ┌────────┐     ┌────────┐     ┌────────┐
          │ Wazuh  │     │ Nessus │     │ Trivy  │
          └────┬───┘     └────┬───┘     └────┬───┘
               │              │              │
               └──────────────┼──────────────┘
                              ▼
                    ┌──────────────────┐
                    │     VulnGuard     │
                    │  Correlation &   │
                    │   Management     │
                    └────────┬─────────┘
                             │
             ┌───────────────┼────────────────┐
             ▼               ▼                ▼
        Prioritization   Remediation       Reports
             │               │                │
             └───────────────┼────────────────┘
                             ▼
                    ┌──────────────────┐
                    │ Security Teams   │
                    │ SOC / Pentesters │
                    └──────────────────┘
```

---

# ✨ Features

## 🔐 Authentication & Access Control

VulnGuard provides role-based access control for different security team members.

Supported roles include:

| Role          | Description                                        |
| ------------- | -------------------------------------------------- |
| `ADMIN`       | Full platform administration                       |
| `SOC_ANALYST` | Monitor and analyze security findings              |
| `PENTESTER`   | Work with vulnerabilities and security assessments |
| `VIEWER`      | Read-only access                                   |

The platform uses token-based authentication with access and refresh tokens.

---

## 📊 Dashboard

The dashboard provides a centralized security overview including:

* Total assets
* Vulnerability statistics
* Severity distribution
* Scan status
* Security findings
* Vulnerability trends
* Critical vulnerabilities
* Security activity

The objective is to give SOC analysts a quick understanding of the current security posture.

---

## 🖥️ Asset Management

VulnGuard allows security teams to manage monitored assets.

Examples:

* Servers
* Workstations
* Virtual machines
* Security infrastructure
* Network hosts

Asset information can be associated with vulnerability findings and security scans.

---

## 🔎 Vulnerability Management

The vulnerability management module provides centralized tracking of security findings.

Vulnerabilities can be:

* Identified
* Classified
* Prioritized
* Assigned
* Investigated
* Remediated
* Closed

Severity levels include:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

---

## 🧪 Security Scanning

VulnGuard integrates multiple security scanners.

### Wazuh

Used for endpoint security monitoring and vulnerability information.

The platform can communicate with the Wazuh API and synchronize vulnerability information.

### Nessus

Used for vulnerability assessment and network security scanning.

VulnGuard provides Nessus integration for:

* Scan management
* Scan execution
* Scan monitoring
* Finding collection

### Trivy

Trivy can be used to scan software and container-related assets for vulnerabilities.

---

# 🧠 Vulnerability Correlation

One of the main concepts behind VulnGuard is **correlation**.

Security findings coming from different tools can describe the same underlying security problem.

Instead of treating every scanner result independently, VulnGuard can correlate findings and provide a more unified view.

```text
Wazuh Finding
      │
      │
      ├──────────────┐
      │              │
      ▼              ▼
  Correlation    Asset Mapping
      │              │
      └───────┬──────┘
              ▼
      Unified Vulnerability
              │
              ▼
        Prioritization
```

This helps security teams reduce duplicate findings and focus on the vulnerabilities that matter most.

---

# 👥 Purple Team Approach

VulnGuard is designed around a **Purple Team** concept.

The platform connects the activities of:

### 🔴 Red Team / Pentesters

Pentesters identify and validate vulnerabilities through offensive security techniques.

### 🔵 Blue Team / SOC

SOC analysts monitor systems, investigate findings, prioritize vulnerabilities, and coordinate remediation.

### 🟣 Purple Team

VulnGuard helps connect these two workflows.

```text
             🔴 RED TEAM
                 │
          Vulnerability
             Discovery
                 │
                 ▼
          ┌─────────────┐
          │  VulnGuard  │
          └──────┬──────┘
                 │
          Correlation
          Prioritization
          Tracking
                 │
                 ▼
             🔵 BLUE TEAM
                 │
          Detection /
          Monitoring /
          Remediation
```

---

# 📄 Reporting

VulnGuard includes a reporting system for generating security reports.

Reports can help summarize:

* Vulnerabilities
* Severity
* Assets
* Scan results
* Security findings
* Remediation status

The backend contains a dedicated report generation service.

---

# ⚙️ Technology Stack

## Backend

* Python
* FastAPI
* SQLAlchemy
* PostgreSQL
* AsyncPG
* Pydantic
* HTTPX
* JWT authentication

## Frontend

* HTML5
* CSS3
* JavaScript
* Font Awesome

## Security Tools

* Wazuh
* Nessus
* Trivy
* OpenSearch / Wazuh Indexer

---

# 📁 Project Structure

```text
VulnGuard/
│
├── index.html
│
├── backend/
│   │
│   ├── app/
│   │   ├── api/
│   │   │   ├── routes/
│   │   │   │   ├── assets.py
│   │   │   │   ├── auth.py
│   │   │   │   ├── dashboard.py
│   │   │   │   ├── nessus.py
│   │   │   │   ├── reports.py
│   │   │   │   ├── scans.py
│   │   │   │   ├── settings.py
│   │   │   │   ├── users.py
│   │   │   │   └── vulnerabilities.py
│   │   │   │
│   │   │   ├── deps.py
│   │   │   ├── router.py
│   │   │   └── serializers.py
│   │   │
│   │   ├── core/
│   │   │   ├── config.py
│   │   │   └── security.py
│   │   │
│   │   ├── db/
│   │   │   ├── base.py
│   │   │   └── session.py
│   │   │
│   │   ├── models/
│   │   │   ├── asset.py
│   │   │   ├── report.py
│   │   │   ├── scan.py
│   │   │   ├── setting.py
│   │   │   ├── user.py
│   │   │   └── vulnerability.py
│   │   │
│   │   ├── schemas/
│   │   │
│   │   ├── services/
│   │   │   ├── correlation_engine.py
│   │   │   ├── report_generator.py
│   │   │   ├── scan_runner.py
│   │   │   ├── wazuh_sync.py
│   │   │   │
│   │   │   └── scanners/
│   │   │       ├── base.py
│   │   │       ├── nessus.py
│   │   │       ├── registry.py
│   │   │       └── trivy.py
│   │   │
│   │   └── utils/
│   │
│   ├── alembic/
│   └── seed.py
│
├── frontend/
│   ├── assets/
│   │   ├── css/
│   │   └── js/
│   │
│   ├── components/
│   ├── layout/
│   ├── pages/
│   ├── services/
│   └── utils/
│
└── README.md
```

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/VulnGuard.git
cd VulnGuard
```

---

# 🐍 Backend Setup

Go to the backend directory:

```bash
cd backend
```

Create a Python environment if desired:

```bash
python -m venv venv
```

Activate it on Windows:

```powershell
venv\Scripts\activate
```

Install the required dependencies:

```bash
pip install -r requirements.txt
```

---

# 🗄️ PostgreSQL

VulnGuard uses PostgreSQL.

Create a database and user:

```sql
CREATE DATABASE vmp;
CREATE USER vmp WITH PASSWORD 'your_password';
GRANT ALL PRIVILEGES ON DATABASE vmp TO vmp;
```

Configure the database connection through environment variables.

Example:

```env
DATABASE_URL=postgresql+asyncpg://vmp:your_password@localhost:5432/vmp
```

---

# 🔑 Environment Variables

**Never commit your real ****`.env`**** file.**

Create:

```text
backend/.env
```

Example configuration:

```env
ENVIRONMENT=development
DEBUG=false
API_PREFIX=/api

DATABASE_URL=postgresql+asyncpg://vmp:your_password@localhost:5432/vmp

SECRET_KEY=your_secret_key

ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080

CORS_ORIGINS=http://localhost:5500,http://127.0.0.1:5500,http://localhost:8080,http://127.0.0.1:8080

FIRST_ADMIN_EMAIL=admin@vulnguard.com
FIRST_ADMIN_PASSWORD=change_this_password

TRIVY_BINARY=trivy
TRIVY_TIMEOUT_SECONDS=900

WAZUH_API_URL=
WAZUH_API_USER=
WAZUH_API_PASSWORD=
WAZUH_VERIFY_SSL=false

WAZUH_INDEXER_URL=
WAZUH_INDEXER_USER=
WAZUH_INDEXER_PASSWORD=

NESSUS_URL=
NESSUS_ACCESS_KEY=
NESSUS_SECRET_KEY=
NESSUS_VERIFY_SSL=false
```

---

# 🏗️ Initialize the Database

Run:

```bash
python seed.py --no-wazuh
```

This initializes the database schema and creates the initial administrator.

For a complete environment with Wazuh synchronization:

```bash
python seed.py
```

---

# ▶️ Start VulnGuard

From the `backend` directory:

```bash
fastapi dev app/main.py
```

The application should then be available at:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

Health check:

```text
http://127.0.0.1:8000/health
```

---

# 🔌 API

VulnGuard exposes a REST API under:

```text
/api
```

Main API areas include:

```text
/api/login
/api/refresh
/api/logout
/api/me

/api/assets
/api/scans
/api/vulnerabilities
/api/reports
/api/users
/api/settings
/api/dashboard
/api/nessus
```

Interactive API documentation is available through FastAPI Swagger UI.

---

# 🛡️ Security

VulnGuard implements several security mechanisms including:

* JWT authentication
* Role-based access control
* Password hashing
* Security headers
* CORS configuration
* Protected administrative endpoints
* API authentication
* SSL verification configuration for integrations
* Centralized vulnerability management

Security headers include:

```text
X-Content-Type-Options
X-Frame-Options
Referrer-Policy
Permissions-Policy
```

---

# 🧪 Security Research / Lab Usage

VulnGuard is intended for:

* Cybersecurity laboratories
* Security research
* Vulnerability management
* SOC training
* Purple Team exercises
* Penetration testing workflows
* Security automation

Only scan systems and infrastructure that you own or have explicit authorization to test.

---

# 🗺️ Roadmap

Future improvements may include:

* [ ] Improved vulnerability deduplication
* [ ] CVSS-based prioritization
* [ ] EPSS integration
* [ ] CISA KEV integration
* [ ] Automated remediation workflows
* [ ] More scanner integrations
* [ ] Docker deployment
* [ ] CI/CD security pipeline
* [ ] Advanced RBAC
* [ ] Email notifications
* [ ] Security metrics
* [ ] Advanced reporting
* [ ] Vulnerability SLA tracking
* [ ] Audit logging
* [ ] Kubernetes security integration

---

# 🎯 Project Objectives

VulnGuard aims to provide a centralized platform capable of:

1. Collecting vulnerability data from multiple security tools.
2. Associating vulnerabilities with affected assets.
3. Correlating security findings.
4. Prioritizing vulnerabilities.
5. Tracking remediation.
6. Supporting SOC analysts.
7. Supporting penetration testers.
8. Generating security reports.
9. Improving collaboration between Red and Blue Teams.

---

# 👨‍💻 Author

**Fouad Naatani**

Cybersecurity Student · Penetration Testing · SOC · Purple Team · Cloud Security

---

# ⚠️ Disclaimer

VulnGuard is developed for educational, research, and authorized security testing purposes.

Do not use the platform to scan, attack, or access systems without explicit authorization.

---

## ⭐ If you find this project useful

Give the repository a ⭐ and feel free to contribute.
