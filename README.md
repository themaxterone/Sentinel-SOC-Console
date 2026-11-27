# Sentinel SOC Console

A web application for security investigations: Microsoft Entra ID sign-in audits, risky-user detection, KQL queries in Microsoft Sentinel and Defender XDR, IP reputation analysis, and report generation.

## Table of Contents

1. [Overview and Architecture](#overview-and-architecture)
2. [Key Features](#key-features)
3. [Requirements and Dependencies](#requirements-and-dependencies)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Usage](#usage)
7. [Modules and Workflows](#modules-and-workflows)
   - [Sign-in Audit](#1-sign-in-audit)
   - [Risky Users](#2-risky-users)
   - [Sentinel and Defender XDR](#3-sentinel-and-defender-xdr)
   - [IP Intelligence](#4-ip-intelligence)
   - [API Key Status](#5-api-key-status)
   - [Reports](#6-reports)
8. [Directory Structure and Generated Files](#directory-structure-and-generated-files)
9. [Multi-user Deployment](#multi-user-deployment)
10. [Security and Credentials](#security-and-credentials)
11. [Troubleshooting](#troubleshooting)

## Overview and Architecture

The application provides a local web interface served by Flask. Operations run as background jobs so the interface can display their status and progress while they query Microsoft Graph, Azure Log Analytics, Defender XDR, and threat intelligence services.

The project is organized into these main components:

- `templates/index.html`, `static/app.js`, and `static/styles.css`: user interface.
- `webapp.py`: Flask server, web API, job handling, data isolation, and report routes.
- `soc_workers.py` and `soc_core.py`: SOC operations, external service queries, and report generation.
- `auth.py`: local or Microsoft Entra authentication and token cache.
- `gui-soc.py` and `wsgi.py`: entry points for local execution and WSGI deployment.

The terminal displays concise messages for job start, current stage, progress milestones, warnings, errors, and completion. Routine HTTP requests are not shown.

## Key Features

- Single-user and bulk sign-in audits.
- Active Directory SID-to-UPN resolution.
- Entra ID Protection risky-user queries.
- KQL queries in Sentinel or Defender XDR.
- Optional detection and enrichment of public IPs with AbuseIPDB.
- Individual IP searches, IP lists, and PaloAlto IPS events from Sentinel.
- Intigriti IP checks and result filtering.
- HTML and CSV reports, plus blocklists.
- Per-user Entra authentication for multi-user deployments on a single instance.

## Requirements and Dependencies

### Environment

- Windows, Linux, or another Python-compatible environment.
- Python 3.10 or later.
- Network access to the Microsoft and threat intelligence services used.

Python dependencies are listed in `requirements.txt`:

- Flask
- MSAL
- Requests and urllib3
- Cryptography
- Waitress

### Microsoft Permissions

Operations require authentication and appropriate delegated permissions for the signed-in user:

- Microsoft Graph: read access to sign-in audit logs, users, Identity Protection, and Threat Hunting, depending on the operation.
- Azure Log Analytics: query access to the Sentinel workspace.
- Azure Resource Manager: permissions to discover subscriptions and workspaces.

The Graph scopes defined in `auth.py` are `AuditLog.Read.All`, `IdentityRiskyUser.Read.All`, `User.Read.All`, and `ThreatHunting.Read.All`. Availability also depends on the permissions and roles assigned in the tenant and Azure.

## Installation

Example using Conda in PowerShell:

```powershell
conda create -n gui-soc --override-channels -c conda-forge python=3.12 pip
conda activate gui-soc
python -m pip install -r requirements.txt
```

You can also use a Python virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

## Configuration

### Local Execution

By default, `SOC_AUTH_MODE` is `local`. In this mode, the application listens only on `127.0.0.1:5000`, and Microsoft authentication is requested interactively when an operation needs it.

The default workspace is configured through `DEFAULT_SENTINEL_WORKSPACE_ID` in `soc_core.py`. You can also discover or select a workspace in the interface.

### Third-party Service Credentials

AbuseIPDB and Intigriti credentials are currently defined in `soc_core.py`. Do not publish or share the project with active credentials. Rotate them and move them to a secure store or external configuration before deploying the application or granting access to others. Integration with LastPass Secrets Manager or Azure Key Vault has not been implemented.

### Entra Deployment Configuration

Multi-user mode uses a single-tenant Entra web application. Configure its redirect URI as `https://YOUR-HOST/auth/callback` and grant the delegated Graph, Log Analytics, and Azure Resource Manager permissions required by your tenant.

Store these values in the deployment environment's secret store, not in source code or the repository:

```powershell
$env:SOC_AUTH_MODE = "entra"
$env:SOC_TENANT_ID = "<tenant-guid>"
$env:SOC_CLIENT_ID = "<web-app-registration-client-id>"
$env:SOC_CLIENT_SECRET = "<web-app-registration-secret>"
$env:SOC_REDIRECT_URI = "https://YOUR-HOST/auth/callback"
$env:SOC_ALLOWED_HOSTS = "YOUR-HOST"
$env:SOC_TRUST_PROXY = "1"
$env:SOC_SESSION_SECRET = "<random-long-secret>"
$env:SOC_TOKEN_ENCRYPTION_KEY = "<Fernet-key>"
$env:SOC_DATA_DIR = "D:\soc-data"
$env:SOC_BIND_HOST = "127.0.0.1"
$env:PORT = "5000"
$env:SOC_HTTP_THREADS = "16"
$env:SOC_MAX_CONCURRENT_JOBS = "8"
```

Generate the session and encryption keys locally and store them securely:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

## Usage

From the project directory, activate the Python environment and start the server:

```powershell
cd "C:\path\to\project"
python gui-soc.py
```

In local mode, open `http://127.0.0.1:5000`. The terminal displays concise job progress and errors.

In Entra mode, `gui-soc.py` starts Waitress. You can also start the WSGI application directly:

```powershell
waitress-serve --listen=127.0.0.1:5000 --threads=16 wsgi:app
```

`wsgi.py` refuses to start unless Entra mode is enabled.

## Modules and Workflows

### 1. Sign-in Audit

- **Single account:** enter a UPN or SID.
- **Bulk list:** paste multiple UPNs/SIDs or upload a `.txt` file; duplicates are removed.
- **Translate SID only:** resolve SIDs to UPNs without downloading sign-in logs.
- **Lookback period:** select how many days to query.
- **IP enrichment:** optionally query AbuseIPDB for public IPs.
- **Retries and fallback:** if Microsoft Graph continues to return `429` and a Sentinel workspace is available, the application queries `SigninLogs` for that account.

Results are exported as HTML and CSV.

### 2. Risky Users

Searches for users marked as at risk in Entra ID Protection. You can select **High**, **Medium**, **Low**, or **All** risk levels and filter by the number of days since the last update. After the scan, you can start a sign-in audit for the discovered accounts.

### 3. Sentinel and Defender XDR

Run KQL queries using either of these engines:

- **Sentinel Workspace:** query Log Analytics in a selected or discovered workspace.
- **Defender XDR (Graph):** run an Advanced Hunting query through Microsoft Graph.

Results can be exported as HTML and CSV. Public IPs in the results can optionally be detected and enriched with AbuseIPDB.

### 4. IP Intelligence

Three input sources are supported:

- A single IP address.
- A `.txt` file containing multiple IPs.
- A Sentinel query for weekly PaloAlto IPS events with a configurable lookback period.

When enabled, Intigriti is queried first. IPs identified by Intigriti are not sent to AbuseIPDB or included in the exported results. IPs with an AbuseIPDB score of 10% or lower are also filtered out.

Bulk and Sentinel searches generate an HTML report, an extended CSV, and a TXT blocklist.

### 5. API Key Status

Checks the quotas of configured AbuseIPDB keys concurrently. The interface displays partially masked keys and summarizes the available queries. Do not share screenshots or logs that could expose credentials.

### 6. Reports

The **Reports** tab lists saved HTML reports and lets you preview or download them within the console. Exported reports include light and dark themes.

## Directory Structure and Generated Files

```text
├── auth.py
├── gui-soc.py
├── requirements.txt
├── soc_core.py
├── soc_workers.py
├── webapp.py
├── wsgi.py
├── templates/
│   └── index.html
├── static/
│   ├── app.js
│   ├── favicon.svg
│   └── styles.css
├── signInsLogs/
│   ├── sign-in audit reports (HTML and CSV)
│   └── uploads/
├── sentinelLogs/
│   └── KQL query reports (HTML and CSV)
└── abuseIpLogs/
    ├── IP intelligence reports (HTML)
    ├── extended results (CSV)
    └── blocklists (TXT)
```

In local mode, output directories are created alongside the project. In Entra mode, `SOC_DATA_DIR` contains user-separated data and the SQLite authentication database with the encrypted MSAL cache.

## Multi-user Deployment

Entra mode allows multiple people to use the same instance by signing in individually and selecting their own Microsoft account. Microsoft API calls use the signed-in user's delegated permissions. Jobs, reports, risky-user results, and token caches are separated by user.

Operational requirements:

- Run the application behind a reverse proxy that terminates HTTPS, overwrites forwarded headers, and is the only permitted route to the service.
- `SOC_TRUST_PROXY=1` configures trust in one proxy hop. `SOC_ALLOWED_HOSTS` must contain the permitted public hostnames.
- Use persistent storage for `SOC_DATA_DIR` and keep `SOC_TOKEN_ENCRYPTION_KEY` stable. If the key is lost or changed, users will need to authenticate again.
- Use **one application process and one instance** with multiple Waitress threads. The job queue and progress state are process-local; do not use multiple WSGI processes or replicas until that state is moved to a shared service.
- `SOC_MAX_CONCURRENT_JOBS` controls the maximum number of concurrent operations and accepts values from 1 to 16.
- If the proxy runs in another container or server, set `SOC_BIND_HOST=0.0.0.0` and restrict network access to the proxy only.

## Security and Credentials

- Do not store secrets in the repository or include them in reports or logs.
- Third-party credentials currently in `soc_core.py` must be rotated and moved to a secret store before any shared deployment.
- The Entra-mode MSAL cache is encrypted with Fernet in persistent storage.
- Entra mode fails closed if required configuration variables are missing.
- External queries are made only when the corresponding operation is started.
- **TLS validation is a known issue:** some outgoing requests currently use `verify=False`, which disables server certificate validation. This is not suitable for production. Configure the corporate certificate chain and update the requests to validate TLS before deploying to a shared environment.

## Troubleshooting

- **The application does not start in Entra mode:** check `SOC_AUTH_MODE`, all required variables, the allowed host, the HTTPS callback URI, and `SOC_TRUST_PROXY=1`.
- **Microsoft authorization is required:** connect the requested Microsoft account and confirm that it has the required Graph, Azure, or Log Analytics permissions.
- **Workspace discovery fails:** check the user's subscription access and assign the required Azure/Sentinel roles. You can also enter the workspace GUID manually.
- **Graph returns `429`:** calls include retries; for audits, Sentinel `SigninLogs` is used as a per-account fallback if a workspace is configured.
- **Older reports are missing:** verify that you are signed in as the expected user and that `SOC_DATA_DIR` points to the expected persistent storage.
- **Token decryption fails:** confirm that `SOC_TOKEN_ENCRYPTION_KEY` matches the Fernet key used when the cache was created.
- **The application cannot run multiple replicas:** jobs currently live in memory and require a single instance/process.
- **Corporate TLS certificate errors:** check HTTPS inspection and the corporate certificate configuration. Do not disable TLS validation as a general workaround; configure an appropriate trusted certificate chain instead.
