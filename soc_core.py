import concurrent.futures
import csv
from datetime import datetime, timedelta, timezone
import hashlib
import html
import ipaddress
import json
import os
import re
import sys
import threading
import time
import msal
import requests
import urllib3
from auth import (
    AUTH_MODE,
    AZURE_ARM_SCOPES,
    DATA_ROOT,
    GRAPH_SCOPES,
    LOG_ANALYTICS_SCOPES,
    current_job_user_id,
)

# Suppress SSL warnings in corporate environments with proxy inspection
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================================================================
# CONFIGURATION & OUTPUT DIRECTORIES
# =========================================================================
# Microsoft Graph Command Line Tools official public Client ID (for Graph API)
CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

# Microsoft Azure CLI official public Client ID (for Log Analytics / Sentinel & ARM API)
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

AUTHORITY = "https://login.microsoftonline.com/organizations"

# Default Microsoft Sentinel Workspace ID (GUID)
DEFAULT_SENTINEL_WORKSPACE_ID = "e9b01d76-96a7-4acf-843b-5e8ba5640cb1"

DIR_SIGNINS = str(DATA_ROOT / "signInsLogs")
DIR_ABUSEIP = str(DATA_ROOT / "abuseIpLogs")
DIR_SENTINEL = str(DATA_ROOT / "sentinelLogs")

os.makedirs(DIR_SIGNINS, exist_ok=True)
os.makedirs(DIR_ABUSEIP, exist_ok=True)
os.makedirs(DIR_SENTINEL, exist_ok=True)

OUTPUT_DIRECTORIES = {
    "signins": DIR_SIGNINS,
    "abuseip": DIR_ABUSEIP,
    "sentinel": DIR_SENTINEL,
}


def get_output_dir(folder, user_id=None):
    base_directory = OUTPUT_DIRECTORIES.get(folder)
    if base_directory is None:
        raise ValueError(f"Unknown report folder: {folder}")
    if AUTH_MODE == "entra":
        owner_id = user_id if user_id is not None else current_job_user_id()
        if not owner_id:
            raise RuntimeError("A signed-in user is required to access report storage.")
        owner_key = hashlib.sha256(owner_id.encode("utf-8")).hexdigest()
        directory = os.path.join(str(DATA_ROOT), "users", owner_key, os.path.basename(base_directory))
    else:
        directory = base_directory
    os.makedirs(directory, exist_ok=True)
    return directory

# Intigriti Access Token (Company / Researcher IP Verification)
INTIGRITI_ACCESS_TOKEN = "4F38FC2441D5912C1B42CFA2BCDA5464321E8E0083951880E84716D44664C9D7-1"
INTIGRITI_API_URL = "https://api.intigriti.com/external/company/v2/iplookup"

# AbuseIPDB API Keys Pool
ABUSEIPDB_API_KEYS = [
    "8b755fbc1c5d99c7c91a17d0d3985c71c8ec7112123a9d52955b025beddaf2f93e1f406c6de63ba6",
    "79355356a82c71fcdd7f39bfa3efef060bd636c242d54946b17ef2e28e7740868cd8c393ccb61077",
    "23e158b28e1c2c150e523a2ed0239d69b767b871ff6a4ccd9da5dd39f1d80f05b6fb5634a1f45619", #Trash1
    "111718fff330b38f2cfa1756e367917a0501e2aff07004a2dc066410dbac209c9741600452b8c7ca", #Proton3
    "c63cc76859b06be105d814f3cdbff749e91a2a7a6ce45e40b18069a7066a8de238278cd6cc63ae1f"  #Proton3
]
# =========================================================================

ABUSE_CATEGORIES = {
    3: "Fraud Orders", 4: "DDoS Attack", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 14: "Port Scan", 15: "Hacking", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted"
}

ENTRA_ERRORS = {
    50034: "The user account does not exist in the directory.",
    50053: "Account is temporarily locked out due to multiple failed password attempts.",
    50055: "The user's password has expired.",
    50057: "The user account is disabled.",
    50058: "Silent sign-in failed (user interaction required).",
    50074: "Multifactor authentication (MFA) is required.",
    50076: "Strong authentication (MFA) is required due to security policies.",
    50079: "The user must enroll in multifactor authentication.",
    50088: "The external user does not belong to the target tenant.",
    50126: "Invalid username or password.",
    50131: "The device does not comply with security policies or is not trusted.",
    50144: "Password has expired and must be reset.",
    53003: "Access blocked by Conditional Access policies.",
    70008: "Refresh token has expired.",
    70043: "Session revoked or terminated by the administrator."
}

SID_REGEX = re.compile(r'\bS-1-\d+(?:-\d+)+\b', re.IGNORECASE)
EMAIL_REGEX = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
IPV4_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
GUID_REGEX = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')

IP_CACHE = {}
INTIGRITI_CACHE = {}
MSAL_APPS = {}
CURRENT_KEY_INDEX = 0


class GraphRateLimitError(Exception):
    """Raised when Microsoft Graph persists with HTTP 429 Too Many Requests."""
    pass


def get_current_api_key():
    global CURRENT_KEY_INDEX
    if not ABUSEIPDB_API_KEYS:
        return None
    return ABUSEIPDB_API_KEYS[CURRENT_KEY_INDEX]


def rotate_api_key(log_callback):
    global CURRENT_KEY_INDEX
    if len(ABUSEIPDB_API_KEYS) <= 1:
        return False
    CURRENT_KEY_INDEX = (CURRENT_KEY_INDEX + 1) % len(ABUSEIPDB_API_KEYS)
    log_callback(f"[!] Quota reached. Rotating to API Key #{CURRENT_KEY_INDEX + 1}...", "warn")
    return True


def get_access_token(log_callback, scopes=None, client_id=None):
    target_scopes = scopes if scopes is not None else GRAPH_SCOPES
    target_client = client_id if client_id is not None else CLIENT_ID

    if AUTH_MODE == "entra":
        from auth import acquire_user_token
        token = acquire_user_token(current_job_user_id(), target_scopes)
        log_callback("[+] Using the signed-in user's Microsoft authorization.", "success")
        return token

    if target_client not in MSAL_APPS:
        MSAL_APPS[target_client] = msal.PublicClientApplication(target_client, authority=AUTHORITY)

    app = MSAL_APPS[target_client]
    accounts = app.get_accounts()
    if accounts:
        silent_res = app.acquire_token_silent(target_scopes, account=accounts[0])
        if silent_res and "access_token" in silent_res:
            return silent_res["access_token"]

    log_callback("[*] Opening browser for Microsoft interactive authentication...", "info")
    result = app.acquire_token_interactive(scopes=target_scopes, prompt="select_account")
    if "access_token" in result:
        log_callback("[+] Authentication successful.", "success")
        return result["access_token"]
    else:
        error_msg = result.get("error_description", result.get("error"))
        raise Exception(f"Authentication error: {error_msg}")


def graph_get_with_retry(url, headers, log_callback, max_retries=3, allow_404=False, cap_wait=15):
    """Performs a GET request to Microsoft Graph handling timeouts, HTTP 429, and transient 5xx errors."""
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(url, headers=headers, timeout=(15, 90), verify=False)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            wait_seconds = min(5 * attempt, cap_wait)
            if attempt == max_retries:
                raise Exception(f"Microsoft Graph request timed out after {max_retries} attempts: {e}")
            log_callback(
                f"[!] Graph Timeout/Network delay. Retrying in {wait_seconds}s ({attempt}/{max_retries})...",
                "warn"
            )
            time.sleep(wait_seconds)
            continue

        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            header_wait = int(retry_after) if (retry_after and retry_after.isdigit()) else (5 * attempt)
            wait_seconds = min(header_wait, cap_wait)
            if attempt == max_retries:
                raise GraphRateLimitError(f"429 Too Many Requests persisted after {max_retries} attempt(s).")
            log_callback(
                f"[!] Graph Rate Limit (429). Waiting {wait_seconds}s before retry ({attempt}/{max_retries})...",
                "warn"
            )
            time.sleep(wait_seconds)
            continue

        if resp.status_code in (502, 503, 504):
            wait_seconds = min(5 * attempt, cap_wait)
            if attempt == max_retries:
                resp.raise_for_status()
            log_callback(
                f"[!] Graph HTTP {resp.status_code}. Waiting {wait_seconds}s before retry ({attempt}/{max_retries})...",
                "warn"
            )
            time.sleep(wait_seconds)
            continue

        if allow_404 and resp.status_code == 404:
            return resp

        resp.raise_for_status()
        return resp

    raise Exception("Microsoft Graph request failed after maximum retries.")


def safe_json_parse(value, default):
    """Safely parses JSON strings returned by Sentinel Log Analytics dynamic columns."""
    if isinstance(value, type(default)):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            if isinstance(parsed, type(default)):
                return parsed
        except Exception:
            pass
    return default


def fetch_signins_from_sentinel(user, days, ws_guid, log_callback):
    """Fallback: queries Sentinel SigninLogs and normalizes rows into Microsoft Graph event format."""
    la_token = get_access_token(
        log_callback,
        scopes=LOG_ANALYTICS_SCOPES,
        client_id=AZURE_CLI_CLIENT_ID
    )
    safe_user = user.replace('"', '').replace("'", "")
    kql = (
        f"SigninLogs\n"
        f"| where TimeGenerated >= ago({days}d)\n"
        f"| where UserPrincipalName =~ \"{safe_user}\"\n"
        f"| project TimeGenerated, UserPrincipalName, UserDisplayName, AppDisplayName, "
        f"IPAddress, ResultType, ResultDescription, Location, LocationDetails, DeviceDetail, ConditionalAccessPolicies\n"
        f"| order by TimeGenerated desc"
    )

    url = f"https://api.loganalytics.io/v1/workspaces/{ws_guid}/query"
    headers = {"Authorization": f"Bearer {la_token}", "Content-Type": "application/json"}
    log_callback(f"    [*] Querying Sentinel SigninLogs (WS: {ws_guid}) for {user}...", "info")

    resp = requests.post(url, headers=headers, json={"query": kql}, timeout=90, verify=False)
    if not resp.ok:
        raise Exception(f"Sentinel Log Analytics HTTP {resp.status_code}: {resp.text}")

    data = resp.json()
    tables = data.get("tables", [])
    if not tables:
        return []

    cols = [c["name"] for c in tables[0].get("columns", [])]
    raw_rows = tables[0].get("rows", [])

    normalized_events = []
    for raw_row in raw_rows:
        row = dict(zip(cols, raw_row))

        raw_code = row.get("ResultType", 0)
        try:
            err_code = int(raw_code) if raw_code not in (None, "") else 0
        except (ValueError, TypeError):
            err_code = 0 if str(raw_code).strip() == "0" else 1

        loc_details = safe_json_parse(row.get("LocationDetails"), {})
        if not loc_details.get("countryOrRegion") and row.get("Location"):
            loc_details["countryOrRegion"] = str(row.get("Location"))

        dev_details = safe_json_parse(row.get("DeviceDetail"), {})
        ca_policies = safe_json_parse(row.get("ConditionalAccessPolicies"), [])

        normalized_events.append({
            "createdDateTime": row.get("TimeGenerated") or "N/A",
            "userPrincipalName": row.get("UserPrincipalName") or user,
            "userDisplayName": row.get("UserDisplayName") or "N/A",
            "appDisplayName": row.get("AppDisplayName") or "N/A",
            "ipAddress": row.get("IPAddress") or "N/A",
            "status": {
                "errorCode": err_code,
                "failureReason": row.get("ResultDescription") or ""
            },
            "location": loc_details,
            "deviceDetail": dev_details,
            "appliedConditionalAccessPolicies": ca_policies
        })

    return normalized_events


def extract_workspace_guid(raw_text):
    """Extracts the 36-char Workspace GUID from raw input or 'Name (GUID)' dropdown items."""
    if not raw_text:
        return ""
    match = GUID_REGEX.search(raw_text.strip())
    return match.group(0) if match else ""


def discover_sentinel_workspaces(log_callback):
    """Queries Azure Resource Manager to list available Log Analytics / Sentinel workspaces."""
    arm_token = get_access_token(
        log_callback,
        scopes=AZURE_ARM_SCOPES,
        client_id=AZURE_CLI_CLIENT_ID
    )
    headers = {"Authorization": f"Bearer {arm_token}", "Content-Type": "application/json"}

    subs_url = "https://management.azure.com/subscriptions?api-version=2022-12-01"
    subs_resp = requests.get(subs_url, headers=headers, timeout=20, verify=False)
    subs_resp.raise_for_status()
    subscriptions = subs_resp.json().get("value", [])

    discovered = []
    for sub in subscriptions:
        sub_id = sub.get("subscriptionId")
        sub_name = sub.get("displayName", sub_id)
        if not sub_id:
            continue

        ws_url = (
            f"https://management.azure.com/subscriptions/{sub_id}"
            f"/providers/Microsoft.OperationalInsights/workspaces?api-version=2022-10-01"
        )
        ws_resp = requests.get(ws_url, headers=headers, timeout=20, verify=False)
        if not ws_resp.ok:
            continue

        for ws in ws_resp.json().get("value", []):
            ws_name = ws.get("name", "Unknown")
            customer_id = ws.get("properties", {}).get("customerId")
            if customer_id:
                discovered.append({
                    "label": f"{ws_name} ({customer_id})",
                    "name": ws_name,
                    "guid": customer_id,
                    "subscription": sub_name
                })

    return discovered


def resolve_targets_to_upns(raw_targets, token, log_callback):
    """Resolves on-premises AD SIDs (S-1-5-21-...) to Entra ID UPNs while keeping valid emails intact."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    resolved_upns = []
    seen = set()

    for target in raw_targets:
        clean_target = target.strip()
        if SID_REGEX.fullmatch(clean_target):
            sid_upper = clean_target.upper()
            log_callback(f"[*] Resolving SID {sid_upper} via Microsoft Graph...", "info")
            url = (
                f"https://graph.microsoft.com/v1.0/users?"
                f"$filter=onPremisesSecurityIdentifier eq '{sid_upper}'&$select=id,userPrincipalName,displayName"
            )
            try:
                resp = graph_get_with_retry(url, headers, log_callback)
                users = resp.json().get("value", [])
                if users:
                    upn = users[0].get("userPrincipalName", "").strip().lower()
                    disp = users[0].get("displayName", "N/A")
                    log_callback(f"    [+] Resolved: {sid_upper} -> {upn} ({disp})", "success")
                    if upn and upn not in seen:
                        seen.add(upn)
                        resolved_upns.append(upn)
                else:
                    log_callback(f"    [-] No Entra ID user found matching SID: {sid_upper}", "danger")
            except Exception as e:
                log_callback(f"    [!] Error resolving SID {sid_upper}: {e}", "danger")
        else:
            em = clean_target.lower()
            if em not in seen:
                seen.add(em)
                resolved_upns.append(em)

    return resolved_upns


def is_public_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False


def check_intigriti_ip(ip, log_callback):
    """Queries Intigriti v2 iplookup endpoint and returns True if exists==True."""
    if ip in INTIGRITI_CACHE:
        return INTIGRITI_CACHE[ip]

    if not INTIGRITI_ACCESS_TOKEN or INTIGRITI_ACCESS_TOKEN.startswith("YOUR_INTIGRITI"):
        return False

    headers = {
        "accept": "application/json",
        "authorization": f"Bearer {INTIGRITI_ACCESS_TOKEN.strip()}"
    }

    try:
        url = f"{INTIGRITI_API_URL}?ipAddress={ip}"
        response = requests.get(url, headers=headers, timeout=10, verify=False)

        if response.status_code == 200:
            data = response.json()
            is_match = bool(data.get("exists", False))
            INTIGRITI_CACHE[ip] = is_match
            return is_match

        elif response.status_code in (401, 403):
            log_callback(f"[!] Intigriti API unauthorized (HTTP {response.status_code}). Check INTIGRITI_ACCESS_TOKEN.", "warn")
            INTIGRITI_CACHE[ip] = False
            return False

        else:
            INTIGRITI_CACHE[ip] = False
            return False

    except Exception as e:
        log_callback(f"[!] Intigriti lookup error for {ip}: {e}", "warn")
        INTIGRITI_CACHE[ip] = False
        return False


def check_abuseipdb(ip, log_callback):
    if not ip or ip == "N/A":
        return {"score": 0, "reports": 0, "categories": [], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}

    if ip in IP_CACHE:
        return IP_CACHE[ip]

    if not is_public_ip(ip):
        res = {"score": 0, "reports": 0, "categories": ["Private / Internal IP"], "risk": "Internal", "isp": "Internal Network", "domain": "N/A", "country": "Internal"}
        IP_CACHE[ip] = res
        return res

    if not ABUSEIPDB_API_KEYS:
        res = {"score": 0, "reports": 0, "categories": ["No API Key"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
        IP_CACHE[ip] = res
        return res

    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90", "verbose": "true"}
    attempts = 0
    max_attempts = len(ABUSEIPDB_API_KEYS)

    while attempts < max_attempts:
        active_key = get_current_api_key()
        if not active_key or active_key.startswith("YOUR_API_KEY"):
            res = {"score": 0, "reports": 0, "categories": ["No API Key"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
            IP_CACHE[ip] = res
            return res

        headers = {"Accept": "application/json", "Key": active_key}
        try:
            response = requests.get(url, headers=headers, params=params, timeout=12, verify=False)
            if response.status_code == 429:
                attempts += 1
                if rotate_api_key(log_callback) and attempts < max_attempts:
                    continue
                else:
                    res = {"score": 0, "reports": 0, "categories": ["Rate Limited (429)"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
                    IP_CACHE[ip] = res
                    return res
            if response.status_code == 401:
                attempts += 1
                rotate_api_key(log_callback)
                continue

            response.raise_for_status()
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)
            reports = data.get("totalReports", 0)
            isp = data.get("isp") or "N/A"
            domain = data.get("domain") or "N/A"
            country = data.get("countryCode") or "N/A"

            reported_cats = set()
            for r in data.get("reports", []):
                for c in r.get("categories", []):
                    reported_cats.add(c)
            cat_labels = [ABUSE_CATEGORIES.get(c, f"Category {c}") for c in reported_cats]

            risk = "Malicious" if score >= 60 else "Suspicious" if score >= 20 else "Clean"
            res = {"score": score, "reports": reports, "categories": sorted(cat_labels), "risk": risk, "isp": isp, "domain": domain, "country": country}
            time.sleep(0.12)
            IP_CACHE[ip] = res
            return res
        except Exception as e:
            res = {"score": 0, "reports": 0, "categories": [f"Error: {e}"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
            IP_CACHE[ip] = res
            return res

    res = {"score": 0, "reports": 0, "categories": ["Lookup Failed"], "risk": "Unknown", "isp": "N/A", "domain": "N/A", "country": "N/A"}
    IP_CACHE[ip] = res
    return res


def check_single_key(key_index, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key.strip()}
    params = {"ipAddress": "1.1.1.1", "maxAgeInDays": "1"}
    masked_key = f"{api_key[:6]}...{api_key[-4:]}" if len(api_key) > 10 else api_key

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10, verify=False)
        limit = response.headers.get("X-RateLimit-Limit")
        remaining = response.headers.get("X-RateLimit-Remaining")
        reset_ts = response.headers.get("X-RateLimit-Reset")

        reset_str = "N/A"
        if reset_ts and reset_ts.isdigit():
            reset_dt = datetime.fromtimestamp(int(reset_ts), tz=timezone.utc)
            reset_str = reset_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        if response.status_code == 200:
            limit_val = int(limit) if limit and limit.isdigit() else 1000
            rem_val = int(remaining) if remaining and remaining.isdigit() else 0
            used = limit_val - rem_val
            usage_pct = (used / limit_val) * 100 if limit_val > 0 else 0
            return {"index": key_index, "key": masked_key, "status": "Active", "limit": limit_val, "remaining": rem_val, "used_pct": f"{usage_pct:.1f}%", "reset": reset_str, "color": "#16a34a"}
        elif response.status_code == 429:
            return {"index": key_index, "key": masked_key, "status": "Exhausted (429)", "limit": limit or 1000, "remaining": 0, "used_pct": "100.0%", "reset": reset_str, "color": "#dc2626"}
        elif response.status_code == 401:
            return {"index": key_index, "key": masked_key, "status": "Unauthorized (401)", "limit": "-", "remaining": "-", "used_pct": "-", "reset": "-", "color": "#991b1b"}
        else:
            return {"index": key_index, "key": masked_key, "status": f"HTTP {response.status_code}", "limit": "-", "remaining": "-", "used_pct": "-", "reset": "-", "color": "#d97706"}
    except Exception as e:
        return {"index": key_index, "key": masked_key, "status": f"Error: {type(e).__name__}", "limit": "-", "remaining": "-", "used_pct": "-", "reset": "-", "color": "#d97706"}


# =========================================================================
# HTML & REPORT GENERATORS
# =========================================================================
REPORT_THEME_CSS = """
/* Sentinel SOC report theme v3 */
:root {
    color-scheme: light;
    --bg-primary: #f5f7fb;
    --surface: #ffffff;
    --text-main: #172337;
    --text-muted: #536176;
    --border-color: #e6eaf1;
    --primary: #3478f6;
    --success: #159570;
    --danger: #d54d58;
    --warning: #c47a25;
    --success-bg: #e7f6f0;
    --danger-bg: #fdecef;
    --warning-bg: #fff3e4;
    --info-bg: #eaf1ff;
}
* { box-sizing: border-box; }
body {
    margin: 0;
    padding: 30px;
    background: var(--bg-primary);
    color: var(--text-main);
    font: 14px/1.5 "Segoe UI", "Segoe UI Variable", Arial, sans-serif;
}
.header, .controls, .table-container, .section-card, .query-box {
    max-width: 1440px;
    margin-right: auto;
    margin-left: auto;
}
.header {
    align-items: flex-end;
    gap: 18px;
    margin-bottom: 20px;
}
.header h1 { font-size: 25px; font-weight: 800; letter-spacing: -.6px; }
.header p { color: var(--text-muted); font-size: 12px; }
.stats { gap: 11px; }
.stat-card {
    min-width: 95px;
    padding: 13px 17px;
    border: 1px solid var(--border-color);
    border-radius: 11px;
    background: var(--surface);
    box-shadow: 0 8px 26px rgba(19, 38, 72, .045);
}
.stat-card .num { font-size: 22px; }
.stat-card .label { color: #8490a2; font-size: 9px; letter-spacing: .5px; }
.section-card, .table-container {
    overflow: auto;
    border: 1px solid var(--border-color);
    border-radius: 12px;
    background: var(--surface);
    box-shadow: 0 8px 26px rgba(19, 38, 72, .045);
}
.section-card { margin-bottom: 19px; padding: 17px; }
.section-title { font-size: 14px; }
.controls { gap: 10px; }
.search-box {
    min-height: 38px;
    border: 1px solid var(--border-color);
    border-radius: 7px;
    color: var(--text-main);
    background: var(--surface);
}
.search-box:focus { border-color: var(--primary); }
.filter-btn, .filter-btn-sm {
    border: 1px solid var(--border-color);
    border-radius: 7px;
    color: var(--text-muted);
    background: var(--surface);
    transition: .15s ease;
}
.filter-btn { padding: 8px 13px; font-size: 10px; }
.filter-btn-sm { font-size: 9px; }
.filter-btn:hover, .filter-btn-sm:hover { border-color: var(--primary); }
.filter-btn.active, .filter-btn-sm:hover {
    border-color: var(--primary);
    color: #fff;
    background: var(--primary);
}
table { width: 100%; border-collapse: collapse; font-size: 11px; }
thead { position: sticky; top: 0; z-index: 2; background: #f0f3f9; }
th {
    padding: 11px 13px;
    border-bottom: 1px solid var(--border-color);
    color: #536176;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: .35px;
    text-transform: uppercase;
}
td { padding: 11px 13px; border-bottom: 1px solid var(--border-color); }
tr:hover { background: #f8faff; }
.badge { border-radius: 6px; font-size: 9px; }
.badge-success { color: var(--success); background: var(--success-bg); }
.badge-danger { color: var(--danger); background: var(--danger-bg); }
.badge-warning { color: var(--warning); background: var(--warning-bg); }
.badge-info { color: var(--primary); background: var(--info-bg); }
.failure-desc { border-radius: 5px; }
.progress-bar-bg { background: #e9edf4; }
.category-tag { border: 1px solid var(--border-color); border-radius: 5px; background: #f0f3f9; }
.query-box { border-radius: 9px; }
.font-mono { font-family: Consolas, "Cascadia Code", monospace; }
.text-muted { color: #8490a2; }
html[data-theme="dark"] {
    color-scheme: dark;
    --bg-primary: #0c1421;
    --surface: #121e2e;
    --text-main: #e7edf7;
    --text-muted: #a7b3c5;
    --border-color: #26364c;
    --primary: #6a9cff;
    --success: #58c29f;
    --danger: #f17d87;
    --warning: #edbd69;
    --success-bg: #183a35;
    --danger-bg: #422832;
    --warning-bg: #44351f;
    --info-bg: #1a2c49;
}
html[data-theme="dark"] thead { background: #1b2a40; }
html[data-theme="dark"] th { color: #c2cede; }
html[data-theme="dark"] tr:hover { background: #172437; }
html[data-theme="dark"] .summary-table th {
    color: #c2cede;
    background: #1b2a40;
    border-bottom-color: #26364c;
}
html[data-theme="dark"] .summary-table td {
    color: var(--text-main);
    background: var(--surface);
    border-bottom-color: #26364c;
}
html[data-theme="dark"] .summary-table tbody tr:hover td {
    background: #172437;
}
html .signins-table-container {
    max-height: 1200px;
}
html[data-theme="dark"] .category-tag { color: #c2cede; background: #1b2a40; }
html[data-theme="dark"] .progress-bar-bg { background: #26364c; }
html[data-theme="dark"] .search-box,
html[data-theme="dark"] .filter-btn,
html[data-theme="dark"] .filter-btn-sm {
    color: var(--text-main);
    background: var(--surface);
}
html[data-theme="dark"] .filter-btn:hover,
html[data-theme="dark"] .filter-btn-sm:hover {
    color: #ffffff;
    background: #25395b;
}
html[data-theme="dark"] .filter-btn.active {
    color: #ffffff;
    background: var(--primary);
}
html[data-theme="dark"] .btn-filters {
    color: var(--text-main);
}
html[data-theme="dark"] .stat-card,
html[data-theme="dark"] .table-container,
html[data-theme="dark"] .section-card,
html[data-theme="dark"] .query-box {
    color: var(--text-main);
    background: var(--surface);
    box-shadow: 0 8px 26px rgba(0, 0, 0, .14);
}
html[data-theme="dark"] .category-tag {
    border-color: #26364c;
}
html[data-theme="light"] thead {
    background: #f0f3f9;
}
@media (max-width: 760px) {
    body { padding: 16px; }
    .header { align-items: flex-start; }
    .stats { width: 100%; }
}
"""


def _apply_report_theme(document):
    theme_script = """<script>
(() => {
    const root = document.documentElement;
    const setTheme = (theme) => {
        if (theme === "light" || theme === "dark") root.dataset.theme = theme;
    };
    setTheme(window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    window.addEventListener("message", (event) => {
        if (event.source === window.parent && event.data && event.data.type === "soc-theme") {
            setTheme(event.data.theme);
        }
    });
})();
</script>"""
    return document.replace("</head>", f"<style>{REPORT_THEME_CSS}</style>{theme_script}</head>", 1)


def export_signins_html(filepath, title_label, days, records, user_summaries, use_abuseip=True):
    total = len(records)
    success_count = sum(1 for r in records if r["is_success"])
    failure_count = total - success_count
    malicious_ips = sum(1 for r in records if r.get("abuse_risk") == "Malicious")
    suspicious_ips = sum(1 for r in records if r.get("abuse_risk") == "Suspicious")
    total_users_count = len(user_summaries)

    account_summary_rows = []
    for u in user_summaries:
        account_summary_rows.append(f"""
        <tr>
            <td class="font-mono"><strong>{html.escape(u['user'])}</strong></td>
            <td><strong>{u['total']}</strong></td>
            <td style="color: var(--success); font-weight: 700;">{u['success']}</td>
            <td style="color: var(--danger); font-weight: 700;">{u['failures']}</td>
            {"<td style='color: var(--danger); font-weight: 700;'>" + str(u['malicious']) + "</td>" if use_abuseip else ""}
            {"<td style='color: var(--warning); font-weight: 700;'>" + str(u['suspicious']) + "</td>" if use_abuseip else ""}
            <td>{u['unique_ips']}</td>
            <td>
                <button class="filter-btn-sm" onclick="filterByUser('{html.escape(u['user'])}')">Filter Logs</button>
            </td>
        </tr>
        """)

    rows_html = []
    for r in records:
        status_cell = '<span class="badge badge-success">Success</span>' if r["is_success"] else f'<span class="badge badge-danger">Failure ({r["error_code"]})</span><div class="failure-desc">{html.escape(r["failure_desc"])}</div>'

        if use_abuseip:
            risk = r.get("abuse_risk", "Unknown")
            score = r.get("abuse_score", 0)
            bar_color = "#dc2626" if risk == "Malicious" else "#d97706" if risk == "Suspicious" else "#64748b" if risk == "Internal" else "#16a34a"
            badge_cls = "badge-danger" if risk == "Malicious" else "badge-warning" if risk == "Suspicious" else "badge-info" if risk == "Internal" else "badge-success"
            cats_text = ", ".join(r.get("abuse_categories", [])) if r.get("abuse_categories") else "Clean"
            ip_cell = f"""
            <div class="ip-block">
                <span class="font-mono"><strong>{html.escape(r['ip'])}</strong></span>
                <div><span class="badge {badge_cls}">{risk} ({score}%)</span> <small class="text-muted">{r.get('abuse_reports', 0)} rep.</small></div>
                <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: {score}%; background-color: {bar_color};"></div></div>
                <div class="cats-tags text-muted">{html.escape(cats_text)}</div>
            </div>"""
        else:
            risk = "N/A"
            ip_cell = f'<span class="font-mono"><strong>{html.escape(r["ip"])}</strong></span>'

        rows_html.append(f"""
        <tr data-status="{r['status']}" data-risk="{risk}" data-user="{html.escape(r['user'].lower())}">
            <td class="font-mono text-nowrap">{html.escape(r['datetime'])}</td>
            <td><strong>{html.escape(r['user'])}</strong><br><small class="text-muted">{html.escape(r['user_display'])}</small></td>
            <td>{html.escape(r['app'])}</td>
            <td class="status-cell">{status_cell}</td>
            <td class="ip-cell">{ip_cell}</td>
            <td>{html.escape(r['location'])}</td>
            <td>{html.escape(r['os'])}</td>
            <td>{html.escape(r['browser'])}</td>
        </tr>""")

    abuse_cards_html = f"""
        <div class="stat-card"><span class="num" style="color: var(--danger);">{malicious_ips}</span><span class="label">Malicious IPs</span></div>
        <div class="stat-card"><span class="num" style="color: var(--warning);">{suspicious_ips}</span><span class="label">Suspicious IPs</span></div>
    """ if use_abuseip else ""

    abuse_filter_btns_html = """
        <button class="filter-btn" onclick="setFilter('Malicious', this)">Malicious IP</button>
        <button class="filter-btn" onclick="setFilter('Suspicious', this)">Suspicious IP</button>
        <button class="filter-btn" onclick="setFilter('Clean', this)">Clean IP</button>
    """ if use_abuseip else ""

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Sign-in Audit - {html.escape(title_label)}</title>
    <style>
        :root {{
            --bg-primary: #f8fafc; --surface: #ffffff; --text-main: #0f172a; --text-muted: #64748b;
            --border-color: #e2e8f0; --primary: #2563eb; --success: #16a34a; --danger: #dc2626;
            --warning: #d97706; --success-bg: #dcfce7; --danger-bg: #fee2e2; --warning-bg: #fef3c7; --info-bg: #e2e8f0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg-primary); color: var(--text-main); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 20px; }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
        .header p {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats {{ display: flex; gap: 12px; flex-wrap: wrap; }}
        .stat-card {{ background: var(--surface); padding: 10px 18px; border-radius: 10px; border: 1px solid var(--border-color); display: flex; flex-direction: column; align-items: center; min-width: 90px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }}
        .stat-card .num {{ font-size: 1.5rem; font-weight: 700; }}
        .stat-card .label {{ font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; font-weight: 700; }}

        .section-card {{
            background: var(--surface); border: 1px solid var(--border-color); border-radius: 10px;
            padding: 16px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.04);
        }}
        .section-title {{ font-size: 1.1rem; font-weight: 700; margin-bottom: 12px; }}
        .summary-table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }}
        .summary-table th {{ background: #f1f5f9; padding: 10px 12px; font-weight: 700; border-bottom: 1px solid var(--border-color); }}
        .summary-table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border-color); }}
        .filter-btn-sm {{
            background: var(--surface); border: 1px solid var(--border-color); padding: 4px 10px;
            border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer; transition: 0.1s;
        }}
        .filter-btn-sm:hover {{ background: var(--primary); color: white; border-color: var(--primary); }}

        .controls {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
        .search-box {{ flex: 1; min-width: 250px; padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 8px; font-size: 0.9rem; outline: none; background: var(--surface); }}
        .search-box:focus {{ border-color: var(--primary); }}
        .btn-filters {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{
            background: var(--surface); border: 1px solid var(--border-color); padding: 8px 16px; border-radius: 8px;
            cursor: pointer; font-size: 0.85rem; font-weight: 700; color: var(--text-main); transition: all 0.15s ease;
        }}
        .filter-btn:hover {{ background: #f1f5f9; }}
        .filter-btn.active {{ background: var(--primary); color: white; border-color: var(--primary); }}

        .table-container {{ background: var(--surface); border: 1px solid var(--border-color); border-radius: 10px; overflow: auto; max-height: 75vh; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }}
        thead {{ position: sticky; top: 0; background: #f1f5f9; z-index: 10; }}
        th {{ padding: 12px 14px; font-weight: 700; color: #334155; border-bottom: 2px solid var(--border-color); white-space: nowrap; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid var(--border-color); vertical-align: top; }}
        tr:hover {{ background-color: #f8fafc; }}
        .status-cell {{ min-width: 170px; max-width: 230px; }}
        .ip-cell {{ min-width: 200px; max-width: 280px; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-weight: 700; font-size: 0.72rem; text-align: center; }}
        .badge-success {{ background-color: var(--success-bg); color: var(--success); }}
        .badge-danger {{ background-color: var(--danger-bg); color: var(--danger); }}
        .badge-warning {{ background-color: var(--warning-bg); color: var(--warning); }}
        .badge-info {{ background-color: var(--info-bg); color: #475569; }}
        .failure-desc {{ font-size: 0.72rem; color: #991b1b; margin-top: 5px; line-height: 1.3; background: #fef2f2; padding: 4px 6px; border-radius: 4px; border-left: 2px solid #ef4444; word-break: break-word; }}
        .ip-block {{ display: flex; flex-direction: column; gap: 4px; }}
        .progress-bar-bg {{ width: 100%; height: 6px; background-color: #e2e8f0; border-radius: 3px; overflow: hidden; margin-top: 3px; }}
        .progress-bar-fill {{ height: 100%; border-radius: 3px; }}
        .cats-tags {{ font-size: 0.72rem; line-height: 1.2; word-break: break-word; }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 0.82rem; }}
        .text-nowrap {{ white-space: nowrap; }}
        .text-muted {{ color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>User Sign-in Audit Report</h1>
            <p>Target: <strong>{html.escape(title_label)}</strong> | Window: Last {days} days | Threat Intel: <strong>{'Enabled' if use_abuseip else 'Disabled'}</strong></p>
        </div>
        <div class="stats">
            <div class="stat-card"><span class="num">{total_users_count}</span><span class="label">Accounts</span></div>
            <div class="stat-card"><span class="num">{total}</span><span class="label">Total Logs</span></div>
            <div class="stat-card"><span class="num" style="color: var(--success);">{success_count}</span><span class="label">Success</span></div>
            <div class="stat-card"><span class="num" style="color: var(--danger);">{failure_count}</span><span class="label">Failures</span></div>
            {abuse_cards_html}
        </div>
    </div>

    <div class="section-card">
        <div class="section-title">Account Investigation Breakdown</div>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Account / UPN</th>
                    <th>Total Logs</th>
                    <th>Success</th>
                    <th>Failures</th>
                    {"<th>Malicious IPs</th>" if use_abuseip else ""}
                    {"<th>Suspicious IPs</th>" if use_abuseip else ""}
                    <th>Unique IPs</th>
                    <th>Quick Action</th>
                </tr>
            </thead>
            <tbody>
                {''.join(account_summary_rows)}
            </tbody>
        </table>
    </div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Search by IP, user account, app, browser, date, error...">
        <div class="btn-filters">
            <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
            <button class="filter-btn" onclick="setFilter('Success', this)">Success</button>
            <button class="filter-btn" onclick="setFilter('Failure', this)">Failures</button>
            {abuse_filter_btns_html}
        </div>
    </div>

    <div class="table-container signins-table-container">
        <table id="logsTable">
            <thead>
                <tr>
                    <th>Date and Time</th><th>User</th><th>APP</th><th>Auth Status</th>
                    <th>IP Address {'& Threat Intel' if use_abuseip else ''}</th>
                    <th>Location</th><th>OS</th><th>Device Browser</th>
                </tr>
            </thead>
            <tbody>{''.join(rows_html)}</tbody>
        </table>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const rows = document.querySelectorAll('#logsTable tbody tr');
        let activeFilter = 'all';

        function applyFilters() {{
            const query = searchInput.value.toLowerCase();
            rows.forEach(row => {{
                const matchesSearch = row.innerText.toLowerCase().includes(query);
                const status = row.getAttribute('data-status');
                const risk = row.getAttribute('data-risk');
                let matchesFilter = (activeFilter === 'all') || 
                                    (activeFilter === status) || 
                                    (activeFilter === risk);
                row.style.display = (matchesSearch && matchesFilter) ? '' : 'none';
            }});
        }}

        searchInput.addEventListener('input', applyFilters);

        function setFilter(filterType, btn) {{
            activeFilter = filterType;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyFilters();
        }}

        function filterByUser(userEmail) {{
            searchInput.value = userEmail;
            applyFilters();
            document.getElementById('logsTable').scrollIntoView({{ behavior: 'smooth' }});
        }}
    </script>
</body>
</html>"""
    template = _apply_report_theme(template)
    with open(filepath, mode="w", encoding="utf-8") as f:
        f.write(template)


def export_sentinel_html(filepath, engine_label, workspace_label, query_text, columns, rows, use_abuseip=False):
    total_rows = len(rows)
    malicious_count = sum(1 for r in rows if r.get("_abuse_risk") == "Malicious")
    suspicious_count = sum(1 for r in rows if r.get("_abuse_risk") == "Suspicious")

    display_cols = list(columns)
    if use_abuseip:
        display_cols.extend(["Detected IPs", "Threat Intel"])

    headers_html = "".join([f"<th>{html.escape(str(c))}</th>" for c in display_cols])

    body_rows = []
    for r in rows:
        risk_attr = r.get("_abuse_risk", "N/A")
        cells = []
        for c in columns:
            val = r.get(c, "")
            val_str = "" if val is None else str(val)
            cells.append(f"<td>{html.escape(val_str)}</td>")

        if use_abuseip:
            ips_list = r.get("_detected_ips", [])
            ips_str = ", ".join(ips_list) if ips_list else "None"
            score = r.get("_abuse_score", 0)
            risk = r.get("_abuse_risk", "Clean")
            badge_cls = (
                "badge-danger" if risk == "Malicious"
                else "badge-warning" if risk == "Suspicious"
                else "badge-info" if risk in ("Internal", "N/A")
                else "badge-success"
            )
            cats_str = r.get("_abuse_cats", "")
            cells.append(f'<td class="font-mono"><strong>{html.escape(ips_str)}</strong></td>')
            cells.append(f'<td><span class="badge {badge_cls}">{risk} ({score}%)</span><div class="cats-tags text-muted">{html.escape(cats_str)}</div></td>')

        body_rows.append(f'<tr data-risk="{risk_attr}">{"".join(cells)}</tr>')

    abuse_cards = f"""
        <div class="stat-card"><span class="num" style="color: var(--danger);">{malicious_count}</span><span class="label">Malicious</span></div>
        <div class="stat-card"><span class="num" style="color: var(--warning);">{suspicious_count}</span><span class="label">Suspicious</span></div>
    """ if use_abuseip else ""

    abuse_filters = """
        <button class="filter-btn" onclick="setFilter('Malicious', this)">Malicious</button>
        <button class="filter-btn" onclick="setFilter('Suspicious', this)">Suspicious</button>
        <button class="filter-btn" onclick="setFilter('Clean', this)">Clean</button>
    """ if use_abuseip else ""

    ws_info = f" | Workspace: <strong>{html.escape(workspace_label)}</strong>" if workspace_label else ""

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel / XDR Hunting Report</title>
    <style>
        :root {{
            --bg-primary: #f8fafc; --surface: #ffffff; --text-main: #0f172a; --text-muted: #64748b;
            --border-color: #e2e8f0; --primary: #2563eb; --success: #16a34a; --danger: #dc2626;
            --warning: #d97706; --success-bg: #dcfce7; --danger-bg: #fee2e2; --warning-bg: #fef3c7; --info-bg: #e2e8f0;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-primary); color: var(--text-main); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 16px; }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
        .header p {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats {{ display: flex; gap: 12px; flex-wrap: wrap; }}
        .stat-card {{ background: var(--surface); padding: 10px 20px; border-radius: 10px; border: 1px solid var(--border-color); display: flex; flex-direction: column; align-items: center; min-width: 95px; }}
        .stat-card .num {{ font-size: 1.5rem; font-weight: 700; }}
        .stat-card .label {{ font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; margin-top: 4px; font-weight: 700; }}
        .query-box {{ background: #0f172a; color: #e2e8f0; padding: 12px 16px; border-radius: 8px; font-family: ui-monospace, Consolas, monospace; font-size: 0.82rem; margin-bottom: 16px; white-space: pre-wrap; overflow-x: auto; }}
        .controls {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
        .search-box {{ flex: 1; min-width: 250px; padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 8px; font-size: 0.9rem; outline: none; background: var(--surface); }}
        .search-box:focus {{ border-color: var(--primary); }}
        .btn-filters {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{ background: var(--surface); border: 1px solid var(--border-color); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 700; color: var(--text-main); }}
        .filter-btn.active {{ background: var(--primary); color: white; border-color: var(--primary); }}
        .table-container {{ background: var(--surface); border: 1px solid var(--border-color); border-radius: 10px; overflow: auto; max-height: 75vh; }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.83rem; }}
        thead {{ position: sticky; top: 0; background: #f1f5f9; z-index: 10; }}
        th {{ padding: 11px 14px; font-weight: 700; color: #334155; border-bottom: 2px solid var(--border-color); white-space: nowrap; }}
        td {{ padding: 10px 14px; border-bottom: 1px solid var(--border-color); vertical-align: top; max-width: 340px; word-break: break-word; }}
        tr:hover {{ background-color: #f8fafc; }}
        .badge {{ display: inline-block; padding: 3px 8px; border-radius: 12px; font-weight: 700; font-size: 0.72rem; }}
        .badge-success {{ background-color: var(--success-bg); color: var(--success); }}
        .badge-danger {{ background-color: var(--danger-bg); color: var(--danger); }}
        .badge-warning {{ background-color: var(--warning-bg); color: var(--warning); }}
        .badge-info {{ background-color: var(--info-bg); color: #475569; }}
        .cats-tags {{ font-size: 0.72rem; margin-top: 3px; }}
        .font-mono {{ font-family: ui-monospace, Consolas, monospace; }}
        .text-muted {{ color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>Sentinel / Defender XDR Hunting Report</h1>
            <p>Engine: <strong>{html.escape(engine_label)}</strong>{ws_info} | Threat Intel: <strong>{'Enabled' if use_abuseip else 'Disabled'}</strong></p>
        </div>
        <div class="stats">
            <div class="stat-card"><span class="num">{total_rows}</span><span class="label">Total Rows</span></div>
            {abuse_cards}
        </div>
    </div>

    <div class="query-box">{html.escape(query_text)}</div>

    <div class="controls">
        <input type="text" id="searchInput" class="search-box" placeholder="Filter results by any column, user, IP, timestamp...">
        <div class="btn-filters">
            <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
            {abuse_filters}
        </div>
    </div>

    <div class="table-container">
        <table id="huntingTable">
            <thead><tr>{headers_html}</tr></thead>
            <tbody>{"".join(body_rows)}</tbody>
        </table>
    </div>

    <script>
        const searchInput = document.getElementById('searchInput');
        const rows = document.querySelectorAll('#huntingTable tbody tr');
        let activeFilter = 'all';

        function applyFilters() {{
            const query = searchInput.value.toLowerCase();
            rows.forEach(row => {{
                const matchesSearch = row.innerText.toLowerCase().includes(query);
                const risk = row.getAttribute('data-risk');
                const matchesRisk = (activeFilter === 'all') || (risk === activeFilter);
                row.style.display = (matchesSearch && matchesRisk) ? '' : 'none';
            }});
        }}
        searchInput.addEventListener('input', applyFilters);
        function setFilter(val, btn) {{
            activeFilter = val;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyFilters();
        }}
    </script>
</body>
</html>"""
    template = _apply_report_theme(template)
    with open(filepath, mode="w", encoding="utf-8") as f:
        f.write(template)


def export_ipsearcher_html(filepath, results, skipped_intigriti_count=0, skipped_low_score_count=0):
    total_ips = len(results)
    malicious_count = sum(1 for r in results if r and r.get("score", 0) >= 60)
    suspicious_count = sum(1 for r in results if r and 20 <= r.get("score", 0) < 60)
    clean_count = sum(1 for r in results if r and r.get("score", 0) < 20)

    rows_html = []
    for r in results:
        if not r:
            continue
        score = r.get("score", 0)
        bar_color = "#dc2626" if score >= 60 else "#d97706" if score >= 20 else "#16a34a"
        badge_cls = "badge-danger" if score >= 60 else "badge-warning" if score >= 20 else "badge-success"
        risk_label = "Malicious" if score >= 60 else "Suspicious" if score >= 20 else "Clean"
        cats_badges = "".join([f'<span class="category-tag">{html.escape(c)}</span>' for c in r.get("categories", [])]) if r.get("categories") else '<span class="text-muted">None</span>'

        rows_html.append(f"""
        <tr data-risk="{risk_label}">
            <td class="font-mono"><strong>{html.escape(r.get('ip', 'N/A'))}</strong></td>
            <td><span class="badge {badge_cls}">{risk_label}</span></td>
            <td>
                <div class="score-container">
                    <span class="score-val">{score}%</span>
                    <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: {score}%; background-color: {bar_color};"></div></div>
                </div>
            </td>
            <td>{html.escape(r.get('country', 'N/A'))}</td>
            <td>{html.escape(r.get('isp', 'N/A'))}</td>
            <td>{html.escape(r.get('domain', 'N/A'))}</td>
            <td class="font-mono">{r.get('reports', 0)}</td>
            <td>{cats_badges}</td>
        </tr>""")

    notes = []
    if skipped_intigriti_count > 0:
        notes.append(f"Excluded Intigriti IPs: <strong>{skipped_intigriti_count}</strong>")
    if skipped_low_score_count > 0:
        notes.append(f"Omitted Low Score (&le;10%): <strong>{skipped_low_score_count}</strong>")
    notes_html = (" | " + " | ".join(notes)) if notes else ""

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AbuseIPDB Threat Intelligence Report</title>
    <style>
        :root {{
            --bg-primary: #f8fafc; --surface: #ffffff; --text-main: #0f172a; --text-muted: #64748b;
            --border-color: #e2e8f0; --primary: #2563eb; --total-color: #0f172a; --danger: #dc2626;
            --warning: #d97706; --success: #16a34a; --danger-bg: #fee2e2; --warning-bg: #fef3c7; --success-bg: #dcfce7;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background-color: var(--bg-primary); color: var(--text-main); padding: 24px; }}
        .header {{ display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 1.5rem; font-weight: 700; }}
        .header p {{ color: var(--text-muted); font-size: 0.9rem; }}
        .stats {{ display: flex; gap: 12px; flex-wrap: wrap; }}
        .stat-card {{ background: var(--surface); padding: 12px 24px; border-radius: 10px; border: 1px solid var(--border-color); display: flex; flex-direction: column; align-items: center; min-width: 105px; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }}
        .stat-card .num {{ font-size: 1.75rem; font-weight: 700; line-height: 1.1; }}
        .stat-card .label {{ font-size: 0.72rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; margin-top: 6px; letter-spacing: 0.5px; }}
        .controls {{ display: flex; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }}
        .search-box {{ flex: 1; min-width: 250px; padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 8px; font-size: 0.9rem; outline: none; background: var(--surface); }}
        .search-box:focus {{ border-color: var(--primary); }}
        .btn-filters {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{ background: var(--surface); border: 1px solid var(--border-color); padding: 8px 16px; border-radius: 8px; cursor: pointer; font-size: 0.85rem; font-weight: 700; color: var(--text-main); transition: all 0.15s ease; }}
        .filter-btn:hover {{ background: #f1f5f9; }}
        .filter-btn.active {{ background: var(--primary); color: white; border-color: var(--primary); }}
        .table-container {{ background: var(--surface); border: 1px solid var(--border-color); border-radius: 10px; overflow: auto; max-height: 75vh; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
        table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }}
        thead {{ position: sticky; top: 0; background: #f1f5f9; z-index: 10; }}
        th {{ padding: 12px 14px; font-weight: 700; color: #334155; border-bottom: 2px solid var(--border-color); white-space: nowrap; }}
        td {{ padding: 12px 14px; border-bottom: 1px solid var(--border-color); vertical-align: middle; }}
        tr:hover {{ background-color: #f8fafc; }}
        .font-mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 12px; font-weight: 700; font-size: 0.75rem; }}
        .badge-success {{ background-color: var(--success-bg); color: var(--success); }}
        .badge-warning {{ background-color: var(--warning-bg); color: var(--warning); }}
        .badge-danger {{ background-color: var(--danger-bg); color: var(--danger); }}
        .score-container {{ display: flex; align-items: center; gap: 8px; min-width: 130px; }}
        .score-val {{ font-weight: 700; width: 35px; }}
        .progress-bar-bg {{ flex: 1; height: 6px; background-color: #e2e8f0; border-radius: 3px; overflow: hidden; }}
        .progress-bar-fill {{ height: 100%; border-radius: 3px; }}
        .category-tag {{ display: inline-block; background-color: #f1f5f9; color: #475569; padding: 2px 7px; border-radius: 4px; font-size: 0.72rem; margin: 2px; border: 1px solid #cbd5e1; }}
        .text-muted {{ color: var(--text-muted); }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h1>AbuseIPDB Threat Intelligence Report</h1>
            <p>Exported <strong>{total_ips}</strong> external IP address(es){notes_html}</p>
        </div>
        <div class="stats">
            <div class="stat-card"><span class="num" style="color: var(--total-color);">{total_ips}</span><span class="label">TOTAL IPS</span></div>
            <div class="stat-card"><span class="num" style="color: var(--danger);">{malicious_count}</span><span class="label">MALICIOUS</span></div>
            <div class="stat-card"><span class="num" style="color: var(--warning);">{suspicious_count}</span><span class="label">SUSPICIOUS</span></div>
            <div class="stat-card"><span class="num" style="color: var(--success);">{clean_count}</span><span class="label">CLEAN</span></div>
        </div>
    </div>

    <div class="controls">
        <input type="text" id="s" class="search-box" placeholder="Search by IP, country, ISP, domain, category..." oninput="applyFilters()">
        <div class="btn-filters">
            <button class="filter-btn active" onclick="setRiskFilter('all', this)">All</button>
            <button class="filter-btn" onclick="setRiskFilter('Malicious', this)">Malicious</button>
            <button class="filter-btn" onclick="setRiskFilter('Suspicious', this)">Suspicious</button>
            <button class="filter-btn" onclick="setRiskFilter('Clean', this)">Clean</button>
        </div>
    </div>

    <div class="table-container">
        <table id="abuseTable">
            <thead>
                <tr><th>IP Address</th><th>Risk</th><th>Score</th><th>Country</th><th>ISP</th><th>Domain</th><th>Reports</th><th>Categories</th></tr>
            </thead>
            <tbody id="tb">{''.join(rows_html)}</tbody>
        </table>
    </div>

    <script>
        let currentFilter = 'all';
        function applyFilters() {{
            const q = document.getElementById('s').value.toLowerCase();
            document.querySelectorAll('#tb tr').forEach(row => {{
                const matchesSearch = row.innerText.toLowerCase().includes(q);
                const matchesRisk = (currentFilter === 'all') || (row.getAttribute('data-risk') === currentFilter);
                row.style.display = (matchesSearch && matchesRisk) ? '' : 'none';
            }});
        }}
        function setRiskFilter(val, btn) {{
            currentFilter = val;
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            applyFilters();
        }}
    </script>
</body>
</html>"""
    template = _apply_report_theme(template)
    with open(filepath, mode="w", encoding="utf-8") as f:
        f.write(template)


def export_ipsearcher_blocklist_and_csv(txt_filepath, csv_filepath, results):
    """Exports blocklist (.txt with /32) and extended CSV."""
    with open(txt_filepath, mode="w", newline="", encoding="utf-8") as txt_f, \
         open(csv_filepath, mode="w", newline="", encoding="utf-8-sig") as csv_f:

        writer = csv.writer(csv_f)
        writer.writerow(["sourceIP", "totalReports", "abuseConfidenceScore", "abuseBlock", "existsIntigriti", "Block?"])

        for r in results:
            if not r:
                continue
            ip = r.get("ip", "")
            score = r.get("score", 0)
            reports = r.get("reports", 0)

            abuse_block = score > 10
            final_block = abuse_block

            if final_block:
                txt_f.write(f"{ip}/32\n")

            writer.writerow([
                ip,
                reports,
                score,
                "TRUE" if abuse_block else "FALSE",
                "FALSE",
                "TRUE" if final_block else "FALSE"
            ])


# =========================================================================
# MODERN GUI APP
# =========================================================================
