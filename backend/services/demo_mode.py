from __future__ import annotations

import hashlib
import json
import random
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from config import get_settings

DEMO_NAMESPACE = uuid.UUID("6f0ddcfb-7d42-49d1-95cc-2855d8f3d341")
DEMO_VERSION = "2026.05"
DEMO_LABEL = "Presentation Mode"

DEMO_CONFIG_VALUES = {
    "SPLUNK_HOST": "splunk-demo.zerotrustx.local",
    "SPLUNK_PORT": "8089",
    "SPLUNK_USERNAME": "soc_demo",
    "SPLUNK_PASSWORD": "configured",
    "SPLUNK_HEC_TOKEN": "configured",
    "SPLUNK_HEC_URL": "https://splunk-demo.zerotrustx.local:8088/services/collector",
    "PFSENSE_HOST": "https://pfsense-demo.zerotrustx.local",
    "PFSENSE_USERNAME": "soc_api",
    "PFSENSE_PASSWORD": "configured",
    "PFSENSE_VERIFY_SSL": "true",
    "PFSENSE_CA_CERT_TEXT": "configured",
    "PFSENSE_CA_CERT_PATH": "",
    "PFSENSE_BLOCK_ALIAS": "SOC_BLOCK_TEMP",
    "PFSENSE_TIMEOUT": "10",
    "ABUSEIPDB_API_KEY": "configured",
    "VIRUSTOTAL_API_KEY": "configured",
    "IP_REPUTATION_ENABLED": "true",
    "IP_REPUTATION_AUTO_INCIDENT_ENABLED": "true",
}

DEMO_DEFAULT_PASSWORDS = {
    "SEED_ADMIN_PASSWORD": "DemoAdmin!2026",
    "SEED_ANALYST_PASSWORD": "DemoAnalyst!2026",
    "SEED_VIEWER_PASSWORD": "DemoViewer!2026",
}

DEMO_USERS = [
    {
        "username": "admin",
        "email": "admin@zerotrustx.demo",
        "display_name": "Aysel Mammadova",
        "role": "admin",
        "mfa_enabled": True,
        "last_login_ip": "85.132.41.22",
        "last_login_country": "Azerbaijan",
    },
    {
        "username": "analyst",
        "email": "analyst@zerotrustx.demo",
        "display_name": "Kamal Safarli",
        "role": "soc_analyst",
        "mfa_enabled": True,
        "last_login_ip": "91.198.77.14",
        "last_login_country": "Azerbaijan",
    },
    {
        "username": "viewer",
        "email": "viewer@zerotrustx.demo",
        "display_name": "Laman Rahimova",
        "role": "viewer",
        "mfa_enabled": False,
        "last_login_ip": "85.132.41.44",
        "last_login_country": "Azerbaijan",
    },
]

DEMO_ASSETS = [
    {"slug": "portal-edge-01", "hostname": "portal-edge-01", "ip": "10.40.12.18", "zone": "dmz", "owner": "IAM Team", "asset_criticality": 4},
    {"slug": "vpn-gateway-01", "hostname": "vpn-gateway-01", "ip": "10.10.5.14", "zone": "dmz", "owner": "Network Operations", "asset_criticality": 5},
    {"slug": "finance-ws-044", "hostname": "finance-ws-044", "ip": "10.20.44.18", "zone": "internal", "owner": "Finance", "asset_criticality": 3},
    {"slug": "file-srv-02", "hostname": "file-srv-02", "ip": "10.30.8.25", "zone": "internal", "owner": "Infrastructure", "asset_criticality": 5},
    {"slug": "dc-auth-01", "hostname": "dc-auth-01", "ip": "10.20.1.15", "zone": "management", "owner": "Identity Engineering", "asset_criticality": 5},
    {"slug": "jump-admin-01", "hostname": "jump-admin-01", "ip": "10.50.1.10", "zone": "management", "owner": "SOC Admin", "asset_criticality": 4},
    {"slug": "proxy-west-01", "hostname": "proxy-west-01", "ip": "10.40.20.11", "zone": "dmz", "owner": "Web Platform", "asset_criticality": 4},
    {"slug": "hr-ws-022", "hostname": "hr-ws-022", "ip": "10.20.52.22", "zone": "internal", "owner": "Human Resources", "asset_criticality": 2},
    {"slug": "mail-sec-01", "hostname": "mail-sec-01", "ip": "10.20.3.50", "zone": "management", "owner": "Messaging", "asset_criticality": 4},
    {"slug": "api-edge-02", "hostname": "api-edge-02", "ip": "10.40.18.29", "zone": "dmz", "owner": "Application Security", "asset_criticality": 4},
]

DEMO_ASSETS.extend([
    {"slug": "web-dmz-01", "hostname": "web-dmz-01", "ip": "10.40.12.31", "zone": "web", "owner": "Web Platform", "asset_criticality": 4},
    {"slug": "owasp-web", "hostname": "owasp-web", "ip": "10.40.12.44", "zone": "dmz", "owner": "Application Security", "asset_criticality": 3},
    {"slug": "win-ad-01", "hostname": "win-ad-01", "ip": "10.20.1.11", "zone": "identity", "owner": "Identity Engineering", "asset_criticality": 5},
    {"slug": "win-client-01", "hostname": "win-client-01", "ip": "10.20.61.17", "zone": "endpoint", "owner": "Finance", "asset_criticality": 3},
    {"slug": "win-client-02", "hostname": "win-client-02", "ip": "10.20.62.28", "zone": "endpoint", "owner": "Operations", "asset_criticality": 3},
    {"slug": "splunk-mgmt-01", "hostname": "splunk-mgmt-01", "ip": "10.50.4.20", "zone": "management", "owner": "SOC Platform", "asset_criticality": 5},
    {"slug": "pfsense-fw-01", "hostname": "pfsense-fw-01", "ip": "10.10.1.1", "zone": "firewall", "owner": "Network Operations", "asset_criticality": 5},
    {"slug": "db-internal-01", "hostname": "db-internal-01", "ip": "10.30.4.40", "zone": "database", "owner": "Data Platform", "asset_criticality": 5},
    {"slug": "vpn-gw-01", "hostname": "vpn-gw-01", "ip": "10.10.5.21", "zone": "vpn", "owner": "Network Operations", "asset_criticality": 5},
    {"slug": "analyst-workstation-01", "hostname": "analyst-workstation-01", "ip": "10.50.8.12", "zone": "management", "owner": "SOC", "asset_criticality": 3},
    {"slug": "redis-cache-01", "hostname": "redis-cache-01", "ip": "10.30.6.25", "zone": "database", "owner": "Platform Engineering", "asset_criticality": 4},
    {"slug": "postgres-db-01", "hostname": "postgres-db-01", "ip": "10.30.6.31", "zone": "database", "owner": "Platform Engineering", "asset_criticality": 5},
    {"slug": "cloud-appgw-01", "hostname": "cloud-appgw-01", "ip": "10.70.12.15", "zone": "cloud", "owner": "Cloud Engineering", "asset_criticality": 4},
    {"slug": "idp-prod-01", "hostname": "idp-prod-01", "ip": "10.20.2.25", "zone": "identity", "owner": "Identity Engineering", "asset_criticality": 5},
])

DEMO_PUBLIC_IP_POOL = [
    "185.193.88.41", "103.27.14.205", "77.91.124.33", "45.146.55.201", "91.210.174.78",
    "34.107.221.82", "52.29.87.144", "3.121.66.91", "34.149.120.17", "45.155.205.233",
    "185.220.101.45", "194.26.192.64", "89.248.165.39", "91.240.118.172", "162.142.125.42",
    "167.94.138.48", "198.98.51.189", "141.98.11.71", "109.206.240.66", "31.220.3.173",
    "64.227.18.91", "142.93.211.14", "159.65.88.42", "178.128.203.119", "139.59.130.12",
    "206.189.25.63", "165.22.77.209", "167.71.92.101", "134.209.44.17", "68.183.112.90",
    "157.230.84.36", "188.166.74.115", "104.248.92.81", "46.101.22.118", "138.68.99.52",
    "13.58.92.104", "18.197.31.88", "20.50.74.22", "35.203.210.77", "44.204.127.9",
    "52.12.84.201", "54.93.33.17", "72.14.182.64", "80.82.77.139", "92.255.85.107",
    "94.102.61.46", "146.70.103.12", "172.104.24.52", "176.113.115.91", "193.32.162.54",
]

DEMO_IP_REPUTATION = {
    "185.193.88.41": {
        "verdict": "malicious",
        "score": 93,
        "abuseipdb_score": 91,
        "total_reports": 148,
        "country": "RU",
        "usage_type": "Data Center / Web Hosting / Transit",
        "isp": "Raven Transit LLC",
        "domain": "raven-transit.example",
        "last_reported_at": "2026-04-30T21:14:00Z",
        "vt_malicious": 7,
        "vt_suspicious": 2,
        "vt_harmless": 12,
        "vt_undetected": 68,
        "vt_reputation": -42,
        "as_owner": "Raven Transit LLC",
        "network": "185.193.88.0/24",
    },
    "103.27.14.205": {
        "verdict": "suspicious",
        "score": 61,
        "abuseipdb_score": 47,
        "total_reports": 39,
        "country": "SG",
        "usage_type": "Data Center / Web Hosting / Transit",
        "isp": "Edgewave Hosting",
        "domain": "edgewave-hosting.example",
        "last_reported_at": "2026-04-29T11:42:00Z",
        "vt_malicious": 1,
        "vt_suspicious": 4,
        "vt_harmless": 14,
        "vt_undetected": 75,
        "vt_reputation": -9,
        "as_owner": "Edgewave Hosting",
        "network": "103.27.14.0/24",
    },
    "77.91.124.33": {
        "verdict": "malicious",
        "score": 88,
        "abuseipdb_score": 83,
        "total_reports": 94,
        "country": "NL",
        "usage_type": "VPN Provider",
        "isp": "Tunnel Forge",
        "domain": "tunnelforge.example",
        "last_reported_at": "2026-05-01T00:48:00Z",
        "vt_malicious": 5,
        "vt_suspicious": 3,
        "vt_harmless": 10,
        "vt_undetected": 51,
        "vt_reputation": -27,
        "as_owner": "Tunnel Forge B.V.",
        "network": "77.91.124.0/24",
    },
    "45.146.55.201": {
        "verdict": "malicious",
        "score": 96,
        "abuseipdb_score": 99,
        "total_reports": 214,
        "country": "DE",
        "usage_type": "Data Center / Web Hosting / Transit",
        "isp": "Northline Transit",
        "domain": "northline-transit.example",
        "last_reported_at": "2026-05-01T02:03:00Z",
        "vt_malicious": 9,
        "vt_suspicious": 1,
        "vt_harmless": 3,
        "vt_undetected": 44,
        "vt_reputation": -64,
        "as_owner": "Northline Transit GmbH",
        "network": "45.146.55.0/24",
    },
    "91.210.174.78": {
        "verdict": "suspicious",
        "score": 54,
        "abuseipdb_score": 31,
        "total_reports": 17,
        "country": "TR",
        "usage_type": "ISP",
        "isp": "Anatolia Broadband",
        "domain": "anatolia-broadband.example",
        "last_reported_at": "2026-04-28T17:18:00Z",
        "vt_malicious": 0,
        "vt_suspicious": 2,
        "vt_harmless": 23,
        "vt_undetected": 81,
        "vt_reputation": -3,
        "as_owner": "Anatolia Broadband",
        "network": "91.210.174.0/24",
    },
    "34.107.221.82": {
        "verdict": "clean",
        "score": 0,
        "abuseipdb_score": 0,
        "total_reports": 0,
        "country": "US",
        "usage_type": "Enterprise",
        "isp": "Contoso WAN",
        "domain": "contoso.example",
        "last_reported_at": None,
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_harmless": 31,
        "vt_undetected": 59,
        "vt_reputation": 16,
        "as_owner": "Contoso WAN",
        "network": "34.107.221.0/24",
    },
    "52.29.87.144": {
        "verdict": "clean",
        "score": 0,
        "abuseipdb_score": 0,
        "total_reports": 0,
        "country": "GB",
        "usage_type": "Business",
        "isp": "Blue Peak Fibre",
        "domain": "bluepeak.example",
        "last_reported_at": None,
        "vt_malicious": 0,
        "vt_suspicious": 0,
        "vt_harmless": 28,
        "vt_undetected": 70,
        "vt_reputation": 11,
        "as_owner": "Blue Peak Fibre",
        "network": "52.29.87.0/24",
    },
}


@dataclass(frozen=True)
class DemoTechnique:
    tactic_id: str
    technique_id: str
    technique_name: str
    reason: str
    confidence_score: int
    subtechnique_id: str | None = None


def is_demo_mode() -> bool:
    return bool(get_settings().DEMO_MODE)


def demo_uuid(*parts: Any) -> str:
    token = ":".join(str(part) for part in parts)
    return str(uuid.uuid5(DEMO_NAMESPACE, token))


def demo_value_for_key(key: str) -> str | None:
    return DEMO_CONFIG_VALUES.get(key)


def demo_password_for_setting(setting_name: str) -> str | None:
    return DEMO_DEFAULT_PASSWORDS.get(setting_name)


def demo_banner_meta() -> dict:
    return {
        "demo_mode": True,
        "label": DEMO_LABEL,
        "version": DEMO_VERSION,
        "simulated": True,
    }


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _dt(value: str | datetime) -> datetime:
    if isinstance(value, datetime):
        return value
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _generated_public_profile(ip: str) -> dict:
    digest = int(hashlib.sha256(ip.encode("utf-8")).hexdigest()[:8], 16)
    countries = ["NL", "DE", "US", "SG", "TR", "GB", "FR", "RO", "SE", "PL"]
    usage = [
        "Data Center / Web Hosting / Transit",
        "VPN Provider",
        "ISP",
        "Cloud Provider",
        "Business",
    ]
    country = countries[digest % len(countries)]
    usage_type = usage[(digest // 3) % len(usage)]
    if digest % 9 in {0, 1, 2}:
        verdict = "malicious"
        score = 76 + digest % 22
        vt_malicious = 2 + digest % 8
        vt_suspicious = 1 + digest % 4
        reports = 42 + digest % 180
        vt_reputation = -18 - digest % 64
    elif digest % 9 in {3, 4, 5}:
        verdict = "suspicious"
        score = 31 + digest % 38
        vt_malicious = digest % 2
        vt_suspicious = 1 + digest % 5
        reports = 8 + digest % 52
        vt_reputation = -2 - digest % 16
    else:
        verdict = "clean"
        score = digest % 8
        vt_malicious = 0
        vt_suspicious = 0
        reports = digest % 4
        vt_reputation = 5 + digest % 24
    abuse_score = max(score - (digest % 9), 0)
    network = ".".join(ip.split(".")[:3]) + ".0/24"
    return {
        "verdict": verdict,
        "score": score,
        "abuseipdb_score": abuse_score,
        "total_reports": reports,
        "country": country,
        "usage_type": usage_type,
        "isp": f"{country} Edge Transit",
        "domain": f"edge-{ip.replace('.', '-')}.example",
        "last_reported_at": "2026-04-30T18:20:00Z" if verdict != "clean" else None,
        "vt_malicious": vt_malicious,
        "vt_suspicious": vt_suspicious,
        "vt_harmless": 8 + digest % 33,
        "vt_undetected": 42 + digest % 60,
        "vt_reputation": vt_reputation,
        "as_owner": f"{country} Edge Transit",
        "network": network,
    }


def _public_profile(ip: str) -> dict:
    return DEMO_IP_REPUTATION.get(ip) or _generated_public_profile(ip)


def _severity_int(label: str) -> int:
    return {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1,
    }.get(label, 3)


def _event(
    scenario_slug: str,
    idx: int,
    when: datetime,
    *,
    source_system: str,
    sourcetype: str,
    index: str,
    host: str,
    source_ip: str | None,
    destination_ip: str | None,
    user: str | None,
    action: str,
    event_category: str,
    severity: str,
    message: str,
    signature: str | None = None,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
    saved_search_name: str | None = None,
    query_sid: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict:
    payload = {
        "scenario": scenario_slug,
        "saved_search_name": saved_search_name,
        "signature": signature or event_category.replace("_", " ").title(),
        "host": host,
        "user": user,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_category": event_category,
        "action": action,
        "severity": severity,
        "method": method,
        "path": path,
        "status_code": status_code,
    }
    if extra:
        payload.update(extra)
    raw_event = {
        "_time": _iso(when),
        "_raw": message,
        "index": index,
        "sourcetype": sourcetype,
        "host": host,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user": user,
        "action": action,
        "event_category": event_category,
        "message": message,
        "signature": signature or payload["signature"],
        "saved_search_name": saved_search_name,
        "status_code": status_code,
        "method": method,
        "path": path,
        **(extra or {}),
    }
    return {
        "id": demo_uuid("event", scenario_slug, idx),
        "scenario": scenario_slug,
        "time": _iso(when),
        "index": index,
        "sourcetype": sourcetype,
        "host": host,
        "source_system": source_system,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user": user,
        "email": user,
        "action": action,
        "event_category": event_category,
        "severity": severity,
        "signature": signature or payload["signature"],
        "message": message,
        "status_code": status_code,
        "method": method,
        "path": path,
        "query_sid": query_sid or f"sid_{scenario_slug}_{idx}",
        "search_id": f"job_{scenario_slug}_{idx}",
        "saved_search_name": saved_search_name,
        "raw_event": raw_event,
        "raw_data": payload,
        "raw": json.dumps(raw_event, sort_keys=True),
        "keywords": sorted(
            {
                scenario_slug,
                source_system.lower(),
                sourcetype.lower(),
                action.lower(),
                event_category.lower(),
                *(str(signature or "").lower().replace("/", " ").split()),
                *(str(message).lower().replace("/", " ").replace(":", " ").split()),
                *(str(saved_search_name or "").lower().replace("/", " ").split()),
            }
        ),
    }


def _asset_by_slug(slug: str) -> dict:
    for asset in DEMO_ASSETS:
        if asset["slug"] == slug:
            return asset
    raise KeyError(slug)


def _generated_scenarios(now: datetime) -> list[dict]:
    templates = [
        ("credential-stuffing-vpn", "Credential Stuffing Against VPN Gateway", "vpn-gw-01", "authentication", "high", "investigating", "Credential Stuffing Pattern - VPN", "vpn", "T1110.004", "Credential Stuffing"),
        ("sql-injection-owasp", "SQL Injection Attempt Against Juice Shop", "owasp-web", "web_attack", "high", "contained", "SQL Injection Against Public Web App", "web", "T1190", "Exploit Public-Facing Application"),
        ("external-port-scan", "External Port Scan Against DMZ Services", "web-dmz-01", "network_scan", "medium", "new", "External Network Service Discovery", "network", "T1046", "Network Service Discovery"),
        ("powershell-download", "Suspicious PowerShell Download Cradle", "win-client-01", "endpoint", "high", "investigating", "PowerShell Download Cradle Detected", "endpoint", "T1059.001", "PowerShell"),
        ("malicious-ip-web", "Malicious IP Observed in Web Logs", "cloud-appgw-01", "reputation", "medium", "contained", "Malicious IP Hits Application Gateway", "web", "T1190", "Exploit Public-Facing Application"),
        ("mfa-fatigue", "Multiple Failed MFA Attempts", "idp-prod-01", "authentication", "medium", "investigating", "MFA Push Fatigue Sequence", "identity", "T1621", "Multi-Factor Authentication Request Generation"),
        ("admin-after-hours", "Suspicious Admin Access Pattern", "jump-admin-01", "privilege", "high", "resolved", "After Hours Privileged Session", "windows", "T1078", "Valid Accounts"),
        ("outbound-exfil-spike", "Unusual Outbound Traffic Spike", "db-internal-01", "exfiltration", "critical", "investigating", "Large Outbound Transfer From Database Zone", "network", "T1041", "Exfiltration Over C2 Channel"),
        ("defender-disabled", "Endpoint Security Tool Disabled", "win-client-02", "defense_evasion", "high", "contained", "Defender Tamper Protection Alert", "endpoint", "T1562", "Impair Defenses"),
        ("dns-tunnel", "Possible DNS Tunneling From Endpoint", "win-client-01", "command_control", "medium", "investigating", "High Entropy DNS Query Burst", "dns", "T1071.004", "DNS"),
        ("rdp-lateral", "RDP Lateral Movement Attempt", "win-ad-01", "lateral_movement", "high", "investigating", "RDP Authentication From Unusual Workstation", "windows", "T1021.001", "Remote Desktop Protocol"),
        ("archive-staging", "Archive Staging Before Upload", "file-srv-02", "collection", "medium", "resolved", "Archive Created On Shared File Server", "windows", "T1560", "Archive Collected Data"),
        ("proxy-malware", "Proxy Malware Callback Pattern", "proxy-west-01", "command_control", "high", "contained", "Outbound Callback To Known Host", "proxy", "T1071.001", "Web Protocols"),
        ("firewall-deny-sweep", "Firewall Deny Sweep From External Scanner", "pfsense-fw-01", "network_scan", "medium", "new", "pfSense Deny Sweep Across DMZ", "firewall", "T1046", "Network Service Discovery"),
        ("cloud-token-use", "Cloud Token Used From New Geography", "cloud-appgw-01", "credential_access", "medium", "pending_approval", "Cloud Token Anomaly", "cloud", "T1528", "Steal Application Access Token"),
        ("database-login-failures", "Database Login Failure Burst", "postgres-db-01", "authentication", "high", "investigating", "PostgreSQL Failed Login Burst", "database", "T1110", "Brute Force"),
        ("redis-scan", "Redis Service Exposure Probe", "redis-cache-01", "discovery", "medium", "contained", "Redis Port Probe", "network", "T1046", "Network Service Discovery"),
        ("analyst-workstation-script", "Unsigned Script On Analyst Workstation", "analyst-workstation-01", "execution", "low", "false_positive", "Unsigned Script Execution Review", "endpoint", "T1059", "Command and Scripting Interpreter"),
    ]
    tactics = {
        "T1110.004": ("TA0006", "T1110", "T1110.004"),
        "T1190": ("TA0001", "T1190", None),
        "T1046": ("TA0007", "T1046", None),
        "T1059.001": ("TA0002", "T1059", "T1059.001"),
        "T1621": ("TA0006", "T1621", None),
        "T1078": ("TA0001", "T1078", None),
        "T1041": ("TA0010", "T1041", None),
        "T1562": ("TA0005", "T1562", None),
        "T1071.004": ("TA0011", "T1071", "T1071.004"),
        "T1021.001": ("TA0008", "T1021", "T1021.001"),
        "T1560": ("TA0009", "T1560", None),
        "T1071.001": ("TA0011", "T1071", "T1071.001"),
        "T1528": ("TA0006", "T1528", None),
        "T1110": ("TA0006", "T1110", None),
        "T1059": ("TA0002", "T1059", None),
    }
    scenarios: list[dict] = []
    users = [
        "nigar.aliyeva@zerotrustx.demo",
        "samir.guliyev@zerotrustx.demo",
        "leyla.hasanova@zerotrustx.demo",
        "it.admin@zerotrustx.demo",
        "svc.backup@zerotrustx.demo",
        "rashad.mammadli@zerotrustx.demo",
    ]
    for idx, (slug, title, asset_slug, category, severity, status, search_name, index, technique_key, technique_name) in enumerate(templates, start=1):
        asset = _asset_by_slug(asset_slug)
        source_ip = DEMO_PUBLIC_IP_POOL[(idx * 3) % len(DEMO_PUBLIC_IP_POOL)]
        user = users[idx % len(users)]
        tactic_id, technique_id, subtechnique_id = tactics[technique_key]
        approved = status not in {"pending_approval", "new"}
        resolved = status in {"resolved", "false_positive"}
        is_false_positive = status == "false_positive"
        action_status = "failed" if idx % 9 == 0 else ("pending" if status in {"new", "pending_approval"} else "executed")
        action_type = "check_ip_status" if idx % 5 == 0 else ("unblock_ip" if is_false_positive else "block_ip")
        method = "POST" if category in {"web_attack", "reputation"} else None
        path = "/login" if "credential" in slug else ("/api/search?q=' OR 1=1 UNION SELECT" if category == "web_attack" else None)
        scenarios.append({
            "slug": slug,
            "started_hours_ago": 6 + idx * 13.5,
            "title": title,
            "description": f"{search_name} correlated telemetry across {asset['hostname']}, public source {source_ip}, and related evidence in the {asset['zone']} zone.",
            "severity": severity,
            "status": status,
            "activation_state": "approved" if approved else "pending",
            "is_active": not resolved,
            "approval_status": "approved" if approved else "pending",
            "analyst_verdict": "false_positive" if is_false_positive else ("confirmed_true_positive" if resolved else "needs_more_evidence"),
            "priority": "critical" if severity == "critical" else severity,
            "queue": "Threat Response" if severity in {"critical", "high"} else "SOC Triage",
            "workflow_status": "closed" if resolved else ("awaiting_approval" if not approved else "in_progress"),
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", index],
            "response_level": 3 if severity in {"critical", "high"} else 2,
            "category": category,
            "asset_slug": asset_slug,
            "user": user,
            "owner": "Kamal Safarli" if idx % 2 else "Aysel Mammadova",
            "source_ip": source_ip,
            "destination_ip": asset["ip"],
            "verdict_by": "Kamal Safarli" if resolved else None,
            "cia": (1 if severity in {"critical", "high"} else 0, 1 if idx % 2 == 0 else 0, 1 if severity == "critical" else 0),
            "confidence": 0.62 + (idx % 6) * 0.055,
            "saved_search_name": search_name,
            "search": f'index={index} source_ip="{source_ip}" host="{asset["hostname"]}" | stats count by action,event_category,severity',
            "notes": f"Evidence chain is tied by source IP, destination host, and a {category.replace('_', ' ')} detection pattern.",
            "resolution_notes": "Validated and closed after containment review." if resolved and not is_false_positive else ("Benign administrative script confirmed by change record." if is_false_positive else None),
            "close_reason": "false_positive" if is_false_positive else ("remediated" if resolved else None),
            "mitre": [
                DemoTechnique(tactic_id, technique_id, technique_name, f"{search_name} matched event fields, source IP context, and related log chain evidence.", min(92, 65 + idx % 20), subtechnique_id),
            ],
            "comments": [
                ("internal_note", f"Correlated {asset['hostname']} telemetry with reputation and alert context for {source_ip}."),
                ("analyst_note", "Next step is scope validation and containment review." if not resolved else "Workflow outcome recorded after analyst validation."),
            ],
            "steps": [
                {"m": 0, "source_system": index, "sourcetype": f"{index}:event", "index": index, "action": "observed", "event_category": category, "severity": severity, "message": f"{title}: initial event observed from {source_ip} to {asset['hostname']}", "signature": search_name, "method": method, "path": path, "status_code": 403 if category in {"web_attack", "reputation"} else None},
                {"m": 4, "source_system": "splunk", "sourcetype": "savedsearch:alert", "index": "alerts", "action": "alert_triggered", "event_category": "detection", "severity": severity, "message": f"{search_name} triggered for {asset['hostname']} with source {source_ip}", "signature": search_name},
                {"m": 8, "source_system": "pfsense" if action_type != "check_ip_status" else "reputation", "sourcetype": "pfsense:filterlog", "index": "firewall", "action": "blocked" if action_status == "executed" and action_type == "block_ip" else "reviewed", "event_category": "response", "severity": "medium", "message": f"Response workflow {action_type} status {action_status} for {source_ip}", "signature": "Containment Workflow"},
                {"m": 15, "source_system": "case", "sourcetype": "case:activity", "index": "soc", "action": "analyst_update", "event_category": "workflow", "severity": "informational", "message": f"Analyst updated incident {title} with evidence and MITRE mapping", "signature": "Analyst Case Update"},
            ],
            "response_actions": [
                {
                    "action_type": action_type,
                    "target": source_ip,
                    "minutes_after": 9,
                    "status": action_status,
                    "initiated_by": "Kamal Safarli",
                    "approved_by": "Aysel Mammadova" if action_status == "executed" else None,
                    "output": {"provider": "pfSense", "message": f"{action_type.replace('_', ' ').title()} {action_status} for {source_ip}"},
                    "error_message": "pfSense API timeout during rule commit" if action_status == "failed" else None,
                    "rollback_available": action_status == "executed",
                }
            ],
        })
        if idx % 3 == 0:
            scenarios[-1]["response_actions"].append({
                "action_type": "check_ip_status",
                "target": source_ip,
                "minutes_after": 18,
                "status": "executed",
                "initiated_by": "Kamal Safarli",
                "approved_by": None,
                "output": {"provider": "pfSense", "message": f"Checked firewall alias status for {source_ip}"},
                "error_message": None,
                "rollback_available": False,
            })
    return scenarios


def _scenario_catalog(now: datetime) -> list[dict]:
    return [
        {
            "slug": "brute-force-employee-portal",
            "started_hours_ago": 2.5,
            "title": "Brute Force Against Employee Portal",
            "description": "Reverse proxy and identity telemetry show a sustained burst of failed logins from a hostile external IP against a single employee account, followed by a successful session from the same source.",
            "severity": "high",
            "status": "investigating",
            "activation_state": "approved",
            "is_active": True,
            "approval_status": "approved",
            "analyst_verdict": "needs_more_evidence",
            "priority": "high",
            "queue": "Identity Operations",
            "workflow_status": "in_progress",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "reverse_proxy", "azuread"],
            "response_level": 2,
            "category": "authentication",
            "asset_slug": "portal-edge-01",
            "user": "nigar.aliyeva@zerotrustx.demo",
            "owner": "Kamal Safarli",
            "source_ip": "185.193.88.41",
            "destination_ip": "10.40.12.18",
            "verdict_by": None,
            "cia": (1, 1, 0),
            "confidence": 0.92,
            "saved_search_name": "High Volume Authentication Failures - Employee Portal",
            "search": 'index=web_prod sourcetype=nginx:access action=login_failure | stats count by source_ip,user',
            "notes": "Account disabled for forced password reset pending HR confirmation.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0006", "T1110", "Brute Force", "Repeated login failures from one source IP across a short window matched the employee portal rule and supporting web logs.", 88),
                DemoTechnique("TA0001", "T1078", "Valid Accounts", "A successful session followed the failure burst from the same external IP and targeted user, indicating potential credential compromise.", 74),
            ],
            "comments": [
                ("internal_note", "Reverse proxy logs confirm 37 failures in under six minutes against the same employee account."),
                ("status_update", "Identity team notified and password reset initiated through the standard containment workflow."),
            ],
            "steps": [
                {"m": 0, "source_system": "reverse_proxy", "sourcetype": "nginx:access", "index": "web_prod", "action": "login_failure", "event_category": "authentication", "severity": "medium", "message": 'POST /auth/login returned 401 for user nigar.aliyeva@zerotrustx.demo from 185.193.88.41', "signature": "Employee Portal Login Failure Burst", "method": "POST", "path": "/auth/login", "status_code": 401},
                {"m": 2, "source_system": "reverse_proxy", "sourcetype": "nginx:access", "index": "web_prod", "action": "login_failure", "event_category": "authentication", "severity": "medium", "message": 'POST /auth/login returned 401 for user nigar.aliyeva@zerotrustx.demo from 185.193.88.41', "signature": "Employee Portal Login Failure Burst", "method": "POST", "path": "/auth/login", "status_code": 401},
                {"m": 4, "source_system": "azuread", "sourcetype": "azure:signin", "index": "identity", "action": "mfa_failure", "event_category": "authentication", "severity": "medium", "message": "MFA challenge denied after repeated password failures for nigar.aliyeva@zerotrustx.demo", "signature": "Failed MFA After Password Failure"},
                {"m": 6, "source_system": "reverse_proxy", "sourcetype": "nginx:access", "index": "web_prod", "action": "login_success", "event_category": "authentication", "severity": "high", "message": 'POST /auth/login returned 200 for user nigar.aliyeva@zerotrustx.demo from 185.193.88.41', "signature": "Successful Login After Failure Burst", "method": "POST", "path": "/auth/login", "status_code": 200},
                {"m": 9, "source_system": "app_gateway", "sourcetype": "app:gateway", "index": "web_prod", "action": "session_issue", "event_category": "access", "severity": "high", "message": "Employee portal issued privileged session token after unusual authentication pattern", "signature": "Privileged Session Issue"},
            ],
            "response_actions": [
                {"action_type": "check_ip", "status": "executed", "target": "185.193.88.41", "initiated_by": "Kamal Safarli", "approved_by": "Aysel Mammadova", "minutes_after": 18, "output": {"blocked": False, "provider": "pfSense"}, "error_message": None, "rollback_available": False},
            ],
        },
        {
            "slug": "suspicious-powershell-finance",
            "started_hours_ago": 5.5,
            "title": "Suspicious PowerShell Execution on Finance Workstation",
            "description": "Endpoint telemetry captured an encoded PowerShell command that spawned from an Office child process and reached out to an external host before Defender tamper protection was disabled.",
            "severity": "critical",
            "status": "contained",
            "activation_state": "approved",
            "is_active": True,
            "approval_status": "approved",
            "analyst_verdict": "true_positive",
            "priority": "critical",
            "queue": "Endpoint Response",
            "workflow_status": "in_progress",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "edr", "windows"],
            "response_level": 3,
            "category": "endpoint",
            "asset_slug": "finance-ws-044",
            "user": "samir.guliyev@zerotrustx.demo",
            "owner": "Aysel Mammadova",
            "source_ip": "10.20.44.18",
            "destination_ip": "45.146.55.201",
            "verdict_by": "Aysel Mammadova",
            "cia": (2, 2, 1),
            "confidence": 0.97,
            "saved_search_name": "Suspicious PowerShell with EncodedCommand",
            "search": 'index=edr sourcetype=win:eventlogs powershell.exe EncodedCommand | stats count by host,user',
            "notes": "Host isolated from network through endpoint controls. Finance user notified and workstation handed to IR.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0002", "T1059.001", "PowerShell", "Encoded PowerShell execution with a web request and Defender tamper sequence matched EDR detection metadata and process telemetry.", 95),
                DemoTechnique("TA0005", "T1027", "Obfuscated/Compressed Files and Information", "EncodedCommand and base64 fragments indicate deliberate command obfuscation.", 84),
                DemoTechnique("TA0005", "T1562", "Impair Defenses", "Defender service and tamper-protection disable attempts were recorded after execution.", 81),
            ],
            "comments": [
                ("internal_note", "Encoded command resolved to download cradle contacting 45.146.55.201 over HTTPS."),
                ("status_update", "Finance workstation isolated and memory capture requested from endpoint team."),
            ],
            "steps": [
                {"m": 0, "source_system": "edr", "sourcetype": "crowdstrike:process", "index": "edr", "action": "process_start", "event_category": "execution", "severity": "high", "message": "WINWORD.EXE spawned powershell.exe -EncodedCommand JABXAG...", "signature": "Office Child Process Spawning PowerShell"},
                {"m": 1, "source_system": "windows", "sourcetype": "WinEventLog:Microsoft-Windows-PowerShell/Operational", "index": "windows", "action": "powershell_execute", "event_category": "execution", "severity": "critical", "message": "PowerShell script block logged an obfuscated download cradle and environment discovery logic", "signature": "PowerShell EncodedCommand Execution"},
                {"m": 3, "source_system": "proxy", "sourcetype": "proxy:access", "index": "network", "action": "outbound_https", "event_category": "network", "severity": "high", "message": "finance-ws-044 initiated TLS session to 45.146.55.201 shortly after encoded PowerShell execution", "signature": "Endpoint to Suspicious IP", "method": "CONNECT", "path": "45.146.55.201:443", "status_code": 200},
                {"m": 6, "source_system": "windows", "sourcetype": "WinEventLog:System", "index": "windows", "action": "service_change", "event_category": "defense_evasion", "severity": "high", "message": "Windows Defender service configuration changed immediately after malicious process chain", "signature": "Security Tool Disabled Attempt"},
                {"m": 9, "source_system": "edr", "sourcetype": "crowdstrike:detection", "index": "edr", "action": "host_isolated", "event_category": "containment", "severity": "high", "message": "Endpoint isolation executed automatically after high-confidence PowerShell detection", "signature": "Automatic Endpoint Isolation"},
            ],
            "response_actions": [
                {"action_type": "block_ip", "status": "executed", "target": "45.146.55.201", "initiated_by": "Aysel Mammadova", "approved_by": "Aysel Mammadova", "minutes_after": 11, "output": {"message": "IP added to SOC_BLOCK_TEMP", "provider": "pfSense"}, "error_message": None, "rollback_available": True},
            ],
        },
        {
            "slug": "sql-injection-customer-portal",
            "started_hours_ago": 8.0,
            "title": "SQL Injection Attempt Against Customer Portal",
            "description": "WAF and reverse proxy events show classic sqlmap style payloads with UNION SELECT and OR 1=1 patterns against the customer portal search endpoint.",
            "severity": "high",
            "status": "triage",
            "activation_state": "approved",
            "is_active": True,
            "approval_status": "approved",
            "analyst_verdict": "needs_more_evidence",
            "priority": "high",
            "queue": "Application Security",
            "workflow_status": "assigned",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "waf", "reverse_proxy"],
            "response_level": 2,
            "category": "web",
            "asset_slug": "api-edge-02",
            "user": None,
            "owner": "Kamal Safarli",
            "source_ip": "103.27.14.205",
            "destination_ip": "10.40.18.29",
            "verdict_by": None,
            "cia": (1, 2, 0),
            "confidence": 0.91,
            "saved_search_name": "WAF SQL Injection Detection - Customer Portal",
            "search": 'index=web_prod sourcetype=waf:json (sqlmap OR "UNION SELECT" OR "\' OR 1=1") | stats count by source_ip,path',
            "notes": "AppSec requested sample requests and database audit trail review before customer escalation.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0001", "T1190", "Exploit Public-Facing Application", "Multiple WAF hits with UNION SELECT and OR 1=1 payloads targeted the customer API edge within a short interval.", 92),
            ],
            "comments": [
                ("internal_note", "Payloads resemble sqlmap default tamper profiles against /api/v1/search."),
                ("status_update", "Application security team reviewing whether any backend query errors reached the database tier."),
            ],
            "steps": [
                {"m": 0, "source_system": "waf", "sourcetype": "waf:json", "index": "web_prod", "action": "waf_block", "event_category": "web_attack", "severity": "high", "message": 'Blocked request to /api/v1/search?q=\' OR 1=1 -- from 103.27.14.205', "signature": "SQL Injection Pattern", "method": "GET", "path": "/api/v1/search", "status_code": 403},
                {"m": 1, "source_system": "reverse_proxy", "sourcetype": "nginx:access", "index": "web_prod", "action": "http_request", "event_category": "web", "severity": "medium", "message": 'GET /api/v1/search?q=UNION SELECT 1,2,3 returned 403 to 103.27.14.205', "signature": "Customer Portal SQLi", "method": "GET", "path": "/api/v1/search", "status_code": 403},
                {"m": 3, "source_system": "waf", "sourcetype": "waf:json", "index": "web_prod", "action": "waf_block", "event_category": "web_attack", "severity": "high", "message": "Detected sqlmap style User-Agent and blocked follow-up POST against /api/v1/search", "signature": "SQLMap User-Agent", "method": "POST", "path": "/api/v1/search", "status_code": 403},
                {"m": 6, "source_system": "app_gateway", "sourcetype": "app:gateway", "index": "web_prod", "action": "rate_limit", "event_category": "web_defense", "severity": "medium", "message": "Edge rate limiting triggered for repetitive error responses from 103.27.14.205", "signature": "Edge Rate Limit"},
            ],
            "response_actions": [],
        },
        {
            "slug": "external-port-scan-dmz",
            "started_hours_ago": 15.0,
            "title": "Port Scan from External Network",
            "description": "Firewall and IDS telemetry indicate sequential probing of exposed DMZ services from a remote VPS with a pattern consistent with nmap service discovery.",
            "severity": "medium",
            "status": "monitoring",
            "activation_state": "approved",
            "is_active": True,
            "approval_status": "approved",
            "analyst_verdict": "true_positive",
            "priority": "medium",
            "queue": "Network Monitoring",
            "workflow_status": "in_progress",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "ids", "firewall"],
            "response_level": 1,
            "category": "network",
            "asset_slug": "proxy-west-01",
            "user": None,
            "owner": "Laman Rahimova",
            "source_ip": "91.210.174.78",
            "destination_ip": "10.40.20.11",
            "verdict_by": "Kamal Safarli",
            "cia": (0, 1, 0),
            "confidence": 0.79,
            "saved_search_name": "External Network Service Discovery",
            "search": 'index=network (nmap OR "tcp scan" OR "service discovery") | stats count by source_ip,destination_ip',
            "notes": "Still under watch; traffic volume does not yet justify broad blocking across the edge tier.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0007", "T1046", "Network Service Discovery", "Sequential TCP probing across multiple exposed service ports matched IDS signatures and firewall telemetry.", 83),
            ],
            "comments": [
                ("internal_note", "Same source also touched mail-sec-01 and api-edge-02 within the time window."),
            ],
            "steps": [
                {"m": 0, "source_system": "ids", "sourcetype": "suricata:alert", "index": "network", "action": "scan_detected", "event_category": "reconnaissance", "severity": "medium", "message": "ET SCAN Potential Nmap Scan from 91.210.174.78 to 10.40.20.11", "signature": "ET SCAN Potential Nmap Scan"},
                {"m": 2, "source_system": "firewall", "sourcetype": "pfsense:filterlog", "index": "firewall", "action": "deny", "event_category": "firewall", "severity": "low", "message": "Blocked repeated SYN packets from 91.210.174.78 to ports 22, 80, 443 and 8443 on proxy-west-01", "signature": "Repeated Port Probing"},
                {"m": 5, "source_system": "ids", "sourcetype": "suricata:alert", "index": "network", "action": "scan_detected", "event_category": "reconnaissance", "severity": "medium", "message": "IDS observed service fingerprint probes consistent with version detection", "signature": "Service Version Detection"},
            ],
            "response_actions": [
                {"action_type": "check_ip", "status": "executed", "target": "91.210.174.78", "initiated_by": "Kamal Safarli", "approved_by": "Aysel Mammadova", "minutes_after": 12, "output": {"blocked": False, "provider": "pfSense"}, "error_message": None, "rollback_available": False},
            ],
        },
        {
            "slug": "malicious-ip-web-logs",
            "started_hours_ago": 28.0,
            "title": "Malicious IP Observed in Web Logs",
            "description": "Known hostile infrastructure was observed probing administrative endpoints and triggering abuse/reputation detections in reverse proxy logs.",
            "severity": "high",
            "status": "resolved",
            "activation_state": "approved",
            "is_active": False,
            "approval_status": "approved",
            "analyst_verdict": "true_positive",
            "priority": "high",
            "queue": "SOC Tier 2",
            "workflow_status": "resolved",
            "source": "IP Reputation",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "reverse_proxy", "reputation"],
            "response_level": 2,
            "category": "network",
            "asset_slug": "portal-edge-01",
            "user": None,
            "owner": "Aysel Mammadova",
            "source_ip": "77.91.124.33",
            "destination_ip": "10.40.12.18",
            "verdict_by": "Aysel Mammadova",
            "cia": (1, 1, 0),
            "confidence": 0.86,
            "saved_search_name": "Known Malicious Infrastructure in Web Telemetry",
            "search": 'index=web_prod sourcetype=nginx:access ("/admin" OR "/login") | lookup malicious_ip_inventory ip as source_ip OUTPUT verdict',
            "notes": "Source blocked at pfSense and WAF geo-blocking policy updated.",
            "resolution_notes": "No post-auth activity observed. Closed after 24 hours of quiet telemetry.",
            "close_reason": "Source blocked and no additional activity observed.",
            "mitre": [
                DemoTechnique("TA0007", "T1595", "Active Scanning", "Administrative paths and exposed endpoints were probed from a malicious IP with repeated reconnaissance behavior.", 71),
                DemoTechnique("TA0001", "T1190", "Exploit Public-Facing Application", "Requests specifically targeted administrative URLs and login handlers immediately before the block action.", 68),
            ],
            "comments": [
                ("internal_note", "Reputation enrichment flagged the address as previously linked to credential theft infrastructure."),
            ],
            "steps": [
                {"m": 0, "source_system": "reverse_proxy", "sourcetype": "nginx:access", "index": "web_prod", "action": "http_request", "event_category": "web", "severity": "medium", "message": "GET /admin/login from 77.91.124.33 returned 404", "signature": "Admin Path Reconnaissance", "method": "GET", "path": "/admin/login", "status_code": 404},
                {"m": 2, "source_system": "reverse_proxy", "sourcetype": "nginx:access", "index": "web_prod", "action": "http_request", "event_category": "web", "severity": "medium", "message": "GET /server-status from 77.91.124.33 returned 403", "signature": "Administrative Endpoint Probing", "method": "GET", "path": "/server-status", "status_code": 403},
                {"m": 5, "source_system": "reputation", "sourcetype": "reputation:alert", "index": "intel", "action": "ip_enrichment", "event_category": "threat_intel", "severity": "high", "message": "AbuseIPDB and VirusTotal both reported malicious signals for 77.91.124.33", "signature": "Malicious IP Reputation Match"},
            ],
            "response_actions": [
                {"action_type": "block_ip", "status": "executed", "target": "77.91.124.33", "initiated_by": "Aysel Mammadova", "approved_by": "Aysel Mammadova", "minutes_after": 10, "output": {"message": "IP added to SOC_BLOCK_TEMP", "provider": "pfSense"}, "error_message": None, "rollback_available": True},
            ],
        },
        {
            "slug": "outbound-traffic-spike-file-server",
            "started_hours_ago": 35.0,
            "title": "Unusual Outbound Traffic Spike from File Server",
            "description": "NetFlow and proxy telemetry show a large outbound transfer from a file server to a suspicious external destination after archive creation activity on the host.",
            "severity": "critical",
            "status": "investigating",
            "activation_state": "approved",
            "is_active": True,
            "approval_status": "approved",
            "analyst_verdict": "true_positive",
            "priority": "critical",
            "queue": "Data Protection",
            "workflow_status": "escalated",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "netflow", "proxy", "windows"],
            "response_level": 3,
            "category": "data_exfiltration",
            "asset_slug": "file-srv-02",
            "user": "svc.backup@zerotrustx.demo",
            "owner": "Aysel Mammadova",
            "source_ip": "10.30.8.25",
            "destination_ip": "45.146.55.201",
            "verdict_by": "Aysel Mammadova",
            "cia": (2, 2, 1),
            "confidence": 0.94,
            "saved_search_name": "Outbound Data Exfiltration Pattern",
            "search": 'index=network sourcetype=netflow bytes_out>500000000 | stats sum(bytes_out) by source_ip,destination_ip',
            "notes": "Outbound session terminated. Legal and data governance notified because the host contained HR export material.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0009", "T1560", "Archive Collected Data", "The server created a compressed archive immediately before the large outbound transfer.", 82),
                DemoTechnique("TA0010", "T1041", "Exfiltration Over C2 Channel", "NetFlow and proxy records show a high-volume outbound session to suspicious infrastructure after staging.", 90),
            ],
            "comments": [
                ("internal_note", "Archive name payroll_export_2026-04.zip was created seconds before outbound transfer."),
                ("status_update", "Transfer interrupted and file server placed under elevated monitoring."),
            ],
            "steps": [
                {"m": 0, "source_system": "windows", "sourcetype": "WinEventLog:Security", "index": "windows", "action": "archive_create", "event_category": "collection", "severity": "high", "message": "7zip created archive payroll_export_2026-04.zip on file-srv-02", "signature": "Archive Created on Sensitive Server"},
                {"m": 3, "source_system": "netflow", "sourcetype": "netflow:v9", "index": "network", "action": "large_outbound_transfer", "event_category": "exfiltration", "severity": "critical", "message": "Large outbound transfer from file-srv-02 to 45.146.55.201 exceeded 1.8 GB", "signature": "Unusual Outbound Transfer Spike"},
                {"m": 4, "source_system": "proxy", "sourcetype": "proxy:access", "index": "network", "action": "outbound_https", "event_category": "exfiltration", "severity": "high", "message": "Proxy observed sustained encrypted upload session from file-srv-02 to 45.146.55.201", "signature": "Encrypted Upload to Suspicious Host", "method": "PUT", "path": "/upload/archive", "status_code": 200},
                {"m": 8, "source_system": "firewall", "sourcetype": "pfsense:filterlog", "index": "firewall", "action": "session_reset", "event_category": "containment", "severity": "high", "message": "SOC reset active session from file-srv-02 to 45.146.55.201 after exfiltration alert", "signature": "Containment Session Reset"},
            ],
            "response_actions": [
                {"action_type": "block_ip", "status": "executed", "target": "45.146.55.201", "initiated_by": "Aysel Mammadova", "approved_by": "Aysel Mammadova", "minutes_after": 9, "output": {"message": "IP added to SOC_BLOCK_TEMP", "provider": "pfSense"}, "error_message": None, "rollback_available": True},
            ],
        },
        {
            "slug": "privileged-vpn-access-after-mfa-failures",
            "started_hours_ago": 52.0,
            "title": "Suspicious Admin Access Pattern",
            "description": "A privileged VPN account experienced repeated MFA failures followed by a successful session from a new geography and immediate access to an administrative jump host.",
            "severity": "high",
            "status": "contained",
            "activation_state": "approved",
            "is_active": False,
            "approval_status": "approved",
            "analyst_verdict": "true_positive",
            "priority": "high",
            "queue": "Privileged Access",
            "workflow_status": "resolved",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "vpn", "identity", "windows"],
            "response_level": 3,
            "category": "authentication",
            "asset_slug": "jump-admin-01",
            "user": "it.admin@zerotrustx.demo",
            "owner": "Aysel Mammadova",
            "source_ip": "185.193.88.41",
            "destination_ip": "10.50.1.10",
            "verdict_by": "Aysel Mammadova",
            "cia": (2, 2, 1),
            "confidence": 0.9,
            "saved_search_name": "Privileged VPN Access After Failed MFA",
            "search": 'index=identity sourcetype=vpn:auth (mfa_failure OR login_success) user=it.admin@zerotrustx.demo',
            "notes": "Account password reset, VPN token reissued, and all active sessions revoked.",
            "resolution_notes": "Closed after credential reset and admin workstation sweep.",
            "close_reason": "Credential reset complete and no additional malicious activity observed.",
            "mitre": [
                DemoTechnique("TA0006", "T1110.003", "Password Spraying", "Multiple failed MFA attempts and password failures originated from one IP before privileged VPN access succeeded.", 79),
                DemoTechnique("TA0001", "T1078", "Valid Accounts", "Successful privileged login after repeated failures strongly suggests compromised but valid credentials.", 87),
            ],
            "comments": [
                ("internal_note", "Privileged account accessed jump-admin-01 within three minutes of VPN success."),
            ],
            "steps": [
                {"m": 0, "source_system": "vpn", "sourcetype": "vpn:auth", "index": "identity", "action": "login_failure", "event_category": "authentication", "severity": "medium", "message": "VPN login failed for it.admin@zerotrustx.demo from 185.193.88.41", "signature": "Privileged VPN Login Failure"},
                {"m": 2, "source_system": "identity", "sourcetype": "azure:signin", "index": "identity", "action": "mfa_failure", "event_category": "authentication", "severity": "medium", "message": "Authenticator challenge failed for it.admin@zerotrustx.demo from new ASN", "signature": "MFA Failure for Privileged User"},
                {"m": 5, "source_system": "vpn", "sourcetype": "vpn:auth", "index": "identity", "action": "login_success", "event_category": "authentication", "severity": "high", "message": "VPN tunnel established for it.admin@zerotrustx.demo from 185.193.88.41", "signature": "Privileged VPN Success"},
                {"m": 8, "source_system": "windows", "sourcetype": "WinEventLog:Security", "index": "windows", "action": "rdp_logon", "event_category": "access", "severity": "high", "message": "RDP logon to jump-admin-01 from VPN session tied to it.admin@zerotrustx.demo", "signature": "Admin Jump Host Access"},
            ],
            "response_actions": [
                {"action_type": "block_ip", "status": "executed", "target": "185.193.88.41", "initiated_by": "Aysel Mammadova", "approved_by": "Aysel Mammadova", "minutes_after": 13, "output": {"message": "IP added to SOC_BLOCK_TEMP", "provider": "pfSense"}, "error_message": None, "rollback_available": True},
            ],
        },
        {
            "slug": "security-tool-disabled-workstation",
            "started_hours_ago": 79.0,
            "title": "Security Tool Disabled on Endpoint",
            "description": "Endpoint defense telemetry recorded an attempt to stop and tamper with security tooling on an HR workstation during suspicious script execution.",
            "severity": "high",
            "status": "triage",
            "activation_state": "approved",
            "is_active": True,
            "approval_status": "approved",
            "analyst_verdict": "needs_more_evidence",
            "priority": "high",
            "queue": "Endpoint Response",
            "workflow_status": "assigned",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "edr", "windows"],
            "response_level": 2,
            "category": "endpoint",
            "asset_slug": "hr-ws-022",
            "user": "leyla.hasanova@zerotrustx.demo",
            "owner": "Kamal Safarli",
            "source_ip": "10.20.52.22",
            "destination_ip": "34.107.221.82",
            "verdict_by": None,
            "cia": (1, 2, 0),
            "confidence": 0.84,
            "saved_search_name": "Endpoint Defense Tamper Attempt",
            "search": 'index=edr (tamper OR "stop-service" OR "disable defender") host=hr-ws-022',
            "notes": "Awaiting full EDR telemetry pull and user interview.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0005", "T1562", "Impair Defenses", "Service stop and tamper-protection events on the endpoint align with active efforts to disable security controls.", 86),
                DemoTechnique("TA0002", "T1059", "Command and Scripting Interpreter", "Security tool tamper attempt was executed through scripted command-line activity.", 63),
            ],
            "comments": [
                ("internal_note", "No confirmed external beaconing yet; waiting on EDR deep process tree export."),
            ],
            "steps": [
                {"m": 0, "source_system": "edr", "sourcetype": "crowdstrike:process", "index": "edr", "action": "script_execute", "event_category": "execution", "severity": "medium", "message": "cmd.exe launched PowerShell and sc.exe stop WinDefend on hr-ws-022", "signature": "Scripted Security Tool Stop"},
                {"m": 1, "source_system": "windows", "sourcetype": "WinEventLog:System", "index": "windows", "action": "service_change", "event_category": "defense_evasion", "severity": "high", "message": "Windows Defender service stop attempted by user leyla.hasanova@zerotrustx.demo", "signature": "Security Service Stop Attempt"},
                {"m": 4, "source_system": "edr", "sourcetype": "crowdstrike:detection", "index": "edr", "action": "tamper_detected", "event_category": "defense_evasion", "severity": "high", "message": "EDR tamper protection blocked modification of endpoint protection settings", "signature": "Tamper Protection Triggered"},
            ],
            "response_actions": [],
        },
        {
            "slug": "credential-stuffing-vpn-gateway",
            "started_hours_ago": 110.0,
            "title": "Possible Credential Stuffing Against VPN Gateway",
            "description": "The VPN gateway saw one external source attempt authentication across many usernames with a tight cadence and consistent User-Agent values.",
            "severity": "high",
            "status": "pending_approval",
            "activation_state": "pending_approval",
            "is_active": False,
            "approval_status": "pending",
            "analyst_verdict": "needs_more_evidence",
            "priority": "high",
            "queue": "Identity Operations",
            "workflow_status": "waiting",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "vpn"],
            "response_level": 2,
            "category": "authentication",
            "asset_slug": "vpn-gateway-01",
            "user": None,
            "owner": "Laman Rahimova",
            "source_ip": "77.91.124.33",
            "destination_ip": "10.10.5.14",
            "verdict_by": None,
            "cia": (1, 1, 0),
            "confidence": 0.81,
            "saved_search_name": "VPN Username Spray / Credential Stuffing",
            "search": 'index=identity sourcetype=vpn:auth action=login_failure | stats dc(user) by source_ip',
            "notes": "Pending approval for broad block because the same address also appears in a shared threat feed used by another team.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0006", "T1110.004", "Credential Stuffing", "One source IP attempted many usernames with consistent cadence against the VPN surface.", 84),
            ],
            "comments": [
                ("internal_note", "No successful logins observed, but username spray pattern is strong enough to keep the candidate queued."),
            ],
            "steps": [
                {"m": 0, "source_system": "vpn", "sourcetype": "vpn:auth", "index": "identity", "action": "login_failure", "event_category": "authentication", "severity": "medium", "message": "Failed VPN login for a.kerimova@zerotrustx.demo from 77.91.124.33", "signature": "Repeated Failed VPN Login"},
                {"m": 1, "source_system": "vpn", "sourcetype": "vpn:auth", "index": "identity", "action": "login_failure", "event_category": "authentication", "severity": "medium", "message": "Failed VPN login for t.musayev@zerotrustx.demo from 77.91.124.33", "signature": "Repeated Failed VPN Login"},
                {"m": 2, "source_system": "vpn", "sourcetype": "vpn:auth", "index": "identity", "action": "login_failure", "event_category": "authentication", "severity": "medium", "message": "Failed VPN login for n.aliyeva@zerotrustx.demo from 77.91.124.33", "signature": "Repeated Failed VPN Login"},
            ],
            "response_actions": [
                {"action_type": "block_ip", "status": "pending_approval", "target": "77.91.124.33", "initiated_by": "Kamal Safarli", "approved_by": None, "minutes_after": 9, "output": {"message": "Awaiting approval"}, "error_message": None, "rollback_available": True},
            ],
        },
        {
            "slug": "archive-and-exfil-staging",
            "started_hours_ago": 156.0,
            "title": "Archive and Exfiltration Staging on Workstation",
            "description": "A user workstation compressed browser exports and staged them in a temp directory before making an outbound upload to a suspicious destination.",
            "severity": "high",
            "status": "resolved",
            "activation_state": "approved",
            "is_active": False,
            "approval_status": "approved",
            "analyst_verdict": "true_positive",
            "priority": "high",
            "queue": "Endpoint Response",
            "workflow_status": "resolved",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "proxy", "windows"],
            "response_level": 2,
            "category": "data_exfiltration",
            "asset_slug": "finance-ws-044",
            "user": "samir.guliyev@zerotrustx.demo",
            "owner": "Kamal Safarli",
            "source_ip": "10.20.44.18",
            "destination_ip": "103.27.14.205",
            "verdict_by": "Kamal Safarli",
            "cia": (2, 1, 0),
            "confidence": 0.87,
            "saved_search_name": "User Archive Staging Before Upload",
            "search": 'index=windows (zip OR archive) | join host [ search index=network outbound upload ]',
            "notes": "Case closed after reimage and manager review of exported documents.",
            "resolution_notes": "User admitted policy violation; no malware evidence found after triage.",
            "close_reason": "Confirmed policy violation, containment complete.",
            "mitre": [
                DemoTechnique("TA0009", "T1560", "Archive Collected Data", "Browser export and ZIP staging were recorded before upload activity.", 85),
                DemoTechnique("TA0010", "T1567", "Exfiltration Over Web Service", "Proxy recorded a POST upload to an external file sharing service after staging.", 78),
            ],
            "comments": [
                ("internal_note", "Policy violation rather than malware, but exfiltration workflow was followed due to sensitive data exposure risk."),
            ],
            "steps": [
                {"m": 0, "source_system": "windows", "sourcetype": "WinEventLog:Security", "index": "windows", "action": "archive_create", "event_category": "collection", "severity": "medium", "message": "zip archive customer_exports.zip created in user temp directory", "signature": "Archive Created in Temp Path"},
                {"m": 3, "source_system": "proxy", "sourcetype": "proxy:access", "index": "network", "action": "outbound_upload", "event_category": "exfiltration", "severity": "high", "message": "POST upload to fileshare.example/upload from finance-ws-044", "signature": "Outbound File Upload", "method": "POST", "path": "/upload", "status_code": 200},
            ],
            "response_actions": [
                {"action_type": "check_ip", "status": "executed", "target": "103.27.14.205", "initiated_by": "Kamal Safarli", "approved_by": "Aysel Mammadova", "minutes_after": 15, "output": {"blocked": False, "provider": "pfSense"}, "error_message": None, "rollback_available": False},
            ],
        },
        {
            "slug": "scanner-activity-false-positive",
            "started_hours_ago": 220.0,
            "title": "Approved Vulnerability Scanner Activity",
            "description": "External scan pattern initially resembled reconnaissance but was validated as an approved quarterly assessment from the internal security engineering team.",
            "severity": "low",
            "status": "false_positive",
            "activation_state": "approved",
            "is_active": False,
            "approval_status": "approved",
            "analyst_verdict": "false_positive",
            "priority": "low",
            "queue": "Network Monitoring",
            "workflow_status": "closed",
            "source": "splunk",
            "detection_source": "splunk_alert",
            "source_systems": ["splunk", "ids"],
            "response_level": 1,
            "category": "reconnaissance",
            "asset_slug": "api-edge-02",
            "user": None,
            "owner": "Laman Rahimova",
            "source_ip": "52.29.87.144",
            "destination_ip": "10.40.18.29",
            "verdict_by": "Laman Rahimova",
            "cia": (0, 0, 0),
            "confidence": 0.52,
            "saved_search_name": "External Scan Pattern - Quarterly Validation",
            "search": 'index=network sourcetype=suricata:alert "scan" source_ip=52.29.87.144',
            "notes": "Closed as approved scanner after validation with Security Engineering change record SEC-2026-044.",
            "resolution_notes": "Validated as internal assessment traffic.",
            "close_reason": "Approved scanner activity.",
            "mitre": [
                DemoTechnique("TA0007", "T1046", "Network Service Discovery", "Scan pattern matched service discovery behavior but was ultimately attributable to approved internal testing.", 41),
            ],
            "comments": [
                ("internal_note", "Cross-check with change calendar confirmed the scanner IP belongs to the quarterly validation window."),
            ],
            "steps": [
                {"m": 0, "source_system": "ids", "sourcetype": "suricata:alert", "index": "network", "action": "scan_detected", "event_category": "reconnaissance", "severity": "low", "message": "Potential scan activity detected from approved validation source 52.29.87.144", "signature": "Potential Scan Activity"},
            ],
            "response_actions": [],
        },
        {
            "slug": "suspicious-admin-share-access",
            "started_hours_ago": 300.0,
            "title": "Suspicious Admin Share Access from New Host",
            "description": "An administrative share on the domain controller was accessed from a non-standard host shortly after account discovery commands were executed.",
            "severity": "medium",
            "status": "in_review",
            "activation_state": "approved",
            "is_active": True,
            "approval_status": "approved",
            "analyst_verdict": "needs_more_evidence",
            "priority": "medium",
            "queue": "SOC Tier 2",
            "workflow_status": "assigned",
            "source": "splunk",
            "detection_source": "splunk_report",
            "source_systems": ["splunk", "windows"],
            "response_level": 2,
            "category": "endpoint",
            "asset_slug": "dc-auth-01",
            "user": "svc.deploy@zerotrustx.demo",
            "owner": "Kamal Safarli",
            "source_ip": "10.20.52.22",
            "destination_ip": "10.20.1.15",
            "verdict_by": None,
            "cia": (1, 1, 0),
            "confidence": 0.73,
            "saved_search_name": "Admin Share Access After Discovery Commands",
            "search": 'index=windows ("net user" OR "whoami" OR "dir \\\\") host=hr-ws-022',
            "notes": "Correlating with software deployment window before escalating to identity engineering.",
            "resolution_notes": None,
            "close_reason": None,
            "mitre": [
                DemoTechnique("TA0007", "T1087", "Account Discovery", "Discovery commands preceded admin share access against a domain controller.", 69),
                DemoTechnique("TA0007", "T1083", "File and Directory Discovery", "Directory listing commands targeted administrative shares immediately after discovery activity.", 62),
            ],
            "comments": [
                ("internal_note", "May be linked to an unauthorized software packaging script; still under review."),
            ],
            "steps": [
                {"m": 0, "source_system": "windows", "sourcetype": "WinEventLog:Security", "index": "windows", "action": "command_execute", "event_category": "discovery", "severity": "medium", "message": "net user /domain executed from hr-ws-022 under svc.deploy@zerotrustx.demo", "signature": "Account Discovery Command"},
                {"m": 2, "source_system": "windows", "sourcetype": "WinEventLog:Security", "index": "windows", "action": "share_access", "event_category": "discovery", "severity": "medium", "message": "Administrative share \\\\dc-auth-01\\c$ accessed from hr-ws-022", "signature": "Administrative Share Access"},
            ],
            "response_actions": [],
        },
    ]


def _scenario_times(now: datetime, started_hours_ago: float, step_minutes: list[int]) -> tuple[datetime, list[datetime]]:
    start = now - timedelta(hours=started_hours_ago)
    return start, [start + timedelta(minutes=minutes) for minutes in step_minutes]


def _build_scenarios(now: datetime) -> tuple[list[dict], list[dict]]:
    scenario_rows: list[dict] = []
    all_events: list[dict] = []
    for scenario in [*_scenario_catalog(now), *_generated_scenarios(now)]:
        asset = _asset_by_slug(scenario["asset_slug"])
        step_minutes = [step["m"] for step in scenario["steps"]]
        started_at, event_times = _scenario_times(now, scenario["started_hours_ago"], step_minutes)
        alert_id = demo_uuid("alert-live", scenario["slug"])
        incident_id = demo_uuid("incident", scenario["slug"])
        events = []
        for idx, (step, event_time) in enumerate(zip(scenario["steps"], event_times), start=1):
            event = _event(
                scenario["slug"],
                idx,
                event_time,
                source_system=step["source_system"],
                sourcetype=step["sourcetype"],
                index=step["index"],
                host=asset["hostname"],
                source_ip=scenario["source_ip"],
                destination_ip=scenario["destination_ip"],
                user=scenario["user"],
                action=step["action"],
                event_category=step["event_category"],
                severity=step["severity"],
                message=step["message"],
                signature=step.get("signature"),
                method=step.get("method"),
                path=step.get("path"),
                status_code=step.get("status_code"),
                saved_search_name=scenario["saved_search_name"],
            )
            events.append(event)
        all_events.extend(events)
        last_seen = _dt(events[-1]["time"])
        triaged_at = started_at + timedelta(minutes=14)
        contained_at = started_at + timedelta(minutes=20) if scenario["status"] in {"contained", "resolved", "false_positive"} else None
        closed_at = None
        if scenario["status"] in {"resolved", "false_positive"}:
            closed_at = last_seen + timedelta(hours=10)
        alert_event = events[min(1, len(events) - 1)]
        scenario_rows.append(
            {
                **scenario,
                "id": incident_id,
                "alert_id": alert_id,
                "asset": asset,
                "events": events,
                "started_at": started_at,
                "first_seen": started_at,
                "last_seen": last_seen,
                "triaged_at": triaged_at,
                "contained_at": contained_at,
                "closed_at": closed_at,
                "alert_time": _dt(alert_event["time"]),
                "result_count": max(3, len(events) + random.randint(1, 4)),
            }
        )
    return scenario_rows, all_events


def _background_events(now: datetime) -> list[dict]:
    assets = list(DEMO_ASSETS)
    users = [
        "nigar.aliyeva@zerotrustx.demo",
        "samir.guliyev@zerotrustx.demo",
        "leyla.hasanova@zerotrustx.demo",
        "it.admin@zerotrustx.demo",
        "svc.backup@zerotrustx.demo",
    ]
    public_ips = DEMO_PUBLIC_IP_POOL
    events: list[dict] = []
    for idx in range(1, 901):
        asset = assets[idx % len(assets)]
        user = users[idx % len(users)]
        when = now - timedelta(minutes=idx * 23)
        public_ip = public_ips[idx % len(public_ips)]
        if idx % 6 == 0:
            message = f"Successful SSO login for {user} on {asset['hostname']}"
            event = _event(
                "background-auth",
                idx,
                when,
                source_system="azuread",
                sourcetype="azure:signin",
                index="identity",
                host=asset["hostname"],
                source_ip=public_ip,
                destination_ip=asset["ip"],
                user=user,
                action="login_success",
                event_category="authentication",
                severity="low",
                message=message,
                signature="Routine Successful Login",
            )
        elif idx % 6 == 1:
            message = f"DNS request from {asset['hostname']} to internal resolver completed"
            event = _event(
                "background-dns",
                idx,
                when,
                source_system="dns",
                sourcetype="dns:query",
                index="infra",
                host=asset["hostname"],
                source_ip=asset["ip"],
                destination_ip="10.20.1.53",
                user=user,
                action="dns_query",
                event_category="network",
                severity="informational",
                message=message,
                signature="Routine DNS Query",
            )
        elif idx % 6 == 2:
            message = f"Allowed HTTPS request from {asset['hostname']} to updates.vendor.example"
            event = _event(
                "background-proxy",
                idx,
                when,
                source_system="proxy",
                sourcetype="proxy:access",
                index="network",
                host=asset["hostname"],
                source_ip=asset["ip"],
                destination_ip=public_ip,
                user=user,
                action="outbound_https",
                event_category="network",
                severity="informational",
                message=message,
                signature="Routine Outbound HTTPS",
                method="CONNECT",
                path="updates.vendor.example:443",
                status_code=200,
            )
        elif idx % 6 == 3:
            message = f"pfSense blocked inbound probe from {public_ip} to {asset['hostname']} port {80 + (idx % 3) * 363}"
            event = _event(
                "background-firewall",
                idx,
                when,
                source_system="pfsense",
                sourcetype="pfsense:filterlog",
                index="firewall",
                host="pfsense-fw-01",
                source_ip=public_ip,
                destination_ip=asset["ip"],
                user=None,
                action="blocked",
                event_category="network_scan",
                severity="medium" if idx % 12 else "high",
                message=message,
                signature="Inbound Probe Blocked",
            )
        elif idx % 6 == 4:
            message = f"Web request from {public_ip} to {asset['hostname']} returned {403 if idx % 2 else 404}"
            event = _event(
                "background-web",
                idx,
                when,
                source_system="nginx",
                sourcetype="nginx:access",
                index="web",
                host=asset["hostname"],
                source_ip=public_ip,
                destination_ip=asset["ip"],
                user=None,
                action="http_request",
                event_category="web_access",
                severity="low",
                message=message,
                signature="Web Access",
                method="GET",
                path="/admin/login",
                status_code=403 if idx % 2 else 404,
            )
        else:
            command = "powershell -nop -w hidden" if idx % 15 == 0 else "whoami /groups"
            message = f"Endpoint process event on {asset['hostname']}: {command}"
            event = _event(
                "background-endpoint",
                idx,
                when,
                source_system="windows",
                sourcetype="WinEventLog:Security",
                index="endpoint",
                host=asset["hostname"],
                source_ip=asset["ip"],
                destination_ip=None,
                user=user,
                action="process_start",
                event_category="execution",
                severity="medium" if "powershell" in command else "informational",
                message=message,
                signature="Endpoint Process Start",
                extra={"process": command},
            )
        events.append(event)
    return events


def _saved_search_items(now: datetime, scenarios: list[dict]) -> list[dict]:
    items = []
    for scenario in scenarios:
        items.append(
            {
                "id": scenario["alert_id"],
                "name": scenario["saved_search_name"],
                "title": scenario["saved_search_name"],
                "search": scenario["search"],
                "is_scheduled": True,
                "alert_type": "number of events",
                "cron_schedule": "*/15 * * * *",
                "disabled": False,
                "actions": "webhook",
                "description": scenario["description"],
                "trigger_condition": f"severity>={scenario['severity']}",
                "alert_condition": "result_count > 0",
                "alert_comparator": ">",
                "alert_threshold": 0,
                "severity": scenario["severity"],
                "last_triggered": _iso(scenario["alert_time"]),
                "source": "splunk",
                "type": "alert",
            }
        )
    report_rows = [
        ("report-daily-soc-summary", "Daily SOC Operations Summary", 'index=* earliest=-24h | stats count by source_system,severity', "0 7 * * *", "Executive rollup of incidents, alerts, and containment outcomes across the last 24 hours."),
        ("report-attack-sources", "Top External Source IPs - 24h", 'index=network source_ip=* | stats count by source_ip | sort -count', "15 7 * * *", "Ranks the highest-volume external sources seen in network and proxy telemetry."),
        ("report-mitre-coverage", "MITRE ATT&CK Coverage Snapshot", 'index=edr OR index=web_prod OR index=identity | stats count by signature', "30 7 * * *", "Highlights detections mapped to ATT&CK techniques over the last seven days."),
        ("report-response-audit", "Response Action Audit - 7d", 'index=firewall OR index=edr | stats count by action,status', "45 7 * * *", "Containment activity report suitable for operations review."),
        ("report-executive-trends", "Executive Threat Trends - Weekly", 'index=* earliest=-7d | timechart span=1d count by severity', "0 8 * * 1", "Weekly trend report used for leadership review."),
        ("report-auth-risk", "Authentication Risk Review", 'index=identity earliest=-7d | stats count by user,action,source_ip', "20 8 * * *", "Identity and MFA anomaly review for SOC handoff."),
        ("report-web-threats", "Public Web Threat Summary", 'index=web earliest=-24h | stats count by status,path,source_ip', "35 8 * * *", "Daily view of SQL injection, path traversal, and credential attacks against public applications."),
        ("report-firewall-blocks", "Firewall Containment Summary", 'index=firewall earliest=-24h | stats count by target_ip,status', "50 8 * * *", "pfSense action history and currently blocked IPs."),
        ("report-reputation-watchlist", "IP Reputation Watchlist", 'index=* source_ip=* | lookup reputation ip as source_ip | stats max(score) by source_ip', "5 9 * * *", "High-risk public IPs observed in telemetry with AbuseIPDB and VirusTotal signals."),
        ("report-assets-risk", "Asset Risk Distribution", 'index=* host=* | stats count by host,zone,severity', "15 9 * * *", "Asset-level operational exposure and event distribution."),
        ("report-zone-activity", "Zone Activity Heatmap", 'index=* earliest=-7d | stats count by zone,event_category', "30 9 * * *", "Network zone activity and incident pressure by functional area."),
        ("report-database-security", "Database Security Review", 'index=database earliest=-7d | stats count by action,user,source_ip', "45 9 * * 2", "Database login and query anomaly review."),
        ("report-endpoint-execution", "Endpoint Execution Detections", 'index=endpoint earliest=-7d | search process=* | stats count by host,process,severity', "0 10 * * *", "PowerShell, command shell, and unsigned script execution summary."),
        ("report-compliance-ops", "Operational Security Compliance Snapshot", 'index=* earliest=-30d | stats count by control,status', "0 11 * * 5", "Monthly compliance-oriented operational status rollup."),
        ("report-incident-posture", "Incident Posture Board", 'index=alerts earliest=-7d | stats count by severity,status,queue', "25 11 * * *", "Triage workload, SLA exposure, and incident workflow status."),
    ]
    for slug, title, search, cron, description in report_rows:
        items.append(
            {
                "id": demo_uuid("saved-search", slug),
                "name": title,
                "title": title,
                "search": search,
                "is_scheduled": True,
                "alert_type": "",
                "cron_schedule": cron,
                "disabled": False,
                "actions": "",
                "description": description,
                "trigger_condition": "",
                "alert_condition": "",
                "alert_comparator": "",
                "alert_threshold": None,
                "severity": "informational",
                "last_triggered": _iso(now - timedelta(hours=6)),
                "source": "splunk",
                "type": "report",
            }
        )
    return items


def _fired_alerts(scenarios: list[dict]) -> list[dict]:
    items = []
    for scenario in scenarios:
        items.append(
            {
                "id": scenario["alert_id"],
                "name": scenario["saved_search_name"],
                "severity": scenario["severity"],
                "status": scenario["status"],
                "trigger_time": _iso(scenario["alert_time"]),
                "saved_search_name": scenario["saved_search_name"],
                "search_name": scenario["saved_search_name"],
                "search": scenario["search"],
                "trigger_condition": "result_count > 0",
                "result_count": scenario["result_count"],
                "source_ref": scenario["alert_id"],
                "source_hash": hashlib.sha256(f"{scenario['alert_id']}|{scenario['slug']}".encode("utf-8")).hexdigest(),
                "sid": f"sid_{scenario['slug']}",
                "source": "splunk",
            }
        )
    return items


def _incident_entities(scenario: dict) -> dict:
    asset = scenario["asset"]
    return {
        "source_ip": scenario["source_ip"],
        "destination_ip": scenario["destination_ip"],
        "user": scenario["user"],
        "host": asset["hostname"],
        "trigger_time": _iso(scenario["alert_time"]),
        "saved_search_name": scenario["saved_search_name"],
        "query": scenario["search"],
        "result_count": scenario["result_count"],
        "related_ips": [scenario["source_ip"], scenario["destination_ip"]],
        "demo_mode": True,
        "scenario": scenario["slug"],
    }


def _reputation_row(ip: str, now: datetime) -> dict:
    profile = _public_profile(ip)
    score = profile["score"]
    verdict = profile["verdict"]
    return {
        "id": demo_uuid("reputation", ip),
        "ip_address": ip,
        "is_public": True,
        "overall_score": score,
        "overall_verdict": verdict,
        "abuseipdb_score": profile["abuseipdb_score"],
        "abuseipdb_total_reports": profile["total_reports"],
        "abuseipdb_country_code": profile["country"],
        "abuseipdb_usage_type": profile["usage_type"],
        "abuseipdb_isp": profile["isp"],
        "abuseipdb_domain": profile["domain"],
        "abuseipdb_last_reported_at": _dt(profile["last_reported_at"]) if profile["last_reported_at"] else None,
        "virustotal_malicious": profile["vt_malicious"],
        "virustotal_suspicious": profile["vt_suspicious"],
        "virustotal_harmless": profile["vt_harmless"],
        "virustotal_undetected": profile["vt_undetected"],
        "virustotal_reputation": profile["vt_reputation"],
        "virustotal_country": profile["country"],
        "virustotal_as_owner": profile["as_owner"],
        "virustotal_network": profile["network"],
        "provider_sources": {
            "abuseipdb": {
                "success": True,
                "score": profile["abuseipdb_score"],
                "total_reports": profile["total_reports"],
                "country_code": profile["country"],
                "error": None,
            },
            "virustotal": {
                "success": True,
                "malicious": profile["vt_malicious"],
                "suspicious": profile["vt_suspicious"],
                "harmless": profile["vt_harmless"],
                "undetected": profile["vt_undetected"],
                "reputation": profile["vt_reputation"],
                "error": None,
            },
        },
        "raw_abuseipdb": {
            "ipAddress": ip,
            "abuseConfidenceScore": profile["abuseipdb_score"],
            "totalReports": profile["total_reports"],
            "countryCode": profile["country"],
            "usageType": profile["usage_type"],
            "isp": profile["isp"],
            "domain": profile["domain"],
            "lastReportedAt": profile["last_reported_at"],
        },
        "raw_virustotal": {
            "last_analysis_stats": {
                "malicious": profile["vt_malicious"],
                "suspicious": profile["vt_suspicious"],
                "harmless": profile["vt_harmless"],
                "undetected": profile["vt_undetected"],
            },
            "reputation": profile["vt_reputation"],
            "country": profile["country"],
            "as_owner": profile["as_owner"],
            "network": profile["network"],
        },
        "first_seen_at": now - timedelta(days=10),
        "last_seen_at": now - timedelta(hours=2),
        "last_checked_at": now - timedelta(minutes=25),
        "expires_at": now + timedelta(hours=12 if verdict == "malicious" else 48),
        "error_message": None,
    }


def _match_terms(query: str, event: dict) -> bool:
    q = query.lower()
    blob = " ".join(
        str(part or "")
        for part in [
            event.get("scenario"),
            event.get("source_system"),
            event.get("sourcetype"),
            event.get("signature"),
            event.get("message"),
            event.get("path"),
            event.get("user"),
            event.get("host"),
            event.get("source_ip"),
            event.get("destination_ip"),
            event.get("saved_search_name"),
            event.get("raw"),
        ]
    ).lower()
    strong_terms = [
        "powershell", "sql", "sqlmap", "union select", "or 1=1", "nmap", "scan",
        "mfa", "credential", "vpn", "exfil", "archive", "defender", "tamper",
        "admin", "upload", "reverse proxy", "malicious", "rdp", "session",
    ]
    active_terms = [term for term in strong_terms if term in q]
    if active_terms:
        return any(term in blob for term in active_terms)
    if not q.strip() or q.strip() == "search index=*":
        return True
    return any(token in blob for token in q.replace("|", " ").split() if len(token) > 3)


def _exact_match(query: str, event: dict) -> bool:
    checks = [
        ('source_ip="', event.get("source_ip")),
        ('src_ip="', event.get("source_ip")),
        ('src="', event.get("source_ip")),
        ('clientip="', event.get("source_ip")),
        ('destination_ip="', event.get("destination_ip")),
        ('dest_ip="', event.get("destination_ip")),
        ('dest="', event.get("destination_ip")),
        ('dst="', event.get("destination_ip")),
        ('user="', event.get("user")),
        ('username="', event.get("user")),
        ('email="', event.get("user")),
        ('host="', event.get("host")),
        ('hostname="', event.get("host")),
        ('sourcetype="', event.get("sourcetype")),
        ('index=', event.get("index")),
    ]
    q = query.lower()
    for marker, value in checks:
        if marker in q and value:
            needle = str(value).lower()
            if marker.endswith('"'):
                probe = f'{marker}{needle}"'
                if probe not in q:
                    return False
            elif marker == "index=":
                if f"index={needle.lower()}" not in q and "index=*" not in q:
                    return False
    return True


def _event_in_time_range(query: str, event: dict, now: datetime) -> bool:
    lower = query.lower()
    event_time = _dt(event["time"])
    earliest = now - timedelta(days=30)
    latest = now + timedelta(minutes=5)
    if "earliest=-24h" in lower:
        earliest = now - timedelta(hours=24)
    elif "earliest=-7d" in lower:
        earliest = now - timedelta(days=7)
    elif "earliest=-4h" in lower:
        earliest = now - timedelta(hours=4)
    elif "earliest=-1h" in lower:
        earliest = now - timedelta(hours=1)
    elif "earliest=-15m" in lower:
        earliest = now - timedelta(minutes=15)
    return earliest <= event_time <= latest


def _extract_limit(query: str, default: int = 100) -> int:
    parts = query.lower().split("|")
    for part in reversed(parts):
        part = part.strip()
        if part.startswith("head "):
            try:
                return max(1, min(1000, int(part.split()[1])))
            except Exception:
                return default
    return default


def _normalize_search_events(events: list[dict], query: str, now: datetime) -> list[dict]:
    matches = []
    for event in events:
        if not _event_in_time_range(query, event, now):
            continue
        if not _exact_match(query, event):
            continue
        if not _match_terms(query, event):
            continue
        matches.append(event)
    matches.sort(key=lambda item: item["time"], reverse=True)
    return matches[: _extract_limit(query)]


def _dashboard_counts(scenarios: list[dict], saved_searches: list[dict], events: list[dict], now: datetime) -> dict:
    response_actions = sum(len(scenario["response_actions"]) for scenario in scenarios)
    open_rows = [scenario for scenario in scenarios if scenario["status"] not in {"closed", "false_positive", "resolved"}]
    return {
        "total_incidents": len(scenarios),
        "open_incidents": len(open_rows),
        "alerts_today": len([scenario for scenario in scenarios if scenario["alert_time"] >= now - timedelta(days=1)]),
        "events_ingested": len(events),
        "assets_monitored": len(DEMO_ASSETS),
        "response_actions": response_actions,
        "reports_generated": len([item for item in saved_searches if item["type"] == "report"]),
    }


@lru_cache(maxsize=1)
def demo_catalog() -> dict:
    now = _now()
    scenarios, scenario_events = _build_scenarios(now)
    background_events = _background_events(now)
    all_events = sorted(scenario_events + background_events, key=lambda item: item["time"], reverse=True)
    saved_searches = _saved_search_items(now, scenarios)
    fired_alerts = _fired_alerts(scenarios)
    reputation_ips = (
        {scenario["source_ip"] for scenario in scenarios if "." in scenario["source_ip"]}
        | set(DEMO_IP_REPUTATION.keys())
        | set(DEMO_PUBLIC_IP_POOL)
    )
    reputation_rows = {ip: _reputation_row(ip, now) for ip in sorted(reputation_ips)}
    blocked_ips = {
        action["target"]
        for scenario in scenarios
        for action in scenario["response_actions"]
        if action["action_type"] == "block_ip" and action["status"] == "executed"
    }
    return {
        "meta": {
            **demo_banner_meta(),
            "generated_at": _iso(now),
            "status_summary": _dashboard_counts(scenarios, saved_searches, all_events, now),
        },
        "users": DEMO_USERS,
        "assets": DEMO_ASSETS,
        "scenarios": scenarios,
        "events": all_events,
        "saved_searches": saved_searches,
        "fired_alerts": fired_alerts,
        "reputation": reputation_rows,
        "blocked_ips": sorted(blocked_ips),
    }


_DEMO_PFSENSE_BLOCKLIST: set[str] | None = None


def demo_blocked_ips() -> set[str]:
    global _DEMO_PFSENSE_BLOCKLIST
    if _DEMO_PFSENSE_BLOCKLIST is None:
        _DEMO_PFSENSE_BLOCKLIST = set(demo_catalog()["blocked_ips"])
    return _DEMO_PFSENSE_BLOCKLIST


def demo_splunk_connection() -> dict:
    return {
        "connected": True,
        "error": None,
        "version": "Splunk Enterprise 9.2.1 (demo)",
        "rest_connected": True,
        "search_connected": True,
        "hec_connected": True,
        "hec_error": None,
        "saved_searches_accessible": True,
        "saved_searches_error": None,
        "alerts_accessible": True,
        "alerts_error": None,
        "search_warning": None,
        "search_query": "search index=* | head 1",
        "demo_mode": True,
    }


def demo_pfsense_connection() -> dict:
    return {
        "success": True,
        "status": "connected",
        "message": "Simulated pfSense connection successful",
        "connected": True,
        "error": None,
        "version": "pfSense CE 2.7.2 (demo)",
        "demo_mode": True,
    }


def demo_saved_searches() -> dict:
    items = demo_catalog()["saved_searches"]
    return {"items": items, "error": None, "count": len(items), "demo_mode": True}


def demo_fired_alerts() -> dict:
    items = demo_catalog()["fired_alerts"]
    return {"items": items, "error": None, "count": len(items), "demo_mode": True}


def demo_export_search(query: str) -> dict:
    catalog = demo_catalog()
    now = _dt(catalog["meta"]["generated_at"])
    events = _normalize_search_events(catalog["events"], query, now)
    return {"events": events, "status_code": 200, "error": None, "demo_mode": True}


def demo_abuseipdb_check(ip_address: str) -> dict:
    profile = _public_profile(ip_address)
    return {
        "success": True,
        "provider": "abuseipdb",
        "ip_address": ip_address,
        "abuseConfidenceScore": profile["abuseipdb_score"],
        "totalReports": profile["total_reports"],
        "countryCode": profile["country"],
        "usageType": profile["usage_type"],
        "isp": profile["isp"],
        "domain": profile["domain"],
        "lastReportedAt": profile["last_reported_at"],
        "raw": demo_catalog()["reputation"].get(ip_address, {}).get("raw_abuseipdb") or {},
    }


def demo_virustotal_check(ip_address: str) -> dict:
    profile = _public_profile(ip_address)
    return {
        "success": True,
        "provider": "virustotal",
        "ip_address": ip_address,
        "last_analysis_stats": {
            "malicious": profile["vt_malicious"],
            "suspicious": profile["vt_suspicious"],
            "harmless": profile["vt_harmless"],
            "undetected": profile["vt_undetected"],
        },
        "reputation": profile["vt_reputation"],
        "country": profile["country"],
        "as_owner": profile["as_owner"],
        "network": profile["network"],
        "raw": demo_catalog()["reputation"].get(ip_address, {}).get("raw_virustotal") or {},
    }


def demo_provider_status() -> dict:
    return {
        "success": True,
        "enabled": True,
        "abuseipdb": {"configured": True, "connected": True, "error": None, "mode": "simulated"},
        "virustotal": {"configured": True, "connected": True, "error": None, "mode": "simulated"},
        "full_reputation_available": True,
        "demo_mode": True,
        "error": None,
    }


def demo_schema_field(key: str, real_value: str, is_sensitive: bool) -> dict:
    value = real_value or demo_value_for_key(key) or ""
    return {
        "value": "" if is_sensitive else str(value),
        "is_set": bool(value),
        "encrypted": False,
        "sensitive": is_sensitive,
        "demo_value": demo_value_for_key(key),
        "demo_mode": True,
    }


def demo_health_snapshot() -> dict:
    catalog = demo_catalog()
    return {
        **demo_banner_meta(),
        "simulated_integrations": ["splunk", "pfSense", "AbuseIPDB", "VirusTotal"],
        "status_summary": catalog["meta"]["status_summary"],
    }


def incident_demo_payload(incident_id: str) -> dict | None:
    for scenario in demo_catalog()["scenarios"]:
        if scenario["id"] == incident_id:
            return scenario
    return None
