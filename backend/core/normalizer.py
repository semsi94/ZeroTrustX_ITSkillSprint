from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4


@dataclass
class NormalizedEvent:
    event_time: datetime
    source_system: str
    event_type: str
    src_ip: str
    dest_ip: str
    username: Optional[str]
    hostname: Optional[str]
    zone: str
    severity: int
    confidence: float
    cia_confidentiality: int
    cia_integrity: int
    cia_availability: int
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    signature: Optional[str]
    category: Optional[str]
    raw_ref: str
    raw_payload: dict


def _coerce_str(v) -> str:
    if v is None:
        return ""
    return str(v)


def normalize_splunk_payload(payload: dict) -> NormalizedEvent:
    """Normalize a Splunk-shaped webhook payload into a NormalizedEvent.

    Accepts either {"result": {...}} or a flat dict.
    """
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict")

    result = payload.get("result", payload)

    source_map = {
        "suricata": "suricata",
        "pfsense": "pfsense",
        "pan:traffic": "pfsense",
        "iis": "web",
        "apache": "web",
        "nginx": "web",
        "wineventlog": "windows",
        "xmlwineventlog": "windows",
    }
    raw_sourcetype = _coerce_str(result.get("sourcetype", "unknown")).lower()
    source_system = next((v for k, v in source_map.items() if k in raw_sourcetype), "unknown")

    severity_map = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
    }
    raw_severity = _coerce_str(result.get("severity", result.get("alert.severity", "medium"))).lower()
    severity = severity_map.get(raw_severity, 2)
    if isinstance(result.get("alert.severity"), int):
        suricata_map = {1: 5, 2: 4, 3: 3, 4: 2}
        severity = suricata_map.get(result["alert.severity"], 2)

    signature = (
        result.get("signature")
        or result.get("alert.signature")
        or result.get("alert_name")
        or payload.get("search_name")
        or result.get("message")
        or "Unknown event"
    )
    category = result.get("category") or result.get("alert.category") or ""

    sig_lower = _coerce_str(signature).lower() + " " + _coerce_str(category).lower()

    c_high = ["credential", "login", "auth", "exfil", "dump", "spray", "password", "secret", "token"]
    c_low = ["scan", "recon", "enum", "probe"]
    i_high = ["inject", "exploit", "tamper", "modify", "exec", "rce", "shell", "overflow", "traversal"]
    i_low = ["admin", "config", "change", "write"]
    a_high = ["flood", "ddos", "dos", "burst", "spike", "crash", "denial", "unavailable"]
    a_low = ["scan", "probe", "sweep", "ping", "brute"]

    cia_c = 2 if any(w in sig_lower for w in c_high) else 1 if any(w in sig_lower for w in c_low) else 0
    cia_i = 2 if any(w in sig_lower for w in i_high) else 1 if any(w in sig_lower for w in i_low) else 0
    cia_a = 2 if any(w in sig_lower for w in a_high) else 1 if any(w in sig_lower for w in a_low) else 0

    confidence_base = 0.4
    if source_system == "suricata":
        confidence_base += 0.2
    if cia_c + cia_i + cia_a >= 3:
        confidence_base += 0.15
    if severity >= 4:
        confidence_base += 0.1
    confidence = min(0.95, confidence_base)

    raw_time = result.get("_time", result.get("timestamp", ""))
    try:
        event_time = datetime.fromisoformat(_coerce_str(raw_time).replace("Z", "+00:00"))
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
    except Exception:
        event_time = datetime.now(timezone.utc)

    src_ip = _coerce_str(result.get("src_ip") or result.get("src") or result.get("source_ip") or "0.0.0.0")
    dest_ip = _coerce_str(result.get("dest_ip") or result.get("dest") or result.get("destination_ip") or result.get("host") or "0.0.0.0")

    host_str = _coerce_str(result.get("host", ""))
    zone = "dmz" if "dmz" in host_str.lower() else "unknown"

    return NormalizedEvent(
        event_time=event_time,
        source_system=source_system,
        event_type=_coerce_str(result.get("event_type", "alert")),
        src_ip=src_ip,
        dest_ip=dest_ip,
        username=result.get("user") or result.get("username"),
        hostname=result.get("host") or result.get("hostname"),
        zone=zone,
        severity=severity,
        confidence=confidence,
        cia_confidentiality=cia_c,
        cia_integrity=cia_i,
        cia_availability=cia_a,
        mitre_tactic=result.get("mitre_tactic"),
        mitre_technique=result.get("mitre_technique"),
        signature=_coerce_str(signature),
        category=_coerce_str(category) or None,
        raw_ref=_coerce_str(result.get("_cd") or result.get("event_id") or str(uuid4())),
        raw_payload=payload,
    )
