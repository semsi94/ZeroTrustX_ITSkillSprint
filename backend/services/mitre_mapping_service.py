from __future__ import annotations

import json
import logging
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import UUID

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)

ENTERPRISE_ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

TACTICS = [
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
]

FALLBACK_TACTIC_IDS = [tactic_id for tactic_id, _, _ in TACTICS]
FALLBACK_TACTIC_ORDER = {tactic_id: index for index, (tactic_id, _, _) in enumerate(TACTICS, start=1)}


TECHNIQUE_FALLBACKS = [
    ("T1110", None, "Brute Force", "TA0006", False),
    ("T1110", "T1110.003", "Password Spraying", "TA0006", True),
    ("T1110", "T1110.004", "Credential Stuffing", "TA0006", True),
    ("T1078", None, "Valid Accounts", "TA0001", False),
    ("T1190", None, "Exploit Public-Facing Application", "TA0001", False),
    ("T1046", None, "Network Service Discovery", "TA0007", False),
    ("T1083", None, "File and Directory Discovery", "TA0007", False),
    ("T1082", None, "System Information Discovery", "TA0007", False),
    ("T1087", None, "Account Discovery", "TA0007", False),
    ("T1059", None, "Command and Scripting Interpreter", "TA0002", False),
    ("T1059", "T1059.001", "PowerShell", "TA0002", True),
    ("T1059", "T1059.003", "Windows Command Shell", "TA0002", True),
    ("T1053", None, "Scheduled Task/Job", "TA0003", False),
    ("T1547", "T1547.001", "Registry Run Keys / Startup Folder", "TA0003", True),
    ("T1041", None, "Exfiltration Over C2 Channel", "TA0010", False),
    ("T1567", None, "Exfiltration Over Web Service", "TA0010", False),
    ("T1027", None, "Obfuscated Files or Information", "TA0005", False),
    ("T1562", None, "Impair Defenses", "TA0005", False),
    ("T1113", None, "Screen Capture", "TA0009", False),
    ("T1115", None, "Clipboard Data", "TA0009", False),
    ("T1560", None, "Archive Collected Data", "TA0009", False),
    ("T1621", None, "Multi-Factor Authentication Request Generation", "TA0006", False),
]


@dataclass(frozen=True)
class Rule:
    technique_id: str
    technique_name: str
    tactic_id: str
    tactic_name: str
    subtechnique_id: Optional[str] = None
    subtechnique_name: Optional[str] = None
    alert_terms: tuple[str, ...] = ()
    spl_terms: tuple[str, ...] = ()
    field_terms: tuple[str, ...] = ()
    evidence_terms: tuple[str, ...] = ()
    observable_terms: tuple[str, ...] = ()
    reason_template: str = ""


RULES = [
    Rule("T1110", "Brute Force", "TA0006", "Credential Access", alert_terms=("brute force", "failed login", "login failure", "authentication failure"), field_terms=("login_failure", "failed", "failure", "401"), evidence_terms=("failed login", "invalid password", "authentication failed", "401"), reason_template="Repeated authentication failure indicators suggest brute-force credential access."),
    Rule("T1110", "Brute Force", "TA0006", "Credential Access", "T1110.003", "Password Spraying", alert_terms=("password spray", "spraying"), spl_terms=("dc(user)", "distinct user", "user_count"), evidence_terms=("password spray", "many users", "multiple users"), reason_template="Authentication pattern indicates one source attempting credentials across many users."),
    Rule("T1110", "Brute Force", "TA0006", "Credential Access", "T1110.004", "Credential Stuffing", alert_terms=("credential stuffing",), evidence_terms=("credential stuffing", "known leaked", "breached password"), reason_template="Credential stuffing terms were matched in detection context or evidence."),
    Rule("T1078", "Valid Accounts", "TA0001", "Initial Access", alert_terms=("valid login after failures", "valid credentials", "successful login after"), field_terms=("success", "allowed", "login_success"), evidence_terms=("successful login", "logged in", "accepted password"), reason_template="Successful authentication after suspicious activity suggests valid account use."),
    Rule("T1190", "Exploit Public-Facing Application", "TA0001", "Initial Access", alert_terms=("sql injection", "sqli", "xss", "directory traversal", "path traversal", "web exploit"), spl_terms=("sqlmap", "union select", "../", "<script"), evidence_terms=("sqlmap", "union select", "' or 1=1", "<script", "../", "etc/passwd", "path traversal"), reason_template="Web exploitation patterns were found in alert/SPL/evidence content."),
    Rule("T1046", "Network Service Discovery", "TA0007", "Discovery", alert_terms=("port scan", "network scan", "nmap", "scan-like"), field_terms=("blocked", "denied", "scan"), evidence_terms=("nmap", "port scan", "network scan", "syn scan", "blocked", "denied"), reason_template="Network scan or denied traffic pattern suggests service discovery."),
    Rule("T1083", "File and Directory Discovery", "TA0007", "Discovery", alert_terms=("file discovery", "directory discovery"), evidence_terms=("dir ", "ls ", "find ", "get-childitem", "directory listing"), reason_template="File or directory enumeration indicators were observed."),
    Rule("T1082", "System Information Discovery", "TA0007", "Discovery", alert_terms=("system info", "system information"), evidence_terms=("systeminfo", "whoami", "hostname", "uname -a"), reason_template="System information discovery commands were observed."),
    Rule("T1087", "Account Discovery", "TA0007", "Discovery", alert_terms=("account discovery", "user enumeration"), evidence_terms=("net user", "whoami /groups", "id ", "get-aduser"), reason_template="Account enumeration indicators were observed."),
    Rule("T1059", "Command and Scripting Interpreter", "TA0002", "Execution", alert_terms=("command execution", "script execution"), evidence_terms=("cmd.exe", "/bin/sh", "bash -c", "wscript", "cscript"), reason_template="Command or script execution indicators were observed."),
    Rule("T1059", "Command and Scripting Interpreter", "TA0002", "Execution", "T1059.001", "PowerShell", alert_terms=("powershell", "pwsh"), evidence_terms=("powershell", "pwsh", "encodedcommand", "-nop", "invoke-expression"), reason_template="PowerShell command execution indicators were observed."),
    Rule("T1059", "Command and Scripting Interpreter", "TA0002", "Execution", "T1059.003", "Windows Command Shell", alert_terms=("cmd.exe", "command shell"), evidence_terms=("cmd.exe", "cmd /c", "command.com"), reason_template="Windows command shell execution indicators were observed."),
    Rule("T1053", "Scheduled Task/Job", "TA0003", "Persistence", alert_terms=("scheduled task", "cron job"), evidence_terms=("schtasks", "at.exe", "crontab", "systemd timer"), reason_template="Scheduled task/job persistence indicators were observed."),
    Rule("T1547", "Boot or Logon Autostart Execution", "TA0003", "Persistence", "T1547.001", "Registry Run Keys / Startup Folder", alert_terms=("run key", "registry persistence"), evidence_terms=("currentversion\\run", "runonce", "startup folder"), reason_template="Registry run key or startup folder persistence indicators were observed."),
    Rule("T1041", "Exfiltration Over C2 Channel", "TA0010", "Exfiltration", alert_terms=("exfiltration", "data exfil", "large outbound"), evidence_terms=("exfil", "large upload", "large outbound", "bytes_out"), reason_template="Large outbound transfer or exfiltration terms were observed."),
    Rule("T1567", "Exfiltration Over Web Service", "TA0010", "Exfiltration", alert_terms=("cloud upload", "suspicious upload"), evidence_terms=("dropbox", "onedrive", "google drive", "s3 upload", "mega.nz"), reason_template="Suspicious upload to a web/cloud service was observed."),
    Rule("T1027", "Obfuscated Files or Information", "TA0005", "Defense Evasion", alert_terms=("obfuscated", "encoded command"), evidence_terms=("encodedcommand", "base64", "frombase64string", "obfuscated"), reason_template="Obfuscation or encoded command indicators were observed."),
    Rule("T1562", "Impair Defenses", "TA0005", "Defense Evasion", alert_terms=("disable security", "defender disabled"), evidence_terms=("set-mppreference", "disableantispyware", "stop-service windefend", "impair defenses"), reason_template="Security tool impairment indicators were observed."),
    Rule("T1113", "Screen Capture", "TA0009", "Collection", alert_terms=("screen capture", "screenshot"), evidence_terms=("screenshot", "screen capture", "bitblt"), reason_template="Screen capture indicators were observed."),
    Rule("T1115", "Clipboard Data", "TA0009", "Collection", alert_terms=("clipboard",), evidence_terms=("clipboard", "get-clipboard", "clip.exe"), reason_template="Clipboard data collection indicators were observed."),
    Rule("T1560", "Archive Collected Data", "TA0009", "Collection", alert_terms=("archive collected", "zip staging"), evidence_terms=("zip ", "rar ", "7z ", "tar ", "compress-archive"), reason_template="Archive/staging behavior for collected data was observed."),
]


@dataclass
class Candidate:
    rule: Rule
    score: int = 0
    matched_fields: dict[str, list[str]] = field(default_factory=dict)
    matched_evidence_ids: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)

    def add(self, source: str, points: int, value: str, evidence_id: Optional[str] = None) -> None:
        self.score += points
        self.matched_fields.setdefault(source, [])
        if value not in self.matched_fields[source]:
            self.matched_fields[source].append(value[:500])
        if evidence_id:
            self.matched_evidence_ids.add(evidence_id)


def _text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, default=str)
    return str(value)


def _contains_any(text_value: str, terms: tuple[str, ...]) -> list[str]:
    lower = text_value.lower()
    return [term for term in terms if term and term.lower() in lower]


def _mapping_id(rule: Rule) -> str:
    return rule.subtechnique_id or rule.technique_id


def _fallback_description(technique_id: str, name: str) -> str:
    return f"Fallback local ATT&CK entry for {technique_id} {name}. Run MITRE sync to load official descriptions."


async def seed_minimal_attack_data(db: AsyncSession) -> None:
    for order, (tactic_id, short_name, name) in enumerate(TACTICS, start=1):
        await db.execute(text("""
            INSERT INTO mitre_tactics (tactic_id, short_name, name, attack_url, matrix_order)
            VALUES (:tactic_id, :short_name, :name, :url, :matrix_order)
            ON CONFLICT (tactic_id) DO UPDATE
            SET short_name = EXCLUDED.short_name,
                name = EXCLUDED.name,
                attack_url = EXCLUDED.attack_url,
                matrix_order = COALESCE(mitre_tactics.matrix_order, EXCLUDED.matrix_order)
        """), {
            "tactic_id": tactic_id,
            "short_name": short_name,
            "name": name,
            "url": f"https://attack.mitre.org/tactics/{tactic_id}/",
            "matrix_order": order,
        })
    for technique_id, subtechnique_id, name, tactic_id, is_sub in TECHNIQUE_FALLBACKS:
        await db.execute(text("""
            INSERT INTO mitre_techniques (
                technique_id, subtechnique_id, name, description, tactic_id,
                tactic_refs, platforms, data_sources, detection, mitigation_refs,
                attack_url, is_subtechnique, parent_technique_id, revoked, deprecated
            )
            VALUES (
                :technique_id, :subtechnique_id, :name, :description, :tactic_id,
                :tactic_refs, :platforms, :data_sources, :detection, :mitigation_refs,
                :attack_url, :is_subtechnique, :parent_technique_id, FALSE, FALSE
            )
            ON CONFLICT (technique_id, COALESCE(subtechnique_id, ''), COALESCE(tactic_id, '')) DO UPDATE
            SET name = EXCLUDED.name,
                description = EXCLUDED.description,
                tactic_refs = EXCLUDED.tactic_refs,
                attack_url = EXCLUDED.attack_url,
                is_subtechnique = EXCLUDED.is_subtechnique,
                parent_technique_id = EXCLUDED.parent_technique_id,
                revoked = FALSE,
                deprecated = FALSE
        """).bindparams(
            bindparam("tactic_refs", type_=JSONB),
            bindparam("platforms", type_=JSONB),
            bindparam("data_sources", type_=JSONB),
            bindparam("mitigation_refs", type_=JSONB),
        ), {
            "technique_id": technique_id,
            "subtechnique_id": subtechnique_id,
            "name": name,
            "description": _fallback_description(subtechnique_id or technique_id, name),
            "tactic_id": tactic_id,
            "tactic_refs": [tactic_id],
            "platforms": [],
            "data_sources": [],
            "detection": "",
            "mitigation_refs": [],
            "attack_url": f"https://attack.mitre.org/techniques/{(subtechnique_id or technique_id).replace('.', '/')}/",
            "is_subtechnique": is_sub,
            "parent_technique_id": technique_id if is_sub else None,
        })
        await db.execute(text("""
            INSERT INTO mitre_technique_tactics (technique_id, subtechnique_id, tactic_id)
            VALUES (:technique_id, :subtechnique_id, :tactic_id)
            ON CONFLICT (technique_id, COALESCE(subtechnique_id, ''), tactic_id) DO NOTHING
        """), {
            "technique_id": technique_id,
            "subtechnique_id": subtechnique_id,
            "tactic_id": tactic_id,
        })


async def ensure_attack_data(db: AsyncSession) -> None:
    counts = (await db.execute(text("""
        SELECT
            (SELECT COUNT(*) FROM mitre_tactics) AS tactics,
            (SELECT COUNT(*) FROM mitre_techniques WHERE COALESCE(revoked, FALSE) = FALSE AND COALESCE(deprecated, FALSE) = FALSE) AS techniques
    """))).mappings().first()
    if not counts or int(counts.get("tactics") or 0) == 0 or int(counts.get("techniques") or 0) == 0:
        await seed_minimal_attack_data(db)


async def sync_attack_data(db: AsyncSession, url: str = ENTERPRISE_ATTACK_STIX_URL) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            bundle = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        await seed_minimal_attack_data(db)
        health = await mitre_health(db)
        await db.commit()
        return {
            "success": False,
            "synced": False,
            "source": url,
            "tactics": health["tactic_count"],
            "techniques": health["technique_count"],
            "subtechniques": health["subtechnique_count"],
            "error": f"MITRE ATT&CK data not synced from official source: {exc}",
        }

    objects = bundle.get("objects", [])
    id_to_attack_id: dict[str, str] = {}
    id_to_url: dict[str, str] = {}
    id_to_short_name: dict[str, str] = {}
    id_to_name: dict[str, str] = {}
    tactic_short_to_id = {short: tactic_id for tactic_id, short, _ in TACTICS}
    tactic_short_to_order = {short: order for order, (_, short, _) in enumerate(TACTICS, start=1)}

    for obj in objects:
        if obj.get("type") in {"x-mitre-tactic", "attack-pattern"}:
            external_refs = obj.get("external_references") or []
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    id_to_attack_id[obj.get("id")] = ref.get("external_id")
                    id_to_url[obj.get("id")] = ref.get("url")
                    id_to_name[obj.get("id")] = obj.get("name") or ref.get("external_id")
                    if obj.get("type") == "x-mitre-tactic":
                        short_name = obj.get("x_mitre_shortname") or obj.get("name", "").lower().replace(" ", "-")
                        id_to_short_name[obj.get("id")] = short_name
                        tactic_short_to_id[short_name] = ref.get("external_id")
                    break

    matrix_order: dict[str, int] = {}
    for obj in objects:
        if obj.get("type") != "x-mitre-matrix" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        matrix_name = str(obj.get("name") or "").lower()
        if "enterprise" not in matrix_name or ("attack" not in matrix_name and "att&ck" not in matrix_name):
            continue
        for order, tactic_ref in enumerate(obj.get("tactic_refs") or [], start=1):
            attack_id = id_to_attack_id.get(tactic_ref)
            if attack_id:
                matrix_order[attack_id] = order
                short_name = id_to_short_name.get(tactic_ref)
                if short_name:
                    tactic_short_to_order[short_name] = order

    parent_by_sub_id: dict[str, str] = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "subtechnique-of":
            sub_attack_id = id_to_attack_id.get(obj.get("source_ref"))
            parent_attack_id = id_to_attack_id.get(obj.get("target_ref"))
            if sub_attack_id and parent_attack_id:
                parent_by_sub_id[sub_attack_id] = parent_attack_id

    await db.execute(text("DELETE FROM mitre_technique_tactics"))
    await db.execute(text("DELETE FROM mitre_techniques"))
    tactic_count = 0
    technique_count = 0
    subtechnique_count = 0
    for obj in objects:
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        if obj.get("type") == "x-mitre-tactic":
            attack_id = id_to_attack_id.get(obj.get("id"))
            short_name = obj.get("x_mitre_shortname") or obj.get("name", "").lower().replace(" ", "-")
            if not attack_id:
                attack_id = tactic_short_to_id.get(short_name)
            if not attack_id:
                continue
            await db.execute(text("""
                INSERT INTO mitre_tactics (tactic_id, short_name, name, description, attack_url, matrix_order)
                VALUES (:tactic_id, :short_name, :name, :description, :attack_url, :matrix_order)
                ON CONFLICT (tactic_id) DO UPDATE
                SET short_name = EXCLUDED.short_name,
                    name = EXCLUDED.name,
                    description = EXCLUDED.description,
                    attack_url = EXCLUDED.attack_url,
                    matrix_order = EXCLUDED.matrix_order
            """), {
                "tactic_id": attack_id,
                "short_name": short_name,
                "name": obj.get("name") or short_name,
                "description": obj.get("description"),
                "attack_url": next((r.get("url") for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None),
                "matrix_order": matrix_order.get(attack_id) or tactic_short_to_order.get(short_name),
            })
            tactic_count += 1

    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
        if not external:
            continue
        external_id = external.get("external_id")
        is_sub = bool(obj.get("x_mitre_is_subtechnique"))
        technique_id = parent_by_sub_id.get(external_id) or (external_id.split(".")[0] if is_sub and "." in external_id else external_id)
        subtechnique_id = external_id if is_sub else None
        kill_chain = obj.get("kill_chain_phases") or []
        tactic_ids = [tactic_short_to_id.get(k.get("phase_name")) for k in kill_chain if k.get("kill_chain_name") == "mitre-attack"]
        tactic_ids = [tid for tid in tactic_ids if tid]
        if not tactic_ids:
            continue
        canonical_tactic = tactic_ids[0] if tactic_ids else None
        await db.execute(text("""
            INSERT INTO mitre_techniques (
                technique_id, subtechnique_id, name, description, tactic_id,
                tactic_refs, platforms, data_sources, detection, mitigation_refs,
                attack_url, is_subtechnique, parent_technique_id, revoked, deprecated
            )
            VALUES (
                :technique_id, :subtechnique_id, :name, :description, :tactic_id,
                :tactic_refs, :platforms, :data_sources, :detection, :mitigation_refs,
                :attack_url, :is_subtechnique, :parent_technique_id, FALSE, FALSE
            )
            ON CONFLICT (technique_id, COALESCE(subtechnique_id, ''), COALESCE(tactic_id, '')) DO UPDATE
            SET name = EXCLUDED.name,
                description = EXCLUDED.description,
                tactic_refs = EXCLUDED.tactic_refs,
                platforms = EXCLUDED.platforms,
                data_sources = EXCLUDED.data_sources,
                detection = EXCLUDED.detection,
                mitigation_refs = EXCLUDED.mitigation_refs,
                attack_url = EXCLUDED.attack_url,
                is_subtechnique = EXCLUDED.is_subtechnique,
                parent_technique_id = EXCLUDED.parent_technique_id,
                revoked = FALSE,
                deprecated = FALSE
        """).bindparams(
            bindparam("tactic_refs", type_=JSONB),
            bindparam("platforms", type_=JSONB),
            bindparam("data_sources", type_=JSONB),
            bindparam("mitigation_refs", type_=JSONB),
        ), {
            "technique_id": technique_id,
            "subtechnique_id": subtechnique_id,
            "name": obj.get("name") or external_id,
            "description": obj.get("description"),
            "tactic_id": canonical_tactic,
            "tactic_refs": tactic_ids,
            "platforms": obj.get("x_mitre_platforms") or [],
            "data_sources": obj.get("x_mitre_data_sources") or [],
            "detection": obj.get("x_mitre_detection"),
            "mitigation_refs": [],
            "attack_url": external.get("url"),
            "is_subtechnique": is_sub,
            "parent_technique_id": technique_id if is_sub else None,
        })
        for tactic_id in tactic_ids:
            await db.execute(text("""
                INSERT INTO mitre_technique_tactics (technique_id, subtechnique_id, tactic_id)
                VALUES (:technique_id, :subtechnique_id, :tactic_id)
                ON CONFLICT (technique_id, COALESCE(subtechnique_id, ''), tactic_id) DO NOTHING
            """), {
                "technique_id": technique_id,
                "subtechnique_id": subtechnique_id,
                "tactic_id": tactic_id,
            })
        if is_sub:
            subtechnique_count += 1
        else:
            technique_count += 1
    issues = []
    if tactic_count < 14:
        issues.append("MITRE tactic count is lower than expected for Enterprise ATT&CK.")
    if technique_count < 100:
        issues.append("MITRE technique count is suspiciously low. Re-sync may be required.")
    if subtechnique_count == 0:
        issues.append("No sub-techniques were loaded.")
    await db.execute(text("""
        INSERT INTO mitre_sync_state (domain, version, synced_at, source, technique_count, subtechnique_count, tactic_count, issues)
        VALUES ('enterprise-attack', :version, NOW(), :source, :technique_count, :subtechnique_count, :tactic_count, :issues)
        ON CONFLICT (domain) DO UPDATE
        SET version = EXCLUDED.version,
            synced_at = EXCLUDED.synced_at,
            source = EXCLUDED.source,
            technique_count = EXCLUDED.technique_count,
            subtechnique_count = EXCLUDED.subtechnique_count,
            tactic_count = EXCLUDED.tactic_count,
            issues = EXCLUDED.issues
    """).bindparams(bindparam("issues", type_=JSONB)), {
        "version": bundle.get("spec_version") or bundle.get("id"),
        "source": url,
        "technique_count": technique_count,
        "subtechnique_count": subtechnique_count,
        "tactic_count": tactic_count,
        "issues": issues,
    })
    await db.commit()
    return {
        "success": True,
        "synced": True,
        "source": url,
        "tactics": tactic_count,
        "techniques": technique_count,
        "subtechniques": subtechnique_count,
        "issues": issues,
        "error": None,
    }


async def _load_incident_context(db: AsyncSession, incident_id: UUID) -> dict:
    incident = (await db.execute(text("SELECT * FROM incidents WHERE id = :id"), {"id": str(incident_id)})).mappings().first()
    if not incident:
        raise ValueError("Incident not found")
    evidence = (await db.execute(text("""
        SELECT * FROM evidence WHERE incident_id = :id ORDER BY event_time ASC NULLS LAST, collected_at ASC
    """), {"id": str(incident_id)})).mappings().all()
    alerts = (await db.execute(text("""
        SELECT * FROM external_alerts WHERE linked_incident_id = :id ORDER BY ingested_at DESC
    """), {"id": str(incident_id)})).mappings().all()
    observables = (await db.execute(text("""
        SELECT * FROM observables WHERE incident_id = :id
    """), {"id": str(incident_id)})).mappings().all()
    return {"incident": dict(incident), "evidence": [dict(e) for e in evidence], "alerts": [dict(a) for a in alerts], "observables": [dict(o) for o in observables]}


async def analyze_incident_mitre(db: AsyncSession, incident_id: UUID, actor: Optional[dict] = None, persist: bool = True) -> dict:
    await ensure_attack_data(db)
    ctx = await _load_incident_context(db, incident_id)
    incident = ctx["incident"]
    evidence = ctx["evidence"]
    alerts = ctx["alerts"]
    observables = ctx["observables"]

    incident_text = " ".join(_text(incident.get(k)) for k in ("title", "description", "category", "source", "detection_source", "notes", "analyst_notes", "entities"))
    alert_text = " ".join(_text(a.get(k)) for a in alerts for k in ("rule_name", "source_event_id", "severity", "raw_json"))
    spl_text = " ".join(_text((a.get("raw_json") or {}).get(k)) for a in alerts for k in ("search", "query", "spl"))
    observable_text = " ".join(_text(o.get("value")) for o in observables)

    candidates = {(_mapping_id(rule), rule.tactic_id): Candidate(rule) for rule in RULES}
    for rule in RULES:
        candidate = candidates[(_mapping_id(rule), rule.tactic_id)]
        for term in _contains_any(alert_text + " " + incident_text, rule.alert_terms):
            candidate.add("alert_or_rule", 40, term)
        for term in _contains_any(spl_text, rule.spl_terms or rule.evidence_terms):
            candidate.add("spl_query", 20, term)
        for term in _contains_any(observable_text, rule.observable_terms):
            candidate.add("observables", 10, term)
        for ev in evidence:
            raw = ev.get("raw_event") or ev.get("raw_data") or {}
            field_text = " ".join(_text(ev.get(k)) for k in ("action", "message", "sourcetype", "index", "source", "source_system", "host", "source_ip", "destination_ip"))
            field_text = f"{field_text} {_text(raw)}"
            matched_field_terms = _contains_any(field_text, rule.field_terms)
            matched_evidence_terms = _contains_any(field_text, rule.evidence_terms)
            for term in matched_field_terms:
                candidate.add("event_fields", 25, term, str(ev.get("id")))
            for term in matched_evidence_terms:
                candidate.add("evidence", 30, term, str(ev.get("id")))
        if len(candidate.matched_evidence_ids) > 1:
            candidate.add("evidence_volume", 10, f"{len(candidate.matched_evidence_ids)} evidence events")
        if candidate.score > 0:
            candidate.reasons.append(rule.reason_template or f"Matched ATT&CK rule for {rule.technique_id}.")
            if candidate.score <= 40 and _contains_any(incident_text, rule.alert_terms):
                candidate.score = min(candidate.score, 50)

    mappings = []
    for candidate in candidates.values():
        if candidate.score <= 0:
            continue
        rule = candidate.rule
        confidence = max(35, min(95, candidate.score))
        mappings.append({
            "tactic_id": rule.tactic_id,
            "tactic_name": rule.tactic_name,
            "technique_id": rule.technique_id,
            "technique_name": rule.technique_name,
            "subtechnique_id": rule.subtechnique_id,
            "subtechnique_name": rule.subtechnique_name,
            "confidence_score": confidence,
            "mapping_source": "auto",
            "reason": " ".join(candidate.reasons),
            "matched_fields": candidate.matched_fields,
            "matched_evidence_ids": sorted(candidate.matched_evidence_ids),
        })
    mappings.sort(key=lambda item: item["confidence_score"], reverse=True)

    if persist:
        await db.execute(text("""
            DELETE FROM incident_mitre_links
            WHERE incident_id = :incident_id
              AND COALESCE(mapping_source, 'manual') = 'auto'
        """), {"incident_id": str(incident_id)})
        for mapping in mappings:
            technique_key = mapping["subtechnique_id"] or mapping["technique_id"]
            await db.execute(text("""
                INSERT INTO incident_mitre_links (
                    incident_id, tactic_id, technique_id, subtechnique_id,
                    technique_name, confidence, confidence_score, mapped_by,
                    mapping_source, reason, matched_fields, matched_evidence_ids,
                    created_by, updated_at
                )
                VALUES (
                    :incident_id, :tactic_id, :technique_id, :subtechnique_id,
                    :technique_name, :confidence, :confidence_score, :mapped_by,
                    'auto', :reason, :matched_fields, :matched_evidence_ids,
                    :created_by, NOW()
                )
                ON CONFLICT (incident_id, technique_id, COALESCE(subtechnique_id, ''), COALESCE(tactic_id, '')) DO UPDATE
                SET tactic_id = EXCLUDED.tactic_id,
                    subtechnique_id = EXCLUDED.subtechnique_id,
                    technique_name = EXCLUDED.technique_name,
                    confidence = EXCLUDED.confidence,
                    confidence_score = EXCLUDED.confidence_score,
                    mapped_by = EXCLUDED.mapped_by,
                    mapping_source = CASE WHEN incident_mitre_links.mapping_source = 'analyst' THEN incident_mitre_links.mapping_source ELSE 'auto' END,
                    reason = EXCLUDED.reason,
                    matched_fields = EXCLUDED.matched_fields,
                    matched_evidence_ids = EXCLUDED.matched_evidence_ids,
                    updated_at = NOW()
            """).bindparams(
                bindparam("matched_fields", type_=JSONB),
                bindparam("matched_evidence_ids", type_=JSONB),
            ), {
                "incident_id": str(incident_id),
                "tactic_id": mapping["tactic_id"],
                "technique_id": mapping["technique_id"],
                "subtechnique_id": mapping["subtechnique_id"],
                "technique_name": mapping["subtechnique_name"] or mapping["technique_name"],
                "confidence": mapping["confidence_score"] / 100,
                "confidence_score": mapping["confidence_score"],
                "mapped_by": "mitre_analyzer",
                "reason": mapping["reason"],
                "matched_fields": mapping["matched_fields"],
                "matched_evidence_ids": mapping["matched_evidence_ids"],
                "created_by": (actor or {}).get("username") or "system",
            })
            for evidence_id in mapping["matched_evidence_ids"]:
                await db.execute(text("""
                    INSERT INTO evidence_mitre_links (evidence_id, tactic_id, technique_id, subtechnique_id, confidence_score, reason)
                    VALUES (:evidence_id, :tactic_id, :technique_id, :subtechnique_id, :confidence_score, :reason)
                    ON CONFLICT (evidence_id, technique_id, COALESCE(subtechnique_id, '')) DO UPDATE
                    SET confidence_score = EXCLUDED.confidence_score,
                        reason = EXCLUDED.reason
                """), {
                    "evidence_id": evidence_id,
                    "tactic_id": mapping["tactic_id"],
                    "technique_id": mapping["technique_id"],
                    "subtechnique_id": mapping["subtechnique_id"],
                    "confidence_score": mapping["confidence_score"],
                    "reason": mapping["reason"],
                })
        if mappings:
            top = mappings[0]
            await db.execute(text("""
                UPDATE incidents
                SET mitre_tactic = :tactic,
                    mitre_technique = :technique_id,
                    mitre_technique_id = :technique_id,
                    mitre_technique_name = :technique_name,
                    mitre_confidence = :confidence,
                    mitre_mapping_source = 'auto',
                    updated_at = NOW()
                WHERE id = :incident_id
            """), {
                "incident_id": str(incident_id),
                "tactic": top["tactic_name"],
                "technique_id": top["subtechnique_id"] or top["technique_id"],
                "technique_name": top["subtechnique_name"] or top["technique_name"],
                "confidence": top["confidence_score"] / 100,
            })
        await db.execute(text("""
            INSERT INTO event_outbox (event_type, aggregate_type, aggregate_id, payload_json)
            VALUES ('mitre.analyzed', 'incident', :incident_id, :payload)
        """).bindparams(bindparam("payload", type_=JSONB)), {
            "incident_id": str(incident_id),
            "payload": {"mapping_count": len(mappings), "top": mappings[0] if mappings else None},
        })
        await db.commit()

    summary = mitre_summary(mappings)
    return {"success": True, "mappings": mappings, "summary": summary, "error": None}


def mitre_summary(mappings: list[dict]) -> dict:
    top_tactics: dict[str, int] = {}
    for mapping in mappings:
        tactic = mapping.get("tactic_name") or mapping.get("tactic_id") or "Unknown"
        top_tactics[tactic] = top_tactics.get(tactic, 0) + 1
    return {
        "mapped_count": len(mappings),
        "top_tactics": [{"name": k, "count": v} for k, v in sorted(top_tactics.items(), key=lambda item: item[1], reverse=True)],
        "highest_confidence": max([int(m.get("confidence_score") or 0) for m in mappings], default=0),
    }


async def incident_mitre_data(db: AsyncSession, incident_id: UUID) -> dict:
    rows = (await db.execute(text("""
        SELECT DISTINCT ON (l.id)
            l.*, t.name AS tactic_name, mt.description, mt.attack_url, mt.platforms, mt.data_sources, mt.detection
        FROM incident_mitre_links l
        LEFT JOIN mitre_tactics t ON t.tactic_id = l.tactic_id
        LEFT JOIN mitre_techniques mt
          ON mt.technique_id = l.technique_id
         AND COALESCE(mt.subtechnique_id, '') = COALESCE(l.subtechnique_id, '')
         AND (mt.tactic_id = l.tactic_id OR mt.tactic_id IS NULL)
        WHERE l.incident_id = :incident_id
        ORDER BY l.id,
            CASE WHEN mt.tactic_id = l.tactic_id THEN 0 ELSE 1 END,
            mt.attack_url NULLS LAST
    """), {"incident_id": str(incident_id)})).mappings().all()
    mappings = [mitre_link_to_dict(row) for row in rows]
    mappings.sort(key=lambda item: (int(item.get("confidence_score") or 0), item.get("created_at") or ""), reverse=True)
    return {"success": True, "mappings": mappings, "summary": mitre_summary(mappings), "error": None}


def mitre_link_to_dict(row) -> dict:
    confidence_score = row.get("confidence_score")
    if confidence_score is None and row.get("confidence") is not None:
        confidence_score = round(float(row.get("confidence")) * 100)
    return {
        "id": str(row["id"]),
        "incident_id": str(row["incident_id"]),
        "tactic_id": row.get("tactic_id"),
        "tactic_name": row.get("tactic_name"),
        "technique_id": row.get("technique_id"),
        "subtechnique_id": row.get("subtechnique_id"),
        "technique_name": row.get("technique_name"),
        "confidence_score": int(confidence_score or 0),
        "mapping_source": row.get("mapping_source") or "manual",
        "reason": row.get("reason") or "",
        "matched_fields": row.get("matched_fields") or {},
        "matched_evidence_ids": row.get("matched_evidence_ids") or [],
        "mapped_by": row.get("mapped_by") or row.get("created_by"),
        "created_at": row["created_at"].isoformat() if row.get("created_at") else None,
        "updated_at": row["updated_at"].isoformat() if row.get("updated_at") else None,
        "attack_url": row.get("attack_url") or f"https://attack.mitre.org/techniques/{str(row.get('subtechnique_id') or row.get('technique_id') or '').replace('.', '/')}/",
        "description": row.get("description"),
        "platforms": row.get("platforms") or [],
        "data_sources": row.get("data_sources") or [],
        "detection": row.get("detection"),
    }


async def matrix(db: AsyncSession) -> dict:
    await ensure_attack_data(db)
    tactic_rows = (await db.execute(text("""
        SELECT * FROM mitre_tactics
        WHERE matrix_order IS NOT NULL
        ORDER BY matrix_order, tactic_id
    """))).mappings().all()
    technique_rows = (await db.execute(text("""
        SELECT DISTINCT ON (rel.tactic_id, mt.technique_id, COALESCE(mt.subtechnique_id, ''))
            mt.*, rel.tactic_id AS matrix_tactic_id
        FROM mitre_techniques mt
        JOIN mitre_technique_tactics rel
          ON rel.technique_id = mt.technique_id
         AND COALESCE(rel.subtechnique_id, '') = COALESCE(mt.subtechnique_id, '')
        JOIN mitre_tactics tactic ON tactic.tactic_id = rel.tactic_id
        WHERE COALESCE(mt.revoked, FALSE) = FALSE
          AND COALESCE(mt.deprecated, FALSE) = FALSE
          AND tactic.matrix_order IS NOT NULL
        ORDER BY rel.tactic_id, mt.technique_id, COALESCE(mt.subtechnique_id, ''), mt.name
    """))).mappings().all()
    if not technique_rows:
        technique_rows = (await db.execute(text("""
            SELECT *, tactic_id AS matrix_tactic_id
            FROM mitre_techniques
            WHERE COALESCE(revoked, FALSE) = FALSE
              AND COALESCE(deprecated, FALSE) = FALSE
            ORDER BY tactic_id, technique_id, subtechnique_id NULLS FIRST, name
        """))).mappings().all()
    tactic_link_rows = (await db.execute(text("""
        SELECT
            rel.technique_id,
            rel.subtechnique_id,
            rel.tactic_id,
            t.name AS tactic_name,
            t.short_name,
            t.matrix_order
        FROM mitre_technique_tactics rel
        LEFT JOIN mitre_tactics t ON t.tactic_id = rel.tactic_id
        WHERE t.matrix_order IS NOT NULL
        ORDER BY COALESCE(t.matrix_order, 999), rel.tactic_id
    """))).mappings().all()
    tactic_links: dict[tuple[str, str], list[dict]] = {}
    for link in tactic_link_rows:
        key = (link.get("technique_id"), link.get("subtechnique_id") or "")
        tactic_links.setdefault(key, []).append({
            "tactic_id": link.get("tactic_id"),
            "name": link.get("tactic_name"),
            "short_name": link.get("short_name"),
            "matrix_order": link.get("matrix_order"),
        })
    by_tactic: dict[str, list[dict]] = {}
    for row in technique_rows:
        current_tactic_id = row.get("matrix_tactic_id") or row.get("tactic_id")
        appears = tactic_links.get((row.get("technique_id"), row.get("subtechnique_id") or "")) or []
        by_tactic.setdefault(row.get("matrix_tactic_id") or row.get("tactic_id") or "unknown", []).append({
            "id": str(row["id"]),
            "technique_id": row.get("technique_id"),
            "subtechnique_id": row.get("subtechnique_id"),
            "parent_technique_id": row.get("parent_technique_id"),
            "current_tactic_id": current_tactic_id,
            "appears_in_tactics": [item["tactic_id"] for item in appears if item.get("tactic_id")],
            "appears_in_tactics_details": appears,
            "name": row.get("name"),
            "description": row.get("description"),
            "attack_url": row.get("attack_url"),
            "is_subtechnique": bool(row.get("is_subtechnique")),
            "platforms": row.get("platforms") or [],
            "data_sources": row.get("data_sources") or [],
            "detection": row.get("detection"),
        })
    columns = []
    for tactic in tactic_rows:
        techniques = by_tactic.get(tactic.get("tactic_id"), [])
        if not techniques:
            continue
        columns.append({
            "tactic_id": tactic.get("tactic_id"),
            "short_name": tactic.get("short_name"),
            "name": tactic.get("name"),
            "description": tactic.get("description"),
            "attack_url": tactic.get("attack_url"),
            "matrix_order": tactic.get("matrix_order"),
            "technique_count": len(techniques),
            "techniques": techniques,
        })
    verification = await verify_enterprise_matrix_completeness(db)
    return {
        "success": True,
        "matrix": columns,
        "meta": {
            "domain": "enterprise-attack",
            "version": verification.get("version"),
            "source": verification.get("source"),
            "official_tactic_count": verification.get("official_tactic_count"),
            "rendered_tactic_count": len(columns),
            "stored_tactic_count": verification.get("stored_tactic_count"),
            "matrix_matches_official": verification.get("matrix_matches_official"),
        },
        "error": None,
    }


async def verify_enterprise_matrix_completeness(db: AsyncSession) -> dict:
    state = (await db.execute(text("""
        SELECT * FROM mitre_sync_state WHERE domain = 'enterprise-attack'
    """))).mappings().first()
    counts = (await db.execute(text("""
        SELECT
            (SELECT COUNT(*) FROM mitre_tactics) AS stored_tactic_count,
            (SELECT COUNT(*) FROM mitre_tactics WHERE matrix_order IS NOT NULL) AS official_tactic_count,
            (SELECT COUNT(DISTINCT technique_id) FROM mitre_techniques WHERE COALESCE(is_subtechnique, FALSE) = FALSE AND COALESCE(revoked, FALSE) = FALSE AND COALESCE(deprecated, FALSE) = FALSE) AS technique_count,
            (SELECT COUNT(DISTINCT subtechnique_id) FROM mitre_techniques WHERE COALESCE(is_subtechnique, FALSE) = TRUE AND subtechnique_id IS NOT NULL AND COALESCE(revoked, FALSE) = FALSE AND COALESCE(deprecated, FALSE) = FALSE) AS subtechnique_count,
            (SELECT COUNT(*) FROM mitre_technique_tactics) AS technique_tactic_links
    """))).mappings().first() or {}
    rendered_tactics = (await db.execute(text("""
        SELECT t.tactic_id, t.short_name, t.name, t.matrix_order, COUNT(rel.id) AS technique_count
        FROM mitre_tactics t
        LEFT JOIN mitre_technique_tactics rel ON rel.tactic_id = t.tactic_id
        WHERE t.matrix_order IS NOT NULL
        GROUP BY t.tactic_id, t.short_name, t.name, t.matrix_order
        ORDER BY t.matrix_order, t.tactic_id
    """))).mappings().all()
    excluded_tactics = (await db.execute(text("""
        SELECT tactic_id, short_name, name, matrix_order
        FROM mitre_tactics
        WHERE matrix_order IS NULL
        ORDER BY tactic_id
    """))).mappings().all()
    unlinked_techniques = int((await db.execute(text("""
        SELECT COUNT(*) AS count
        FROM mitre_techniques mt
        LEFT JOIN mitre_technique_tactics rel
          ON rel.technique_id = mt.technique_id
         AND COALESCE(rel.subtechnique_id, '') = COALESCE(mt.subtechnique_id, '')
        WHERE rel.id IS NULL
          AND COALESCE(mt.revoked, FALSE) = FALSE
          AND COALESCE(mt.deprecated, FALSE) = FALSE
    """))).scalar() or 0)
    duplicate_rows = int((await db.execute(text("""
        SELECT COUNT(*) FROM (
            SELECT technique_id, COALESCE(subtechnique_id, '') AS subtechnique_id, COUNT(*) AS row_count
            FROM mitre_techniques
            WHERE COALESCE(revoked, FALSE) = FALSE
              AND COALESCE(deprecated, FALSE) = FALSE
            GROUP BY technique_id, COALESCE(subtechnique_id, '')
            HAVING COUNT(*) > 1
        ) duplicates
    """))).scalar() or 0)

    tactic_ids = [row.get("tactic_id") for row in rendered_tactics]
    orders = [int(row.get("matrix_order") or 0) for row in rendered_tactics]
    empty_rendered_tactics = [
        {
            "tactic_id": row.get("tactic_id"),
            "name": row.get("name"),
            "matrix_order": row.get("matrix_order"),
        }
        for row in rendered_tactics
        if int(row.get("technique_count") or 0) == 0
    ]
    issues = list((state or {}).get("issues") or [])
    if not state:
        issues.append("MITRE ATT&CK data has not been synced yet.")
    if int(counts.get("official_tactic_count") or 0) == 0:
        issues.append("Enterprise matrix tactic order is missing. Re-sync official ATT&CK data.")
    if orders != sorted(orders):
        issues.append("Enterprise matrix tactic order is inconsistent.")
    if len(tactic_ids) != len(set(tactic_ids)):
        issues.append("Enterprise matrix contains duplicate tactic IDs.")
    if int(counts.get("technique_count") or 0) < 100:
        issues.append("MITRE technique count is suspiciously low. Re-sync required.")
    if int(counts.get("subtechnique_count") or 0) == 0:
        issues.append("MITRE sub-techniques are missing. Re-sync required.")
    if int(counts.get("technique_tactic_links") or 0) == 0 and int(counts.get("technique_count") or 0):
        issues.append("Technique-to-tactic matrix links are missing. Re-sync required.")
    if empty_rendered_tactics:
        preview = ", ".join(f"{row['name']} / {row['tactic_id']}" for row in empty_rendered_tactics[:5])
        issues.append(f"Enterprise matrix contains rendered tactic columns with zero linked techniques: {preview}.")
    if unlinked_techniques > 0:
        issues.append(f"{unlinked_techniques} techniques have no tactic links and will not render in the matrix.")
    if duplicate_rows > 0:
        issues.append(f"{duplicate_rows} techniques have duplicate database rows for the same ATT&CK ID.")

    matrix_matches_official = not issues
    return {
        "domain": "enterprise-attack",
        "version": (state or {}).get("version"),
        "source": (state or {}).get("source"),
        "last_synced_at": state["synced_at"].isoformat() if state and state.get("synced_at") else None,
        "stored_tactic_count": int(counts.get("stored_tactic_count") or 0),
        "official_tactic_count": int(counts.get("official_tactic_count") or 0),
        "rendered_tactic_count": len([row for row in rendered_tactics if int(row.get("technique_count") or 0) > 0]),
        "tactic_count": int(counts.get("stored_tactic_count") or 0),
        "technique_count": int(counts.get("technique_count") or 0),
        "subtechnique_count": int(counts.get("subtechnique_count") or 0),
        "technique_tactic_links": int(counts.get("technique_tactic_links") or 0),
        "techniques_without_tactic_links": unlinked_techniques,
        "duplicate_technique_rows": duplicate_rows,
        "empty_rendered_tactics": empty_rendered_tactics,
        "excluded_tactics": [dict(row) for row in excluded_tactics],
        "matrix_tactic_ids": tactic_ids,
        "matrix_matches_official": matrix_matches_official,
        "issues": sorted(set(str(issue) for issue in issues if issue)),
    }


async def mitre_health(db: AsyncSession) -> dict:
    try:
        verification = await verify_enterprise_matrix_completeness(db)
        issues = verification.get("issues") or []
        return {
            "success": True,
            "synced": bool(verification.get("last_synced_at")) and not issues,
            **verification,
            "error": None,
        }
    except Exception as exc:
        logger.exception("MITRE health check failed")
        return {
            "success": True,
            "domain": "enterprise-attack",
            "synced": False,
            "version": None,
            "source": None,
            "last_synced_at": None,
            "stored_tactic_count": 0,
            "official_tactic_count": 0,
            "rendered_tactic_count": 0,
            "tactic_count": 0,
            "technique_count": 0,
            "subtechnique_count": 0,
            "techniques_without_tactic_links": 0,
            "empty_rendered_tactics": [],
            "excluded_tactics": [],
            "matrix_matches_official": False,
            "issues": [f"MITRE health check failed: {exc}"],
            "error": None,
        }


async def navigator_layer(db: AsyncSession, incident_id: UUID) -> dict:
    data = await incident_mitre_data(db, incident_id)
    techniques = []
    for mapping in data["mappings"]:
        score = int(mapping.get("confidence_score") or 0)
        color = "#2ECC71" if score >= 80 else "#F2C94C" if score >= 50 else "#F2994A"
        if mapping.get("mapping_source") == "analyst":
            color = "#56CCF2"
        techniques.append({
            "techniqueID": mapping.get("subtechnique_id") or mapping.get("technique_id"),
            "score": score,
            "color": color,
            "comment": f"{mapping.get('reason') or ''} Evidence: {len(mapping.get('matched_evidence_ids') or [])}",
            "enabled": True,
        })
    return {
        "name": f"Incident {incident_id} MITRE Mapping",
        "versions": {"attack": "enterprise-attack", "navigator": "4.9.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "ZeroTrustX incident MITRE ATT&CK mapping export.",
        "techniques": techniques,
        "gradient": {"colors": ["#F2994A", "#F2C94C", "#2ECC71"], "minValue": 0, "maxValue": 100},
        "legendItems": [],
        "metadata": [{"name": "incident_id", "value": str(incident_id)}],
    }
