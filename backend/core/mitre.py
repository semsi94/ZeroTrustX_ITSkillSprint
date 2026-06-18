from __future__ import annotations


MITRE_RULES = [
    (("password spray", "spraying"), ("Credential Access", "T1110.003", "Password Spraying", 0.86)),
    (("brute force", "bruteforce", "failed login", "login failure", "401"), ("Credential Access", "T1110", "Brute Force", 0.82)),
    (("mfa fatigue", "push fatigue"), ("Credential Access", "T1621", "Multi-Factor Authentication Request Generation", 0.78)),
    (("port scan", "network scan", "scan-like", "enumeration"), ("Discovery", "T1046", "Network Service Discovery", 0.75)),
    (("sql injection", "sqli"), ("Initial Access", "T1190", "Exploit Public-Facing Application", 0.84)),
    (("xss", "cross-site scripting"), ("Initial Access", "T1190", "Exploit Public-Facing Application", 0.66)),
    (("directory traversal", "../", "path traversal"), ("Initial Access", "T1190", "Exploit Public-Facing Application", 0.80)),
    (("powershell", "pwsh"), ("Execution", "T1059.001", "PowerShell", 0.82)),
    (("command execution", "cmd.exe", "shell command"), ("Execution", "T1059", "Command and Scripting Interpreter", 0.76)),
    (("exfiltration", "data exfil"), ("Exfiltration", "T1041", "Exfiltration Over C2 Channel", 0.70)),
    (("firewall block", "denied traffic", "blocked"), ("Discovery", "T1046", "Network Service Discovery", 0.50)),
]


def auto_map_mitre(*parts: object) -> dict:
    text = " ".join(str(part or "") for part in parts).lower()
    for needles, mapping in MITRE_RULES:
        if any(needle in text for needle in needles):
            tactic, technique_id, technique_name, confidence = mapping
            return {
                "mitre_tactic": tactic,
                "mitre_technique_id": technique_id,
                "mitre_technique_name": technique_name,
                "mitre_confidence": confidence,
                "mitre_mapping_source": "auto",
            }
    return {
        "mitre_tactic": None,
        "mitre_technique_id": None,
        "mitre_technique_name": None,
        "mitre_confidence": None,
        "mitre_mapping_source": "auto",
    }
