from dataclasses import dataclass


@dataclass
class RiskScore:
    priority_score: int
    severity_label: int


def compute_risk(severity: int, confidence: float, criticality: int,
                 cia_c: int, cia_i: int, cia_a: int) -> RiskScore:
    priority = (severity * 10) + int(confidence * 10) + (criticality * 5) + (cia_c * 3) + (cia_i * 2) + (cia_a * 1)
    if priority <= 20:
        label = 1
    elif priority <= 40:
        label = 2
    elif priority <= 60:
        label = 3
    elif priority <= 80:
        label = 4
    else:
        label = 5
    return RiskScore(priority_score=priority, severity_label=label)
