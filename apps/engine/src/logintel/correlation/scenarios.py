"""Multi-stage cyber attack kill-chain definitions and scenario classifiers."""

from __future__ import annotations

from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from logintel.models.events import Severity


class AttackStage(str, Enum):
    """Canonical attack stages aligned with MITRE ATT&CK enterprise tactics."""
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    IMPACT = "IMPACT"


# Mapping from detection rule category to attack stage
CATEGORY_TO_STAGE: Dict[str, AttackStage] = {
    "AUTH": AttackStage.INITIAL_ACCESS,
    "authentication": AttackStage.INITIAL_ACCESS,
    "PROCESS": AttackStage.EXECUTION,
    "process": AttackStage.EXECUTION,
    "PRIVILEGE": AttackStage.PRIVILEGE_ESCALATION,
    "privilege": AttackStage.PRIVILEGE_ESCALATION,
    "ACCOUNT": AttackStage.PERSISTENCE,
    "account": AttackStage.PERSISTENCE,
    "NETWORK": AttackStage.DISCOVERY,
    "network": AttackStage.DISCOVERY,
    "SECURITY": AttackStage.DEFENSE_EVASION,
    "security": AttackStage.DEFENSE_EVASION,
}

# Recognized multi-stage attack patterns: (stage_a, stage_b) -> scenario title
SCENARIO_SIGNATURES: Dict[Tuple[AttackStage, AttackStage], str] = {
    (AttackStage.INITIAL_ACCESS, AttackStage.PRIVILEGE_ESCALATION): "Initial Access Followed by Privilege Escalation",
    (AttackStage.DISCOVERY, AttackStage.INITIAL_ACCESS): "Network Reconnaissance Followed by Access Attempt",
    (AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION): "Unauthorized Access Followed by Suspicious Execution",
    (AttackStage.PRIVILEGE_ESCALATION, AttackStage.PERSISTENCE): "Privilege Escalation Followed by Account Tampering",
    (AttackStage.EXECUTION, AttackStage.DEFENSE_EVASION): "Execution with Security Policy Violation",
    (AttackStage.INITIAL_ACCESS, AttackStage.LATERAL_MOVEMENT): "Credential Access Followed by Lateral Movement",
    (AttackStage.PRIVILEGE_ESCALATION, AttackStage.IMPACT): "Privilege Abuse Leading to Impact",
}


def classify_stages(categories: Set[str]) -> List[AttackStage]:
    """Map a set of detection rule categories to canonical attack stages."""
    stages = set()
    for cat in categories:
        st = CATEGORY_TO_STAGE.get(cat.upper()) or CATEGORY_TO_STAGE.get(cat.lower())
        if st:
            stages.add(st)
    return sorted(list(stages), key=lambda s: s.value)


def evaluate_escalation(
    current_severity: Severity,
    categories: Set[str],
    alert_count: int,
    is_multi_host: bool = False,
) -> Tuple[Severity, Optional[str]]:
    """Determine whether an incident's severity should be escalated based on multi-stage progression.
    
    Returns:
        (new_severity, scenario_name_or_reason)
    """
    stages = classify_stages(categories)

    # 1. Multi-stage attack progression (e.g. Initial Access + Privilege Escalation)
    for (s1, s2), scenario_title in SCENARIO_SIGNATURES.items():
        if s1 in stages and s2 in stages:
            # Critical escalation
            return Severity.CRITICAL, scenario_title

    # 2. Multi-host campaign across network
    if is_multi_host and alert_count >= 2:
        if current_severity in (Severity.WARNING, Severity.NOTICE):
            return Severity.ALERT, "Cross-Host Lateral Movement Campaign"
        return current_severity, "Cross-Host Lateral Movement Campaign"

    # 3. High alert volume on single host across 2+ stages
    if len(stages) >= 2 and alert_count >= 3:
        if current_severity in (Severity.WARNING, Severity.NOTICE):
            return Severity.ALERT, "Multi-Tactic Attack Activity"
        elif current_severity == Severity.ALERT:
            return Severity.CRITICAL, "High-Confidence Multi-Stage Attack"

    return current_severity, None
