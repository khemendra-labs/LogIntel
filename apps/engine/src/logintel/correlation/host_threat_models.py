"""Domain models and schemas for Host Threat Correlation and MITRE ATT&CK kill-chain analysis."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from logintel.models.events import Severity


class MitreTactic(str, Enum):
    """Canonical MITRE ATT&CK tactics representing stages in host compromise."""
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COMMAND_AND_CONTROL = "Command and Control"
    IMPACT = "Impact"


class MitreTechnique(BaseModel):
    """Structured MITRE ATT&CK technique reference."""
    id: str = Field(description="MITRE Technique ID (e.g., T1059.004)")
    name: str = Field(description="Descriptive technique name")
    tactic: MitreTactic = Field(description="Associated enterprise tactic")
    description: Optional[str] = Field(default=None, description="Operational explanation")
    reference_url: str = Field(description="Authoritative MITRE ATT&CK documentation URL")


class HostThreatStage(BaseModel):
    """Discrete observable stage in a host attack sequence."""
    stage_id: str = Field(description="Deterministic identifier for this stage")
    tactic: MitreTactic = Field(description="Associated MITRE tactic")
    technique: Optional[MitreTechnique] = Field(default=None, description="Mapped MITRE technique")
    timestamp: datetime = Field(description="Time of the earliest evidence event in this stage")
    summary: str = Field(description="Human-readable summary of the stage activity")
    event_ids: List[str] = Field(default_factory=list, description="Associated canonical event IDs")
    alert_ids: List[int] = Field(default_factory=list, description="Associated operational alert IDs")
    entity_keys: List[str] = Field(default_factory=list, description="Correlated entity keys (e.g., process, user, ip)")
    epistemic_certainty: str = Field(default="OBSERVED", description="OBSERVED, INFERRED, or UNKNOWN")
    severity: Severity = Field(default=Severity.NOTICE, description="Stage threat severity")


class HostAttackSequence(BaseModel):
    """Chronologically ordered sequence of threat stages indicating an unfolding attack."""
    sequence_id: str = Field(description="Deterministic sequence key")
    host: str = Field(description="Target host identifier")
    scenario_name: str = Field(description="Identified attack scenario or pattern name")
    first_seen: datetime = Field(description="Timestamp of first stage event")
    last_seen: datetime = Field(description="Timestamp of last stage event")
    stages: List[HostThreatStage] = Field(default_factory=list, description="Chronological threat stages")
    threat_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Composite threat risk score (0-100)")
    escalated_severity: Severity = Field(default=Severity.NOTICE, description="Escalated operational severity")
    epistemic_confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Certainty score (0.0-1.0)")
    participating_users: List[str] = Field(default_factory=list, description="Users involved in sequence")
    participating_processes: List[str] = Field(default_factory=list, description="Processes involved in sequence")
    external_ips: List[str] = Field(default_factory=list, description="External/remote IPs connected")


class HostThreatAssessment(BaseModel):
    """Comprehensive host threat assessment synthesising multi-source telemetry and kill chains."""
    host: str = Field(description="Target host evaluated")
    incident_id: Optional[int] = Field(default=None, description="Associated incident ID if linked")
    assessed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Evaluation timestamp")
    overall_threat_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Highest sequence threat score (0-100)")
    overall_severity: Severity = Field(default=Severity.NOTICE, description="Overall evaluated severity")
    primary_scenario: str = Field(default="Benign Activity", description="Primary attack scenario identified")
    epistemic_confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Overall epistemic confidence")
    attack_sequences: List[HostAttackSequence] = Field(default_factory=list, description="Identified attack sequences")
    mitre_tactics_observed: List[str] = Field(default_factory=list, description="List of observed MITRE tactics")
    mitre_techniques_observed: List[MitreTechnique] = Field(default_factory=list, description="Detailed list of observed MITRE techniques")
    telemetry_source_diversity: int = Field(default=0, ge=0, description="Count of independent telemetry source types corroborated")
    summary: str = Field(description="Deterministic investigative executive summary")
    node_count: int = Field(default=0, ge=0, description="Total entities in host attack graph")
    edge_count: int = Field(default=0, ge=0, description="Total causal relationships in host attack graph")
