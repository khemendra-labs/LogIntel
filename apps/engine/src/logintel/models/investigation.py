"""Domain models and schemas for LogIntel M4 Investigation Workspace and Threat Hunting."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from logintel.models.events import Severity
from logintel.models.incidents import ConfidenceLevel, IncidentStatus


class NoteTargetType(str, Enum):
    """Target entity or object of an analyst note."""
    INCIDENT = "incident"
    EVENT = "event"
    ENTITY = "entity"
    ALERT = "alert"


class InvestigationNote(BaseModel):
    """Analyst annotation or finding linked to an investigation."""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    incident_id: int
    author: str
    content: str
    created_at: datetime
    target_type: NoteTargetType = NoteTargetType.INCIDENT
    target_id: Optional[str] = None
    is_deleted: bool = False
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None
    deletion_reason: Optional[str] = None

    @field_validator("target_type", mode="before")
    @classmethod
    def _normalize_target_type(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


class InvestigationNoteAudit(BaseModel):
    """Immutable audit entry for analyst note lifecycle."""
    model_config = ConfigDict(extra="ignore")

    id: Optional[int] = None
    note_id: int
    incident_id: int
    action: str
    actor: str
    content: str
    target_type: NoteTargetType
    target_id: Optional[str] = None
    created_at: datetime
    action_timestamp: datetime
    reason: Optional[str] = None

    @field_validator("target_type", mode="before")
    @classmethod
    def _normalize_target_type(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


class CreateNoteRequest(BaseModel):
    """Payload to add an analyst note to an investigation."""
    author: str = Field(min_length=1, max_length=128)
    content: str = Field(min_length=1, max_length=4096)
    target_type: NoteTargetType = NoteTargetType.INCIDENT
    target_id: Optional[str] = None

    @field_validator("target_type", mode="before")
    @classmethod
    def _normalize_target_type(cls, v: Any) -> Any:
        if isinstance(v, str):
            return v.lower()
        return v


class EntityPivotSummary(BaseModel):
    """Deep investigative pivot summary for a specific security entity."""
    model_config = ConfigDict(extra="ignore")

    entity_key: str
    entity_type: str
    display_name: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_events: int = 0
    total_alerts: int = 0
    total_incidents: int = 0
    alert_count: int = 0
    incident_count: int = 0
    associated_hosts: List[str] = Field(default_factory=list)
    associated_users: List[str] = Field(default_factory=list)
    associated_ips: List[str] = Field(default_factory=list)
    associated_processes: List[str] = Field(default_factory=list)
    associated_commands: List[str] = Field(default_factory=list)
    related_relationships: List[Dict[str, Any]] = Field(default_factory=list)
    recent_events: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    incidents: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackPathStepNature(str, Enum):
    """Distinguishes observed facts from inferred or unavailable relationships."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNAVAILABLE = "UNAVAILABLE"


class AttackPathNode(BaseModel):
    """A node representation within a reconstructed attack path."""
    model_config = ConfigDict(extra="ignore")

    node_id: str
    entity_type: str
    label: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AttackPathStep(BaseModel):
    """A single directed progression step in an attack kill-chain."""
    model_config = ConfigDict(extra="ignore")

    step_number: int
    source_node: str
    target_node: str
    relationship_type: str
    stage: str
    confidence: ConfidenceLevel
    nature: AttackPathStepNature = AttackPathStepNature.OBSERVED
    supporting_event_ids: List[str] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    description: str
    inference_reason: Optional[str] = None
    derivation_source: Optional[str] = None
    timestamp: Optional[datetime] = None

    def model_post_init(self, __context: Any) -> None:
        if self.supporting_event_ids and not self.evidence_event_ids:
            self.evidence_event_ids = self.supporting_event_ids
        elif self.evidence_event_ids and not self.supporting_event_ids:
            self.supporting_event_ids = self.evidence_event_ids


class AttackPathReconstruction(BaseModel):
    """Reconstructed multi-stage attack path progression for an incident."""
    model_config = ConfigDict(extra="ignore")

    incident_id: int
    steps: List[AttackPathStep] = Field(default_factory=list)
    root_causes: List[str] = Field(default_factory=list)
    terminal_targets: List[str] = Field(default_factory=list)
    is_multi_host: bool = False
    total_steps: int = 0


class MitreMapping(BaseModel):
    """Evidence-backed mapping of detections and events to MITRE ATT&CK techniques."""
    model_config = ConfigDict(extra="ignore")

    technique_id: str
    technique_name: str
    tactic: str
    rule_id: str
    rule_name: str
    supporting_alert_ids: List[int] = Field(default_factory=list)
    supporting_event_ids: List[str] = Field(default_factory=list)
    evidence_event_count: int = 0
    confidence: ConfidenceLevel = ConfidenceLevel.DIRECT

    def model_post_init(self, __context: Any) -> None:
        if self.supporting_event_ids and not self.evidence_event_count:
            self.evidence_event_count = len(self.supporting_event_ids)


class EventForensics(BaseModel):
    """Deep forensic inspection record of a single event with provenance and context."""
    model_config = ConfigDict(extra="ignore")

    event_id: str
    event: Dict[str, Any]
    provenance: Dict[str, Any]
    detections: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    incidents: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[str] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)


class ThreatHuntFilter(BaseModel):
    """Parameters for evidence-centric threat hunting query across canonical events."""
    search_text: Optional[str] = None
    query: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    host: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    ip: Optional[str] = None
    process_name: Optional[str] = None
    process: Optional[str] = None
    command: Optional[str] = None
    event_type: Optional[str] = None
    source: Optional[str] = None
    severity: Optional[str] = None
    outcome: Optional[str] = None
    rule_id: Optional[str] = None
    detection_rule: Optional[str] = None
    alert_id: Optional[int] = None
    ioc: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=500)
    offset: int = Field(default=0, ge=0)

    def model_post_init(self, __context: Any) -> None:
        if self.query and not self.search_text:
            self.search_text = self.query
        if self.ip and not self.src_ip:
            self.src_ip = self.ip
        if self.process and not self.process_name:
            self.process_name = self.process
        if self.detection_rule and not self.rule_id:
            self.rule_id = self.detection_rule


class ThreatHuntResponse(BaseModel):
    """Bounded, paginated search results for threat hunting queries."""
    items: List[Dict[str, Any]]
    total: int
    total_matches: Optional[int] = None
    limit: int
    offset: int
    query_summary: str

    def model_post_init(self, __context: Any) -> None:
        if self.total_matches is None:
            self.total_matches = self.total


class InvestigationDossier(BaseModel):
    """Complete investigation dossier combining incident, evidence, timeline, graph, attack path, MITRE, and notes."""
    model_config = ConfigDict(extra="ignore")

    incident: Dict[str, Any]
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)
    attack_path: AttackPathReconstruction
    mitre_mappings: List[MitreMapping] = Field(default_factory=list)
    notes: List[InvestigationNote] = Field(default_factory=list)
    timeline_total: int = 0
