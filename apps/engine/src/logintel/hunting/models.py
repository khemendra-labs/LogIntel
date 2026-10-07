"""Domain models, enums, and schemas for M7.5 Advanced Threat Hunting & Analyst Query Operations."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


class HuntIntent(str, Enum):
    """Categorical investigative hunt intent."""
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    AUTHENTICATION_ACTIVITY = "AUTHENTICATION_ACTIVITY"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    FILE_ACTIVITY = "FILE_ACTIVITY"
    PERSISTENCE = "PERSISTENCE"
    SYSTEMD_SERVICE_ACTIVITY = "SYSTEMD_SERVICE_ACTIVITY"
    CONTAINER_ACTIVITY = "CONTAINER_ACTIVITY"
    USER_SESSION = "USER_SESSION"
    CROSS_HOST_ACTIVITY = "CROSS_HOST_ACTIVITY"
    IOC_LOOKUP = "IOC_LOOKUP"
    ENTITY_ACTIVITY = "ENTITY_ACTIVITY"
    TEMPORAL_SEQUENCE = "TEMPORAL_SEQUENCE"
    CORRELATION = "CORRELATION"


class QueryOperator(str, Enum):
    """Allowlisted, type-aware query comparison operators."""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    PREFIX = "prefix"
    SUFFIX = "suffix"
    IN = "in"
    NOT_IN = "not_in"
    EXISTS = "exists"
    RANGE = "range"
    BEFORE = "before"
    AFTER = "after"
    BETWEEN = "between"


class HuntApprovalState(str, Enum):
    """Analyst approval gate lifecycle."""
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    READY = "READY"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"


class HuntExecutionStatus(str, Enum):
    """Outcome status of a governed hunt execution."""
    SUCCESS = "SUCCESS"
    NO_MATCH = "NO_MATCH"
    RESOURCE_LIMIT_EXCEEDED = "RESOURCE_LIMIT_EXCEEDED"
    TIMEOUT = "TIMEOUT"
    INVALID_QUERY = "INVALID_QUERY"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    FAILED = "FAILED"


class EpistemicStatusM75(str, Enum):
    """Epistemic classification preserving forensic truth separation."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class FieldFilter(BaseModel):
    """Controlled field condition with allowlisted operators."""
    model_config = ConfigDict(extra="forbid")

    field: str
    operator: QueryOperator = QueryOperator.EQUALS
    value: Any

    @field_validator("field")
    @classmethod
    def validate_field_name(cls, v: str) -> str:
        allowlisted = {
            "host", "hostname", "username", "user", "src_ip", "dst_ip", "ip",
            "process_name", "process", "command", "cmdline", "event_type",
            "source", "severity", "action", "outcome", "summary", "raw_message",
            "timestamp", "rule_id", "alert_id", "ioc", "container_id", "unit_name",
        }
        f_norm = v.lower().strip()
        if f_norm not in allowlisted:
            raise ValueError(f"Disallowed field '{v}'. Allowed fields: {sorted(allowlisted)}")
        return f_norm


class EntityFilter(BaseModel):
    """Entity-centric filter targeting investigation subjects."""
    model_config = ConfigDict(extra="forbid")

    entity_type: str  # USER, IP, PROCESS, COMMAND, FILE, HOST, CONTAINER, SERVICE
    entity_value: str

    @field_validator("entity_type")
    @classmethod
    def validate_entity_type(cls, v: str) -> str:
        allowed = {"USER", "IP", "PROCESS", "COMMAND", "FILE", "HOST", "CONTAINER", "SERVICE", "SOCKET"}
        u = v.upper().strip()
        if u not in allowed:
            raise ValueError(f"Unknown entity type '{v}'. Allowed: {sorted(allowed)}")
        return u


class TemporalWindow(BaseModel):
    """Bounded temporal parameters for chronological queries."""
    model_config = ConfigDict(extra="forbid")

    start_time: Optional[str] = None
    end_time: Optional[str] = None
    relative_window_minutes: Optional[int] = Field(default=None, ge=1, le=43200)  # Max 30 days
    anchor_timestamp: Optional[str] = None
    direction: Optional[str] = Field(default="around", pattern="^(before|after|around)$")


class HuntResourceBounds(BaseModel):
    """Resource bounds preventing uncontrolled query execution."""
    model_config = ConfigDict(extra="forbid")

    max_results: int = Field(default=100, ge=1, le=500)
    max_time_window_days: int = Field(default=30, ge=1, le=90)
    timeout_seconds: int = Field(default=10, ge=1, le=30)
    max_complexity_predicates: int = Field(default=10, ge=1, le=20)


class GovernedQueryModel(BaseModel):
    """Complete structured query model representing analyst investigative query."""
    model_config = ConfigDict(extra="forbid")

    case_id: int
    hunt_id: Optional[str] = None
    intent: HuntIntent
    question: str
    source_types: List[str] = Field(default_factory=lambda: ["events"])
    field_filters: List[FieldFilter] = Field(default_factory=list)
    entity_filters: List[EntityFilter] = Field(default_factory=list)
    temporal_window: Optional[TemporalWindow] = None
    bounds: HuntResourceBounds = Field(default_factory=HuntResourceBounds)
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class HuntQueryPreview(BaseModel):
    """Dry-run preview describing query execution scope without executing."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    intent: HuntIntent
    question: str
    scope: Dict[str, Any]
    sources: List[str]
    filter_count: int
    time_range_description: str
    operation_class: str
    estimated_resource_bounds: Dict[str, Any]
    validation_status: str  # VALID / INVALID
    validation_errors: List[str]
    requires_approval: bool = True
    preview_sql_summary: str


class HuntResultItem(BaseModel):
    """Single evidence reference result discovered by a hunt."""
    model_config = ConfigDict(extra="ignore")

    result_id: str
    source_type: str  # event, detection, alert
    source_id: str
    host: Optional[str] = None
    timestamp: str
    summary: str
    event_type: Optional[str] = None
    action: Optional[str] = None
    outcome: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    process_name: Optional[str] = None
    epistemic_status: EpistemicStatusM75 = EpistemicStatusM75.OBSERVED
    citation_tag: str
    provenance_hash: str
    raw_preview: Dict[str, Any] = Field(default_factory=dict)


class HuntExecutionResult(BaseModel):
    """Complete execution record of a completed governed threat hunt."""
    model_config = ConfigDict(extra="ignore")

    hunt_id: str
    case_id: int
    intent: HuntIntent
    question: str
    status: HuntExecutionStatus
    approval_state: HuntApprovalState
    approved_by: Optional[str] = None
    executed_by: str
    executed_at: str
    duration_ms: float
    result_count: int
    total_matches: int
    is_truncated: bool = False
    resource_limit_exceeded: bool = False
    results: List[HuntResultItem] = Field(default_factory=list)
    query_fingerprint: str
    provenance_manifest: Dict[str, Any] = Field(default_factory=dict)


class HuntSequenceStep(BaseModel):
    """Individual phase in a multi-step attack sequence proposal."""
    model_config = ConfigDict(extra="forbid")

    step_number: int
    name: str
    action_type: str  # login, sudo, exec, net, write, etc.
    field_filters: List[FieldFilter] = Field(default_factory=list)
    entity_filter: Optional[EntityFilter] = None
    max_time_delta_seconds: Optional[int] = Field(default=3600, ge=1)


class HuntSequenceProposal(BaseModel):
    """Multi-step sequential attack hunt definition."""
    model_config = ConfigDict(extra="forbid")

    case_id: int
    sequence_name: str
    description: str
    steps: List[HuntSequenceStep]
    max_total_window_seconds: int = Field(default=86400, ge=60)


class HuntSequenceResult(BaseModel):
    """Evaluation result of a multi-step sequence hunt."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    sequence_name: str
    matched_steps: int
    total_steps: int
    sequence_status: str  # COMPLETE, PARTIAL, NO_MATCH
    items_by_step: Dict[int, List[HuntResultItem]]
    missing_telemetry_steps: List[int]
    evaluated_at: str
    query_fingerprint: str


class CreateHuntProposalRequest(BaseModel):
    """Request payload to create and validate a hunt proposal."""
    model_config = ConfigDict(extra="forbid")

    intent: HuntIntent
    question: str
    source_types: List[str] = Field(default_factory=lambda: ["events"])
    field_filters: List[FieldFilter] = Field(default_factory=list)
    entity_filters: List[EntityFilter] = Field(default_factory=list)
    temporal_window: Optional[TemporalWindow] = None
    bounds: HuntResourceBounds = Field(default_factory=HuntResourceBounds)
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class ApproveHuntRequest(BaseModel):
    """Request to approve a validated hunt proposal."""
    model_config = ConfigDict(extra="forbid")

    approved_by: str = Field(min_length=1, max_length=100)
    rationale: Optional[str] = Field(default=None, max_length=1000)


class AIHuntProposalRequest(BaseModel):
    """Request for local AI assistance to draft a structured hunt proposal."""
    model_config = ConfigDict(extra="forbid")

    natural_language_question: str = Field(min_length=3, max_length=1000)
    context_hint: Optional[str] = Field(default=None, max_length=500)


class ConvertHuntToFindingRequest(BaseModel):
    """Payload to formulate an analyst finding from selected hunt results."""
    model_config = ConfigDict(extra="forbid")

    hunt_id: str
    title: str = Field(min_length=3, max_length=200)
    statement: str = Field(min_length=5, max_length=5000)
    result_ids: List[str] = Field(min_length=1)
    severity: str = "MEDIUM"
    category: str = "THREAT_HUNT"
    analyst_notes: Optional[str] = None


class ConvertHuntToHypothesisEvidenceRequest(BaseModel):
    """Payload to attach hunt results to hypothesis evaluation."""
    model_config = ConfigDict(extra="forbid")

    hunt_id: str
    hypothesis_id: str
    result_ids: List[str] = Field(min_length=1)
    role: str = "SUPPORTING"  # SUPPORTING or CONTRADICTING
    analyst_assessment: Optional[str] = None


class ConvertHuntToCollectionRequest(BaseModel):
    """Payload to add hunt results to an evidence collection."""
    model_config = ConfigDict(extra="forbid")

    hunt_id: str
    collection_id: str
    result_ids: List[str] = Field(min_length=1)
    role: str = "SUPPORTING"
    analyst_annotation: Optional[str] = None


class HuntExportResponse(BaseModel):
    """Deterministic export payload for a hunt execution."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    hunt_id: str
    format: str  # json or csv
    export_content: str
    exported_at: str
    fingerprint: str
    result_count: int
