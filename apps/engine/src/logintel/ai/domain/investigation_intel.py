"""Domain models and contracts for Milestone 5.6 Investigation Intelligence.

Defines schemas for:
- Investigation Findings (OBSERVED, INFERRED, UNKNOWN)
- Multi-attribute Correlated Findings with explicit explanation reasons
- Temporal Windows (BEFORE, DURING, AFTER) with anomaly and contradiction tracking
- Evidence Corroboration and Gap Analysis
- Governed Threat Hunting proposals, executions, and typed templates
- Entity-Centric Pivots across cases, incidents, alerts, and events
- Case Timeline Intelligence with strict provenance demarcation
- Deterministic Hypothesis Support Scoring
- Attack-Path & MITRE technique traceability
- Comprehensive Case Intelligence Dossier
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.intelligence import QueryProposal


class EpistemicStatus(str, Enum):
    """Rigorous epistemic status for investigation facts and inferences."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class CorroborationRole(str, Enum):
    """Classification of corroborating evidence roles."""
    PRIMARY = "PRIMARY"
    SUPPORTING = "SUPPORTING"
    CORROBORATING = "CORROBORATING"
    CONTRADICTING = "CONTRADICTING"
    TEMPORAL = "TEMPORAL"
    ENTITY_LINKED = "ENTITY_LINKED"
    CONTEXTUAL = "CONTEXTUAL"


class EvidenceSearchStatus(str, Enum):
    """Disambiguated status of evidence availability."""
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"
    SEARCHED_UNAVAILABLE = "SEARCHED_UNAVAILABLE"
    TELEMETRY_SOURCE_UNCOLLECTED = "TELEMETRY_SOURCE_UNCOLLECTED"


class QueryResultStatus(str, Enum):
    """Governed threat hunting query result states."""
    NO_MATCH = "NO_MATCH"
    MATCHED = "MATCHED"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"
    FAILED = "FAILED"


class HypothesisSupportStatus(str, Enum):
    """Deterministic evidence-backed support status for hypotheses."""
    SUPPORTED_BY_CURRENT_EVIDENCE = "SUPPORTED BY CURRENT EVIDENCE"
    WEAKLY_SUPPORTED = "WEAKLY SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT EVIDENCE"
    UNRESOLVED = "UNRESOLVED"


class TimelineSourceType(str, Enum):
    """Strict provenance classification for case timeline items."""
    OBSERVED_EVENT = "OBSERVED_EVENT"
    DETECTION = "DETECTION"
    ALERT = "ALERT"
    ANALYST_ANNOTATION = "ANALYST_ANNOTATION"
    DERIVED_CORRELATION = "DERIVED_CORRELATION"
    AI_INTERPRETATION = "AI_INTERPRETATION"


class InvestigationFinding(BaseModel):
    """Structured, evidence-grounded investigation finding."""
    model_config = ConfigDict(extra="ignore")

    finding_id: str = Field(default_factory=lambda: f"fnd-{uuid.uuid4().hex[:8]}")
    case_id: int
    finding_type: str  # AUTH_FAILURE_BURST, LATERAL_MOVEMENT, PRIVILEGE_ESCALATION, EXFILTRATION, ANOMALY
    title: str
    description: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    confidence_basis: str
    source_references: List[str] = Field(default_factory=list)
    related_entities: List[str] = Field(default_factory=list)
    related_alerts: List[int] = Field(default_factory=list)
    related_detections: List[int] = Field(default_factory=list)
    related_events: List[str] = Field(default_factory=list)
    created_at: str
    generated_by: str = "DETERMINISTIC_CORRELATOR"


class InvestigationCorrelation(BaseModel):
    """Deterministic correlation between investigation artifacts with explicit reasons."""
    model_config = ConfigDict(extra="ignore")

    correlation_id: str = Field(default_factory=lambda: f"corr-{uuid.uuid4().hex[:8]}")
    case_id: int
    source_item: str  # e.g., "[event:101]" or "[alert:14]"
    target_item: str  # e.g., "[event:102]" or "[detection:2]"
    correlation_type: str  # SAME_HOST, SAME_USER, SAME_SRC_IP, TEMPORAL_SEQUENCE, PROCESS_LINEAGE
    reasons: List[str] = Field(default_factory=list)
    confidence_score: float = 1.0
    temporal_distance_seconds: Optional[float] = None
    shared_entities: List[str] = Field(default_factory=list)


class TemporalWindowAnalysis(BaseModel):
    """Deterministic investigation time-bounding around an anchor."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    anchor_type: str  # alert, event, detection, incident
    anchor_id: str
    anchor_timestamp: str
    window_seconds: int = 300
    before_items: List[Dict[str, Any]] = Field(default_factory=list)
    during_items: List[Dict[str, Any]] = Field(default_factory=list)
    after_items: List[Dict[str, Any]] = Field(default_factory=list)
    temporal_anomalies: List[str] = Field(default_factory=list)
    state_contradictions: List[str] = Field(default_factory=list)


class EvidenceGap(BaseModel):
    """Structured gap in investigation evidence with safe hunt recommendation."""
    model_config = ConfigDict(extra="ignore")

    gap_id: str = Field(default_factory=lambda: f"gap-{uuid.uuid4().hex[:8]}")
    case_id: int
    gap_type: str  # MISSING_AUTH, MISSING_PROCESS, MISSING_NETWORK, TEMPORAL_COVERAGE, UNRESOLVED_ENTITY
    description: str
    affected_scope: Dict[str, Any] = Field(default_factory=dict)
    supporting_context: str
    recommended_governed_query: Optional[QueryProposal] = None
    status: str = "OPEN"  # OPEN, ADDRESSED, IRRELEVANT


class GovernedThreatHuntProposal(BaseModel):
    """Validated threat hunting proposal based strictly on allowlisted query templates."""
    model_config = ConfigDict(extra="ignore")

    proposal_id: str = Field(default_factory=lambda: f"hunt-{uuid.uuid4().hex[:8]}")
    case_id: int
    template_id: str  # query_events, search_auth_failures, search_process_exec, search_network_conn
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    validation_status: str = "VALID"  # VALID, INVALID
    validation_errors: List[str] = Field(default_factory=list)
    preview_query_description: str = ""
    suggested_by: str = "SecAnalyst-1"


class GovernedThreatHuntExecution(BaseModel):
    """Result of an analyst-approved threat hunting query execution."""
    model_config = ConfigDict(extra="ignore")

    execution_id: str = Field(default_factory=lambda: f"exec-{uuid.uuid4().hex[:8]}")
    case_id: int
    proposal_id: str
    template_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    executed_by: str = "SecAnalyst-1"
    approved_by: str = "SecAnalyst-1"
    executed_at: str
    result_status: QueryResultStatus = QueryResultStatus.MATCHED
    result_count: int = 0
    matched_items: List[Dict[str, Any]] = Field(default_factory=list)
    candidate_findings: List[InvestigationFinding] = Field(default_factory=list)


class EntityPivotAnalysis(BaseModel):
    """Comprehensive entity investigation pivot across events, alerts, and cases."""
    model_config = ConfigDict(extra="ignore")

    entity_type: str  # IP, USER, HOST, PROCESS, COMMAND, FILE, INCIDENT, ALERT, DETECTION
    entity_value: str
    case_id: int
    related_events: List[Dict[str, Any]] = Field(default_factory=list)
    related_alerts: List[Dict[str, Any]] = Field(default_factory=list)
    related_detections: List[Dict[str, Any]] = Field(default_factory=list)
    related_incidents: List[int] = Field(default_factory=list)
    related_cases: List[int] = Field(default_factory=list)
    related_entities: List[Dict[str, Any]] = Field(default_factory=list)
    temporal_activity: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)


class CaseTimelineItem(BaseModel):
    """Investigation timeline item with verifiable provenance."""
    model_config = ConfigDict(extra="ignore")

    item_id: str
    case_id: int
    timestamp: str
    source_type: TimelineSourceType
    title: str
    summary: str
    provenance: str
    citation_tag: Optional[str] = None
    is_authoritative: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class HypothesisEvidenceAnalysis(BaseModel):
    """Deterministic support analysis for an analyst-owned hypothesis."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    case_id: int
    statement: str
    support_status: HypothesisSupportStatus
    supporting_evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence_items: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    temporal_consistency: str
    entity_consistency: str
    recommended_queries: List[QueryProposal] = Field(default_factory=list)
    analyst_action_required: bool = False


class AttackPathStepAnalysis(BaseModel):
    """Attack path step labeled with explicit epistemic and supporting evidence."""
    model_config = ConfigDict(extra="ignore")

    step_number: int
    stage: str
    description: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    supporting_evidence: List[str] = Field(default_factory=list)
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None


class CaseIntelligenceDossier(BaseModel):
    """Complete aggregated intelligence report for a persistent case."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    incident_id: int
    case_title: str
    status: str
    owner: str
    findings: List[InvestigationFinding] = Field(default_factory=list)
    correlations: List[InvestigationCorrelation] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    timeline: List[CaseTimelineItem] = Field(default_factory=list)
    hypotheses_analysis: List[HypothesisEvidenceAnalysis] = Field(default_factory=list)
    attack_path_steps: List[AttackPathStepAnalysis] = Field(default_factory=list)
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    generated_at: str


class InvestigationIntelligenceResponse(BaseModel):
    """Structured local AI advisory response contract for investigation intelligence."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    summary: str
    observed_claims: List[Dict[str, Any]] = Field(default_factory=list)
    inferred_claims: List[Dict[str, Any]] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    citations: List[str] = Field(default_factory=list)
    suggested_queries: List[QueryProposal] = Field(default_factory=list)
    hypothesis_assessment: Dict[str, Any] = Field(default_factory=dict)
    provenance: Dict[str, Any] = Field(default_factory=dict)

