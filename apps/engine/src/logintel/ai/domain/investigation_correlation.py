"""Domain models and schemas for Milestone 5.9 Evidence Correlation Intelligence.

Defines schemas for:
- Evidence Clusters (grouped around multi-dimensional correlation reasons)
- Correlation Reason Taxonomy (deterministic, explicit justifications)
- Behavioral Sequence Analysis (multi-stage causal patterns)
- Hypothesis Support & Contradiction Analysis
- Evidence Gap Intelligence with Governed Hunt Recommendations
- Entity-Centric Investigation Workbench Dossier
- Advisory Local AI Correlation Explanations
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.investigation_graph import CorroborationStatus, GraphEvidenceItem
from logintel.ai.domain.investigation_intel import EpistemicStatus, QueryProposal


class CorrelationReason(str, Enum):
    """Deterministic, inspectable justification for linking records into a cluster."""
    SHARED_ENTITY = "SHARED_ENTITY"
    SHARED_SESSION = "SHARED_SESSION"
    SHARED_PROCESS = "SHARED_PROCESS"
    SHARED_SOURCE_IP = "SHARED_SOURCE_IP"
    SHARED_DESTINATION_IP = "SHARED_DESTINATION_IP"
    SHARED_INCIDENT = "SHARED_INCIDENT"
    SHARED_DETECTION = "SHARED_DETECTION"
    TEMPORAL_PROXIMITY = "TEMPORAL_PROXIMITY"
    EXPLICIT_RELATIONSHIP = "EXPLICIT_RELATIONSHIP"
    DIRECT_EVIDENCE_LINK = "DIRECT_EVIDENCE_LINK"
    BEHAVIORAL_SEQUENCE = "BEHAVIORAL_SEQUENCE"


class CorrelationReasonItem(BaseModel):
    """Detailed justification item explaining a correlation dimension."""
    model_config = ConfigDict(extra="ignore")

    reason_type: CorrelationReason
    description: str
    dimension_value: Optional[str] = None
    correlation_basis: str = "Deterministic attribute equality"


class EvidenceCluster(BaseModel):
    """Deterministic cluster of related forensic records, detections, and entities."""
    model_config = ConfigDict(extra="ignore")

    cluster_id: str = Field(default_factory=lambda: f"cluster-{uuid.uuid4().hex[:8]}")
    case_id: int
    title: str
    summary: str
    cluster_type: str  # AUTH_ACTIVITY, LATERAL_MOVEMENT, INFRASTRUCTURE_CONVERGENCE, PROCESS_EXECUTION
    correlation_reasons: List[CorrelationReasonItem] = Field(default_factory=list)
    temporal_bounds: Dict[str, Optional[str]] = Field(default_factory=dict)  # start_time, end_time, duration_seconds
    participating_entities: List[str] = Field(default_factory=list)
    evidence_references: List[GraphEvidenceItem] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    corroboration_status: CorroborationStatus = CorroborationStatus.DIRECT_EVIDENCE
    contradictions: List[str] = Field(default_factory=list)
    gaps: List[str] = Field(default_factory=list)
    created_at: str


class BehavioralSequenceStep(BaseModel):
    """A discrete chronological step within a detected behavioral pattern."""
    model_config = ConfigDict(extra="ignore")

    step_index: int
    timestamp: str
    stage_name: str  # INITIAL_ACCESS, EXECUTION, PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, EXFILTRATION
    action_summary: str
    actor_entity: str
    target_entity: str
    evidence_citation: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED


class BehavioralSequence(BaseModel):
    """Multi-step behavioral progression reconstructed from correlated evidence."""
    model_config = ConfigDict(extra="ignore")

    sequence_id: str = Field(default_factory=lambda: f"seq-{uuid.uuid4().hex[:8]}")
    case_id: int
    pattern_name: str
    description: str
    steps: List[BehavioralSequenceStep] = Field(default_factory=list)
    total_steps: int
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    supporting_evidence_count: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None


class HypothesisSupportDetail(BaseModel):
    """Evidence-grounded hypothesis evaluation separating supporting, contradicting, and missing facts."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    case_id: int
    statement: str
    support_status: str  # SUPPORTED BY EVIDENCE, WEAKLY SUPPORTED, CONTRADICTED, INSUFFICIENT EVIDENCE
    supporting_evidence: List[GraphEvidenceItem] = Field(default_factory=list)
    contradicting_evidence: List[GraphEvidenceItem] = Field(default_factory=list)
    contextual_evidence: List[GraphEvidenceItem] = Field(default_factory=list)
    missing_evidence_descriptions: List[str] = Field(default_factory=list)
    unresolved_questions: List[str] = Field(default_factory=list)
    recommended_governed_queries: List[QueryProposal] = Field(default_factory=list)


class EvidenceGapDetail(BaseModel):
    """Structured telemetry gap intelligence with actionable governed hunt proposals."""
    model_config = ConfigDict(extra="ignore")

    gap_id: str = Field(default_factory=lambda: f"gap-{uuid.uuid4().hex[:8]}")
    case_id: int
    gap_type: str  # EXPECTED_TELEMETRY_MISSING, ENTITY_UNRESOLVED, CORROBORATION_MISSING, CONTRADICTORY_TELEMETRY
    title: str
    description: str
    affected_entities: List[str] = Field(default_factory=list)
    affected_hypotheses: List[str] = Field(default_factory=list)
    resolution_remedy: str
    recommended_governed_query: Optional[QueryProposal] = None
    status: str = "OPEN"


class EntityWorkbenchDossier(BaseModel):
    """Deep entity-centric investigation view synthesizing cross-dimensional context."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    entity_key: str
    entity_type: str
    display_name: str
    related_clusters: List[EvidenceCluster] = Field(default_factory=list)
    related_findings: List[Dict[str, Any]] = Field(default_factory=list)
    related_sequences: List[BehavioralSequence] = Field(default_factory=list)
    adjacent_graph_entities: List[str] = Field(default_factory=list)
    evidence_references: List[GraphEvidenceItem] = Field(default_factory=list)
    identified_gaps: List[EvidenceGapDetail] = Field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = Field(default_factory=list)


class CorrelationExplanationRequest(BaseModel):
    """Request schema for local AI correlation briefing."""
    cluster_id: Optional[str] = None
    sequence_id: Optional[str] = None
    question: Optional[str] = None


class CorrelationExplanationResponse(BaseModel):
    """Advisory local AI explanation for correlation clusters and decision support."""
    model_config = ConfigDict(extra="ignore")

    explanation_id: str = Field(default_factory=lambda: f"cexp-{uuid.uuid4().hex[:8]}")
    case_id: int
    target_cluster_id: Optional[str] = None
    summary: str
    reasoning_explanation: str
    supporting_citations: List[str] = Field(default_factory=list)
    identified_unknowns: List[str] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    is_authoritative: bool = False
    generated_by: str = "LOCAL_AI_ADVISORY"
    generated_at: str
