"""Domain models and contracts for Milestone 5.7 Investigation Dossier & Analyst Operations.

Provides schemas for:
- Comprehensive Investigation Dossier with full section-by-section provenance manifests
- Key Findings lifecycle and Review State (UNREVIEWED, UNDER_REVIEW, ACCEPTED, REJECTED, NEEDS_MORE_EVIDENCE)
- Structured Evidence Matrix for hypotheses
- Evidence-Gap Next-Action Operationalization
- Refined Multi-Source Timeline Intelligence
- Structured Incident / Case Briefing
- Threat Hunt Result Integration
- Provenance Manifest for auditability
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.investigation_intel import (
    AttackPathStepAnalysis,
    EpistemicStatus,
    EvidenceGap,
    InvestigationCorrelation,
    InvestigationFinding,
    TimelineSourceType,
)
from logintel.ai.domain.intelligence import QueryProposal


class FindingReviewState(str, Enum):
    """Analyst review state for investigation findings (decoupled from forensic truth)."""
    UNREVIEWED = "UNREVIEWED"
    UNDER_REVIEW = "UNDER_REVIEW"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NEEDS_MORE_EVIDENCE = "NEEDS_MORE_EVIDENCE"


class FindingSeverity(str, Enum):
    """Severity classification for investigation findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class EvidenceMatrixStatus(str, Enum):
    """Deterministic evidence-backed support status for hypotheses in the evidence matrix."""
    SUPPORTED = "SUPPORTED"
    WEAKLY_SUPPORTED = "WEAKLY_SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT = "INSUFFICIENT"
    UNRESOLVED = "UNRESOLVED"


class EvidenceItemResolution(str, Enum):
    """Resolution status of individual evidence items cited in the matrix."""
    RESOLVED = "RESOLVED"
    MISSING = "MISSING"
    UNRESOLVED = "UNRESOLVED"
    UNAVAILABLE = "UNAVAILABLE"


class EvidenceMatrixEntry(BaseModel):
    """Structured evidence matrix row evaluating a single hypothesis."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    case_id: int
    statement: str
    status: EvidenceMatrixStatus
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    temporal_consistency: str = "CONSISTENT"
    entity_consistency: str = "CONSISTENT"
    last_evaluated_at: str


class EvidenceGapAction(BaseModel):
    """Structured next-action suggestion derived from an evidence gap."""
    model_config = ConfigDict(extra="ignore")

    gap_id: str
    case_id: int
    gap_type: str
    description: str
    affected_scope: Dict[str, Any] = Field(default_factory=dict)
    suggested_action: str
    reason: str
    evidence_requirement: str
    recommended_governed_query: Optional[QueryProposal] = None
    status: str = "OPEN"
    execution_control: str = "ANALYST_CONTROLLED"


class RefinedTimelineSourceType(str, Enum):
    """Comprehensive source taxonomy for refined timeline intelligence."""
    OBSERVED_EVENT = "OBSERVED_EVENT"
    DETECTION = "DETECTION"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    CORRELATION = "CORRELATION"
    FINDING = "FINDING"
    ANALYST_NOTE = "ANALYST_NOTE"
    HYPOTHESIS = "HYPOTHESIS"
    THREAT_HUNT_RESULT = "THREAT_HUNT_RESULT"
    AI_INTERPRETATION = "AI_INTERPRETATION"


class RefinedTimelineItem(BaseModel):
    """Unified timeline entry with explicit epistemic status and provenance."""
    model_config = ConfigDict(extra="ignore")

    item_id: str
    case_id: int
    timestamp: str
    source_type: RefinedTimelineSourceType
    source_id: str
    title: str
    summary: str
    epistemic_status: EpistemicStatus
    is_authoritative: bool = True
    citation_tag: Optional[str] = None
    provenance: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ProvenanceManifestEntry(BaseModel):
    """Detailed provenance tracking entry linking statements to source evidence."""
    model_config = ConfigDict(extra="ignore")

    manifest_id: str = Field(default_factory=lambda: f"prov-{uuid.uuid4().hex[:8]}")
    case_id: int
    item_type: str  # finding, timeline_item, evidence_ref, correlation, matrix_entry, briefing_section
    item_id: str
    source_type: str  # event, alert, detection, incident, analyst, query, derived
    source_id: str
    source_hash_or_ref: str
    epistemic_status: EpistemicStatus
    generated_by: str
    generated_at: str


class CaseBriefing(BaseModel):
    """Deterministic structured case briefing for analyst decision support."""
    model_config = ConfigDict(extra="ignore")

    briefing_id: str = Field(default_factory=lambda: f"brf-{uuid.uuid4().hex[:8]}")
    case_id: int
    incident_id: int
    case_title: str
    scope_summary: Dict[str, Any] = Field(default_factory=dict)
    observed_metrics: Dict[str, int] = Field(default_factory=dict)
    key_findings_summary: List[Dict[str, Any]] = Field(default_factory=list)
    correlations_narrative: List[str] = Field(default_factory=list)
    evidence_gaps_summary: List[str] = Field(default_factory=list)
    hypotheses_evidence_states: List[Dict[str, Any]] = Field(default_factory=list)
    recommended_next_actions: List[EvidenceGapAction] = Field(default_factory=list)
    generated_at: str
    generated_by: str = "DETERMINISTIC_BRIEFING_ENGINE"


class InvestigationDossier(BaseModel):
    """Complete aggregated investigation dossier with section-by-section provenance."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    incident_id: int
    case_title: str
    status: str
    owner: str
    created_at: str
    scope: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_summary: Dict[str, Any] = Field(default_factory=dict)
    timeline: List[RefinedTimelineItem] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    correlations: List[InvestigationCorrelation] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGapAction] = Field(default_factory=list)
    evidence_matrix: List[EvidenceMatrixEntry] = Field(default_factory=list)
    threat_hunting_results: List[Dict[str, Any]] = Field(default_factory=list)
    attack_path_steps: List[AttackPathStepAnalysis] = Field(default_factory=list)
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    analyst_notes: List[Dict[str, Any]] = Field(default_factory=list)
    ai_interpretation: Optional[Dict[str, Any]] = None
    review_state_summary: Dict[str, int] = Field(default_factory=dict)
    provenance_manifest: List[ProvenanceManifestEntry] = Field(default_factory=list)
    generated_at: str


class FindingReviewUpdate(BaseModel):
    """Request payload to update an analyst finding review state."""
    model_config = ConfigDict(extra="ignore")

    review_state: FindingReviewState
    analyst_notes: str = ""
    reviewer: str = "SecAnalyst-1"
