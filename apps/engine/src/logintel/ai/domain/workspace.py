"""Domain models and state machines for LogIntel Milestone 5.4 Analyst Investigation Workspace.

Defines reproducible scope, validated investigation states, analyst-owned hypotheses,
explainable claim traces, structured summaries, and citation-grounded report drafts.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.bundle import EvidenceItem


class InvestigationState(str, Enum):
    """Deterministic analyst investigation lifecycle states."""
    OPEN = "OPEN"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    CLOSED = "CLOSED"


# Valid deterministic state transitions
ALLOWED_INVESTIGATION_TRANSITIONS: Dict[InvestigationState, List[InvestigationState]] = {
    InvestigationState.OPEN: [InvestigationState.ACTIVE, InvestigationState.CLOSED],
    InvestigationState.ACTIVE: [InvestigationState.PAUSED, InvestigationState.READY_FOR_REVIEW, InvestigationState.CLOSED],
    InvestigationState.PAUSED: [InvestigationState.ACTIVE, InvestigationState.CLOSED],
    InvestigationState.READY_FOR_REVIEW: [InvestigationState.ACTIVE, InvestigationState.CLOSED],
    InvestigationState.CLOSED: [InvestigationState.ACTIVE],  # Reopening requires explicit transition
}


class InvestigationScope(BaseModel):
    """Explicit, reproducible scope bounding an analyst investigation."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: int
    time_start: Optional[str] = None
    time_end: Optional[str] = None
    subject_type: str = "incident"
    subject_id: str
    selected_entity_ids: List[str] = Field(default_factory=list)
    selected_alert_ids: List[int] = Field(default_factory=list)
    selected_detection_ids: List[int] = Field(default_factory=list)
    selected_event_ids: List[str] = Field(default_factory=list)


class HypothesisStatus(str, Enum):
    """Analyst-determined status of an investigative hypothesis."""
    OPEN = "OPEN"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    UNRESOLVED = "UNRESOLVED"
    REJECTED = "REJECTED"


class AnalystHypothesis(BaseModel):
    """Analyst-owned investigative hypothesis with explicit evidence associations."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    investigation_id: int
    statement: str
    status: HypothesisStatus = HypothesisStatus.OPEN
    supporting_evidence_tags: List[str] = Field(default_factory=list)
    contradicting_evidence_tags: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    analyst_assessment: Optional[str] = None
    created_at: str
    updated_at: str
    created_by: str = "analyst"


class InvestigationStateAudit(BaseModel):
    """Immutable audit record of an investigation state transition."""
    model_config = ConfigDict(extra="ignore")

    timestamp: str
    actor: str
    previous_state: str
    new_state: str
    reason: Optional[str] = None


class ClaimTrace(BaseModel):
    """Complete provenance trace resolving an AI claim to its authoritative source."""
    model_config = ConfigDict(extra="ignore")

    claim_text: str
    epistemic_status: str
    citation_tag: str
    evidence_type: str
    evidence_id: str
    source_table: str
    source_id: str
    timestamp: Optional[str] = None
    summary: Optional[str] = None
    raw_evidence: Optional[Dict[str, Any]] = None


class InvestigationWorkspace(BaseModel):
    """Coherent analyst investigation workspace state combining scope, lifecycle, and evidence."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: int
    incident_id: int
    state: InvestigationState = InvestigationState.OPEN
    scope: InvestigationScope
    hypotheses: List[AnalystHypothesis] = Field(default_factory=list)
    evidence_candidates: List[EvidenceItem] = Field(default_factory=list)
    notes: List[Dict[str, Any]] = Field(default_factory=list)
    state_history: List[InvestigationStateAudit] = Field(default_factory=list)
    created_at: str
    updated_at: str


class InvestigationSummary(BaseModel):
    """Deterministic structured investigation summary covering all required analysis sections."""
    model_config = ConfigDict(extra="ignore")

    investigation_id: int
    scope: Dict[str, Any]
    subject: Dict[str, Any]
    key_observations: List[str] = Field(default_factory=list)
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    entities: List[Dict[str, Any]] = Field(default_factory=list)
    detections: List[Dict[str, Any]] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    attack_path: Dict[str, Any] = Field(default_factory=dict)
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_supporting: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_contradicting: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_context: List[Dict[str, Any]] = Field(default_factory=list)
    analyst_notes: List[Dict[str, Any]] = Field(default_factory=list)
    ai_assisted_analysis: Dict[str, Any] = Field(default_factory=dict)
    open_questions: List[str] = Field(default_factory=list)


class ReportDraft(BaseModel):
    """Evidence-grounded report draft cleanly separating facts, inferences, hypotheses, and unknowns."""
    model_config = ConfigDict(extra="ignore")

    report_id: str
    investigation_id: int
    generated_at: str
    title: str
    executive_summary: str
    facts: List[Dict[str, Any]] = Field(default_factory=list)
    inferences: List[Dict[str, Any]] = Field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    is_draft: bool = True
