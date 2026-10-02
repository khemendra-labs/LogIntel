"""Domain models for Milestone 5.5 Persistent Investigation Cases and Case Continuity.

Defines schemas for persistent cases, versioned state, evidence references with stale detection,
hypotheses, query history, versioned reports, handoff, and audit trail.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.bundle import EvidenceRole
from logintel.ai.domain.evidence import EvidenceType
from logintel.ai.domain.workspace import HypothesisStatus, InvestigationScope


class CaseStatus(str, Enum):
    """Deterministic persistent case lifecycle states."""
    OPEN = "OPEN"
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    CLOSED = "CLOSED"
    ARCHIVED = "ARCHIVED"


# Valid deterministic state transitions for persistent cases
ALLOWED_CASE_TRANSITIONS: Dict[CaseStatus, List[CaseStatus]] = {
    CaseStatus.OPEN: [CaseStatus.ACTIVE, CaseStatus.CLOSED, CaseStatus.ARCHIVED],
    CaseStatus.ACTIVE: [CaseStatus.PAUSED, CaseStatus.READY_FOR_REVIEW, CaseStatus.CLOSED, CaseStatus.ARCHIVED],
    CaseStatus.PAUSED: [CaseStatus.ACTIVE, CaseStatus.CLOSED, CaseStatus.ARCHIVED],
    CaseStatus.READY_FOR_REVIEW: [CaseStatus.ACTIVE, CaseStatus.CLOSED, CaseStatus.ARCHIVED],
    CaseStatus.CLOSED: [CaseStatus.ACTIVE, CaseStatus.ARCHIVED],
    CaseStatus.ARCHIVED: [CaseStatus.ACTIVE, CaseStatus.CLOSED],
}


class ResolutionStatus(str, Enum):
    """Authoritative evidence reference resolution status."""
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    UNRESOLVED = "UNRESOLVED"


class ContentOrigin(str, Enum):
    """Origin classification for investigation content."""
    ANALYST_AUTHORED = "ANALYST_AUTHORED"
    AI_GENERATED = "AI_GENERATED"
    SYSTEM_GENERATED = "SYSTEM_GENERATED"


class CaseEvidenceReference(BaseModel):
    """Pointer to authoritative forensic evidence with resolution state and analyst annotation."""
    model_config = ConfigDict(extra="ignore")

    reference_id: str
    case_id: int
    source_type: str = "event"  # event, alert, detection, entity, mitre
    source_id: str
    role: EvidenceRole = EvidenceRole.SUPPORTING
    epistemic_status: str = "OBSERVED"  # OBSERVED, INFERRED, UNKNOWN
    citation_tag: str
    analyst_annotation: Optional[str] = None
    created_at: str
    resolution_status: ResolutionStatus = ResolutionStatus.AVAILABLE
    resolved_record: Optional[Dict[str, Any]] = None


class CaseHypothesis(BaseModel):
    """Persistent analyst-owned hypothesis with evidence links, versioning, and assessment."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    case_id: int
    statement: str
    status: HypothesisStatus = HypothesisStatus.OPEN
    supporting_evidence_tags: List[str] = Field(default_factory=list)
    contradicting_evidence_tags: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    analyst_assessment: Optional[str] = None
    created_at: str
    updated_at: str
    created_by: str = "SecAnalyst-1"
    version: int = 1


class CaseQueryRecord(BaseModel):
    """Governed threat hunting query history record."""
    model_config = ConfigDict(extra="ignore")

    query_id: str
    case_id: int
    proposal_id: str
    query_template_id: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    executed_by: str = "SecAnalyst-1"
    executed_at: str
    result_count: int = 0
    execution_status: str = "SUCCESS"  # SUCCESS, NO_RESULTS, ERROR
    evidence_candidates_count: int = 0


class CaseReportVersion(BaseModel):
    """Versioned report draft preserving analyst edits, citations, and AI provenance."""
    model_config = ConfigDict(extra="ignore")

    report_id: str
    case_id: int
    version: int = 1
    title: str
    executive_summary: str
    facts: List[Dict[str, Any]] = Field(default_factory=list)
    inferences: List[Dict[str, Any]] = Field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    generated_by: ContentOrigin = ContentOrigin.AI_GENERATED
    model_id: Optional[str] = None
    model_digest: Optional[str] = None
    context_version: int = 1
    created_at: str
    is_final: bool = False


class CaseAuditRecord(BaseModel):
    """Immutable audit record tracking analyst actions and state modifications."""
    model_config = ConfigDict(extra="ignore")

    audit_id: Optional[int] = None
    case_id: int
    timestamp: str
    actor: str
    action: str  # CASE_CREATED, STATE_TRANSITION, SCOPE_UPDATED, HYPOTHESIS_CREATED, etc.
    previous_value: Optional[str] = None
    new_value: Optional[str] = None
    reason: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class InvestigationCase(BaseModel):
    """Persistent analyst investigation case aggregate."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    incident_id: int
    title: str
    description: str
    status: CaseStatus = CaseStatus.OPEN
    version: int = 1
    created_by: str = "SecAnalyst-1"
    owner: str = "SecAnalyst-1"
    scope: InvestigationScope
    created_at: str
    updated_at: str
    evidence_references: List[CaseEvidenceReference] = Field(default_factory=list)
    hypotheses: List[CaseHypothesis] = Field(default_factory=list)
    query_history: List[CaseQueryRecord] = Field(default_factory=list)
    reports: List[CaseReportVersion] = Field(default_factory=list)
    audit_history: List[CaseAuditRecord] = Field(default_factory=list)


class AIReconstructedContext(BaseModel):
    """Deterministically reconstructed context for local AI operations without cross-case memory."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    incident_id: int
    case_version: int
    status: str
    scope: InvestigationScope
    resolved_evidence_count: int
    stale_evidence_count: int
    hypotheses: List[Dict[str, Any]]
    query_history_summary: List[Dict[str, Any]]
    latest_report_summary: Optional[str] = None
    reconstructed_at: str
