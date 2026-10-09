"""Data models and enums for M7.8 Investigation Quality, Closure & Forensic Review."""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReviewGateType(str, Enum):
    """The 12 deterministic review gates required for forensic investigation review."""
    SCOPE = "SCOPE"
    EVIDENCE_COVERAGE = "EVIDENCE_COVERAGE"
    FINDING_GROUNDING = "FINDING_GROUNDING"
    HYPOTHESIS_REVIEW = "HYPOTHESIS_REVIEW"
    CONTRADICTIONS = "CONTRADICTIONS"
    QUESTIONS = "QUESTIONS"
    HUNTS = "HUNTS"
    TIMELINE_CONSISTENCY = "TIMELINE_CONSISTENCY"
    GRAPH_CONSISTENCY = "GRAPH_CONSISTENCY"
    REPORT_CONSISTENCY = "REPORT_CONSISTENCY"
    PACKAGE_CONSISTENCY = "PACKAGE_CONSISTENCY"
    HANDOFF = "HANDOFF"


class GateEvaluationStatus(str, Enum):
    """Outcome status for a specific review gate evaluation."""
    PASS = "PASS"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ReviewBlockerCategory(str, Enum):
    """Categorical classification for review blockers."""
    MISSING_SCOPE = "MISSING_SCOPE"
    UNRESOLVED_EVIDENCE_REFERENCE = "UNRESOLVED_EVIDENCE_REFERENCE"
    UNREVIEWED_FINDING = "UNREVIEWED_FINDING"
    UNREVIEWED_HYPOTHESIS = "UNREVIEWED_HYPOTHESIS"
    OPEN_INVESTIGATION_QUESTION = "OPEN_INVESTIGATION_QUESTION"
    UNRESOLVED_CONTRADICTION = "UNRESOLVED_CONTRADICTION"
    TELEMETRY_GAP_REQUIRES_REVIEW = "TELEMETRY_GAP_REQUIRES_REVIEW"
    STALE_REPORT = "STALE_REPORT"
    PACKAGE_INCONSISTENCY = "PACKAGE_INCONSISTENCY"
    HANDOFF_FOLLOWUP_REQUIRED = "HANDOFF_FOLLOWUP_REQUIRED"
    PROVENANCE_REFERENCE_FAILURE = "PROVENANCE_REFERENCE_FAILURE"


class BlockerSeverity(str, Enum):
    """Categorical severity for a review blocker."""
    BLOCKER = "BLOCKER"   # Prevents case closure without explicit waiver/acknowledgment
    WARNING = "WARNING"   # Analytical advisory requiring analyst review
    INFO = "INFO"         # Informational observation


class BlockerResolutionState(str, Enum):
    """Workflow state for an analyst review blocker."""
    UNRESOLVED = "UNRESOLVED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    WAIVED = "WAIVED"


class ClosureReadinessState(str, Enum):
    """Categorical closure readiness states for investigation lifecycle."""
    NOT_READY = "NOT_READY"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    READY_FOR_REVIEW = "READY_FOR_REVIEW"
    READY_FOR_CLOSURE = "READY_FOR_CLOSURE"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class FindingGroundingStatus(str, Enum):
    """Evidentiary grounding status for an analyst finding."""
    GROUNDED = "GROUNDED"
    PARTIALLY_GROUNDED = "PARTIALLY_GROUNDED"
    UNRESOLVED = "UNRESOLVED"


class QuestionReviewStatus(str, Enum):
    """Categorical review classification for investigation questions."""
    ANSWERED = "ANSWERED"
    PARTIALLY_ANSWERED = "PARTIALLY_ANSWERED"
    UNANSWERED = "UNANSWERED"
    BLOCKED_BY_TELEMETRY = "BLOCKED_BY_TELEMETRY"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ExportFormat(str, Enum):
    """Deterministic export format options."""
    JSON = "JSON"
    CSV = "CSV"
    MARKDOWN = "MARKDOWN"


class ReviewBlocker(BaseModel):
    """A deterministic categorical blocker or warning identified during forensic review."""
    model_config = ConfigDict(extra="ignore")

    blocker_id: str
    gate_type: ReviewGateType
    category: ReviewBlockerCategory
    description: str
    severity: BlockerSeverity
    source_reference: Optional[str] = None
    resolution_state: BlockerResolutionState = BlockerResolutionState.UNRESOLVED
    resolution_notes: Optional[str] = None
    resolved_by: Optional[str] = None
    resolved_at: Optional[str] = None


class ReviewGateResult(BaseModel):
    """Detailed evaluation result for a single review gate."""
    model_config = ConfigDict(extra="ignore")

    gate_type: ReviewGateType
    title: str
    status: GateEvaluationStatus
    summary: str
    blockers: List[ReviewBlocker] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)


class EvidenceCoverageMetrics(BaseModel):
    """Quantitative coverage metrics for forensic evidence references."""
    model_config = ConfigDict(extra="ignore")

    total_references: int = 0
    available_references: int = 0
    missing_references: int = 0
    unresolved_references: int = 0
    observed_evidence_count: int = 0
    inferred_evidence_count: int = 0
    telemetry_gaps_count: int = 0
    critical_gaps_count: int = 0


class ReviewProvenanceManifest(BaseModel):
    """Blake2b cryptographic integrity manifest for a case review snapshot."""
    model_config = ConfigDict(extra="ignore")

    manifest_id: str
    case_id: int
    closure_readiness: ClosureReadinessState
    gates_digest: str
    blockers_digest: str
    root_digest: str
    generated_at: str


class CaseReviewSnapshot(BaseModel):
    """Immutable deterministic snapshot of complete case quality, gates, and closure readiness."""
    model_config = ConfigDict(extra="ignore")

    review_id: str
    case_id: int
    case_status: str
    case_version: int
    closure_readiness: ClosureReadinessState
    gates: List[ReviewGateResult] = Field(default_factory=list)
    blockers: List[ReviewBlocker] = Field(default_factory=list)
    coverage: EvidenceCoverageMetrics = Field(default_factory=EvidenceCoverageMetrics)
    provenance: ReviewProvenanceManifest
    reviewed_by: str
    reviewed_at: str
    analyst_notes: Optional[str] = None


# -----------------------------------------------------------------------------
# Request & Response API Models
# -----------------------------------------------------------------------------

class RunReviewRequest(BaseModel):
    """Request to execute an on-demand forensic quality review."""
    model_config = ConfigDict(extra="ignore")
    notes: Optional[str] = None


class AcknowledgeBlockerRequest(BaseModel):
    """Request by an analyst to acknowledge or waive a review blocker."""
    model_config = ConfigDict(extra="ignore")
    resolution_state: BlockerResolutionState = BlockerResolutionState.ACKNOWLEDGED
    notes: str


class CloseCaseRequest(BaseModel):
    """Request by an authorized analyst to transition a case to CLOSED status."""
    model_config = ConfigDict(extra="ignore")
    closure_notes: str
    override_warnings: bool = False


class ReopenCaseRequest(BaseModel):
    """Request by an authorized analyst to transition a CLOSED case back to ACTIVE."""
    model_config = ConfigDict(extra="ignore")
    reopen_reason: str


class AIReviewSummaryRequest(BaseModel):
    """Request for local advisory AI to summarize review blockers and closure readiness."""
    model_config = ConfigDict(extra="ignore")
    instructions: Optional[str] = None


class AIReviewSummaryResponse(BaseModel):
    """Advisory-only AI explanation of review blockers and closure readiness."""
    model_config = ConfigDict(extra="ignore")
    summary: str
    key_blockers: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    is_authoritative: bool = False
    advisory_only: bool = True


class ReviewExportResponse(BaseModel):
    """Export container for review snapshot in requested format."""
    model_config = ConfigDict(extra="ignore")
    case_id: int
    format: str
    filename: str
    content: str
    root_digest: str
