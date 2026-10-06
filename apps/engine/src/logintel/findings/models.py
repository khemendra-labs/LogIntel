"""Domain models for Milestone 7.4 Findings & Hypothesis Workbench.

Strict categorical separation:
    OBSERVED EVIDENCE ≠ ANALYST FINDING ≠ HYPOTHESIS ≠ FINAL CONCLUSION

No numerical probabilities or fake confidence scores.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class EpistemicStatus(str, Enum):
    """Forensic epistemic state (immutable factual classification)."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class FindingReviewStatus(str, Enum):
    """Analyst review state (strictly decoupled from epistemic status)."""
    UNREVIEWED = "UNREVIEWED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DISPUTED = "DISPUTED"


class FindingLifecycleStatus(str, Enum):
    """Operational lifecycle state of an analyst-authored finding."""
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class HypothesisLifecycleStatus(str, Enum):
    """Evaluative state of an investigative proposition."""
    OPEN = "OPEN"
    SUPPORTED = "SUPPORTED"
    WEAKENED = "WEAKENED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


class EvidenceGapType(str, Enum):
    """Forensic reason for missing evidence."""
    AUDIT_RULE_NOT_CONFIGURED = "AUDIT_RULE_NOT_CONFIGURED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    NO_EVENT_OBSERVED = "NO_EVENT_OBSERVED"
    TELEMETRY_DROPPED = "TELEMETRY_DROPPED"
    UNKNOWN = "UNKNOWN"


class FindingEvidenceRole(str, Enum):
    """Categorical role of an evidence item relative to a finding or hypothesis."""
    SUPPORTING = "SUPPORTING"
    CONTRADICTING = "CONTRADICTING"
    CONTEXTUAL = "CONTEXTUAL"
    TEMPORAL = "TEMPORAL"
    CORROBORATING = "CORROBORATING"


class FindingEvidenceReference(BaseModel):
    """Pointer to authoritative evidence with role, epistemic state, and provenance."""
    model_config = ConfigDict(extra="ignore")

    reference_id: str
    source_type: str = "event"  # "event", "alert", "detection", "incident", "timeline_item", "host_telemetry", "graph_relationship"
    source_id: str
    citation_tag: str
    role: FindingEvidenceRole = FindingEvidenceRole.SUPPORTING
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    collection_id: Optional[str] = None
    analyst_note: Optional[str] = None
    host: Optional[str] = None
    timestamp: Optional[str] = None
    added_at: str
    provenance_hash: Optional[str] = None


class FindingVersion(BaseModel):
    """Deterministic snapshot of an earlier version of an analyst finding."""
    model_config = ConfigDict(extra="ignore")

    version: int
    title: str
    statement: str
    epistemic_status: EpistemicStatus
    updated_at: str
    updated_by: str
    change_summary: str = ""


class Finding(BaseModel):
    """Analyst-authored analytical finding."""
    model_config = ConfigDict(extra="ignore")

    finding_id: str
    case_id: int
    title: str
    statement: str
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    review_status: FindingReviewStatus = FindingReviewStatus.UNREVIEWED
    lifecycle_status: FindingLifecycleStatus = FindingLifecycleStatus.ACTIVE
    severity: str = "MEDIUM"  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
    supporting_evidence: List[FindingEvidenceReference] = Field(default_factory=list)
    contradicting_evidence: List[FindingEvidenceReference] = Field(default_factory=list)
    supporting_collections: List[str] = Field(default_factory=list)
    related_hypotheses: List[str] = Field(default_factory=list)
    contradicting_hypotheses: List[str] = Field(default_factory=list)
    analyst_notes: Optional[str] = None
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    version: int = 1
    version_history: List[FindingVersion] = Field(default_factory=list)
    created_at: str
    updated_at: str
    created_by: str = "analyst"
    provenance: Dict[str, Any] = Field(default_factory=dict)


class EvidenceGap(BaseModel):
    """Explicitly modeled telemetry omission or gap."""
    model_config = ConfigDict(extra="ignore")

    gap_id: str
    gap_type: EvidenceGapType
    description: str
    expected_source: str
    affected_hypotheses: List[str] = Field(default_factory=list)
    detected_at: Optional[str] = None


class HypothesisAssessmentView(BaseModel):
    """Enriched analyst hypothesis with supporting, contradicting, and gap assessments."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    case_id: int
    title: str
    statement: str
    status: HypothesisLifecycleStatus = HypothesisLifecycleStatus.OPEN
    version: int = 1
    supporting_evidence: List[FindingEvidenceReference] = Field(default_factory=list)
    contradicting_evidence: List[FindingEvidenceReference] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    relevant_collections: List[str] = Field(default_factory=list)
    supporting_findings: List[str] = Field(default_factory=list)
    contradicting_findings: List[str] = Field(default_factory=list)
    analyst_assessment: Optional[str] = None
    created_by: str = "SecAnalyst-1"
    created_at: str
    updated_at: str


class HypothesisComparisonItem(BaseModel):
    """Categorical assessment metrics for a single hypothesis in a comparison view."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    title: str
    statement: str
    status: HypothesisLifecycleStatus
    supporting_count: int
    contradicting_count: int
    gaps_count: int
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    contradicting_evidence_ids: List[str] = Field(default_factory=list)
    gap_descriptions: List[str] = Field(default_factory=list)
    analyst_assessment: Optional[str] = None


class HypothesisComparisonResponse(BaseModel):
    """Side-by-side categorical comparison of competing hypotheses."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    hypotheses: List[HypothesisComparisonItem] = Field(default_factory=list)
    total_hypotheses: int = 0
    generated_at: str


class FindingsWorkbenchResponse(BaseModel):
    """Full Findings & Hypothesis Workbench state for an investigation."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    findings: List[Finding] = Field(default_factory=list)
    hypotheses: List[HypothesisAssessmentView] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    total_findings: int = 0
    total_hypotheses: int = 0
    total_gaps: int = 0


class FindingsExportResponse(BaseModel):
    """Deterministic export of findings and hypotheses."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    format: str
    item_count: int
    content: str
    sha256_digest: str


# -----------------------------------------------------------------------------
# Request Models
# -----------------------------------------------------------------------------

class CreateFindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=256)
    statement: str = Field(..., min_length=1, max_length=4000)
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    severity: str = Field(default="MEDIUM", pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)$")
    supporting_evidence: List[Dict[str, Any]] = Field(default_factory=list, max_length=100)
    contradicting_evidence: List[Dict[str, Any]] = Field(default_factory=list, max_length=100)
    supporting_collections: List[str] = Field(default_factory=list, max_length=50)
    related_hypotheses: List[str] = Field(default_factory=list, max_length=50)
    contradicting_hypotheses: List[str] = Field(default_factory=list, max_length=50)
    analyst_notes: Optional[str] = Field(default=None, max_length=2048)
    created_by: str = Field(default="analyst", max_length=100)


class UpdateFindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    statement: Optional[str] = Field(default=None, min_length=1, max_length=4000)
    epistemic_status: Optional[EpistemicStatus] = None
    severity: Optional[str] = Field(default=None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)$")
    lifecycle_status: Optional[FindingLifecycleStatus] = None
    supporting_collections: Optional[List[str]] = Field(default=None, max_length=50)
    related_hypotheses: Optional[List[str]] = Field(default=None, max_length=50)
    contradicting_hypotheses: Optional[List[str]] = Field(default=None, max_length=50)
    analyst_notes: Optional[str] = Field(default=None, max_length=2048)
    updated_by: str = Field(default="analyst", max_length=100)
    change_summary: str = Field(default="Analyst update", max_length=500)


class ReviewFindingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_status: FindingReviewStatus
    analyst_notes: str = Field(default="", max_length=2048)
    reviewed_by: str = Field(default="analyst", max_length=100)


class AddFindingEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_type: str = Field(..., pattern="^(event|alert|detection|incident|timeline_item|host_telemetry|graph_relationship)$")
    source_id: str = Field(..., min_length=1, max_length=256)
    citation_tag: Optional[str] = Field(default=None, max_length=64)
    role: FindingEvidenceRole = FindingEvidenceRole.SUPPORTING
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    collection_id: Optional[str] = Field(default=None, max_length=128)
    analyst_note: Optional[str] = Field(default=None, max_length=2048)
    host: Optional[str] = Field(default=None, max_length=128)
    timestamp: Optional[str] = Field(default=None, max_length=64)
    added_by: str = Field(default="analyst", max_length=100)


class CreateHypothesisM74Request(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(default=None, max_length=256)
    statement: str = Field(..., min_length=3, max_length=4000)
    status: HypothesisLifecycleStatus = HypothesisLifecycleStatus.OPEN
    supporting_evidence: List[str] = Field(default_factory=list, max_length=100)
    contradicting_evidence: List[str] = Field(default_factory=list, max_length=100)
    evidence_gaps: List[str] = Field(default_factory=list, max_length=100)
    relevant_collections: List[str] = Field(default_factory=list, max_length=50)
    analyst_assessment: Optional[str] = Field(default=None, max_length=4000)
    created_by: str = Field(default="SecAnalyst-1", max_length=100)


class UpdateHypothesisM74Request(BaseModel):
    model_config = ConfigDict(extra="forbid")

    statement: Optional[str] = Field(default=None, min_length=3, max_length=4000)
    status: Optional[HypothesisLifecycleStatus] = None
    supporting_evidence: Optional[List[str]] = Field(default=None, max_length=100)
    contradicting_evidence: Optional[List[str]] = Field(default=None, max_length=100)
    evidence_gaps: Optional[List[str]] = Field(default=None, max_length=100)
    relevant_collections: Optional[List[str]] = Field(default=None, max_length=50)
    analyst_assessment: Optional[str] = Field(default=None, max_length=4000)
    updated_by: str = Field(default="SecAnalyst-1", max_length=100)


class AddHypothesisGapRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    gap_type: EvidenceGapType = EvidenceGapType.UNKNOWN
    description: str = Field(..., min_length=3, max_length=1000)
    expected_source: str = Field(default="telemetry", max_length=128)
    detected_by: str = Field(default="analyst", max_length=100)
