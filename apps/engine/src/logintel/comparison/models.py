"""Domain models for Milestone 7.7 Case Comparison, Campaign Correlation & Cross-Investigation Analysis.

Defines schemas for deterministic multi-case comparison, categorical correlation dimensions,
campaign candidate models, provenance manifests, review workflows, and resource bounds.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class CorrelationBasis(str, Enum):
    """Categorical basis explaining WHY cases correlate.
    Strictly non-numerical: no probabilities, percentages, or risk scores.
    """
    ENTITY_OVERLAP = "ENTITY_OVERLAP"
    TEMPORAL_OVERLAP = "TEMPORAL_OVERLAP"
    SEQUENCE_SIMILARITY = "SEQUENCE_SIMILARITY"
    TECHNIQUE_OVERLAP = "TECHNIQUE_OVERLAP"
    PROCESS_CONTINUITY = "PROCESS_CONTINUITY"
    NETWORK_CONTINUITY = "NETWORK_CONTINUITY"
    ACCOUNT_CONTINUITY = "ACCOUNT_CONTINUITY"
    FILE_CONTINUITY = "FILE_CONTINUITY"
    FINDING_OVERLAP = "FINDING_OVERLAP"
    HUNT_RESULT_OVERLAP = "HUNT_RESULT_OVERLAP"
    MULTI_DIMENSIONAL_OVERLAP = "MULTI_DIMENSIONAL_OVERLAP"


class CorrelationType(str, Enum):
    """Specific category of shared investigative characteristics."""
    SHARED_ENTITY = "SHARED_ENTITY"
    SHARED_IP = "SHARED_IP"
    SHARED_HOST = "SHARED_HOST"
    SHARED_USER = "SHARED_USER"
    SHARED_PROCESS = "SHARED_PROCESS"
    SHARED_COMMAND = "SHARED_COMMAND"
    SHARED_FILE = "SHARED_FILE"
    SHARED_SESSION_PATTERN = "SHARED_SESSION_PATTERN"
    SHARED_TECHNIQUE = "SHARED_TECHNIQUE"
    SHARED_TIMELINE_PATTERN = "SHARED_TIMELINE_PATTERN"
    SHARED_FINDING_PATTERN = "SHARED_FINDING_PATTERN"
    SHARED_HUNT_PATTERN = "SHARED_HUNT_PATTERN"
    MULTI_DIMENSIONAL = "MULTI_DIMENSIONAL"


class CorroborationNature(str, Enum):
    """Categorical nature of the correlation evidence."""
    CORROBORATING = "CORROBORATING"
    CONTRADICTING = "CONTRADICTING"
    CONTEXTUAL = "CONTEXTUAL"
    TEMPORAL = "TEMPORAL"
    ENTITY_LINK = "ENTITY_LINK"
    SUPPORTING = "SUPPORTING"
    UNKNOWN = "UNKNOWN"


class CorrelationReviewStatus(str, Enum):
    """Analyst review lifecycle state for a campaign correlation candidate.
    Independent of epistemic status.
    """
    UNREVIEWED = "UNREVIEWED"
    UNDER_REVIEW = "UNDER_REVIEW"
    CORROBORATED = "CORROBORATED"
    WEAKENED = "WEAKENED"
    DISPUTED = "DISPUTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    REJECTED = "REJECTED"


class EpistemicStatus(str, Enum):
    """Core epistemic boundaries preserved across LogIntel."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class ComparisonScopeDimension(str, Enum):
    """Selectable analytical dimensions for cross-case evaluation."""
    ENTITIES = "ENTITIES"
    TIMELINE = "TIMELINE"
    FINDINGS = "FINDINGS"
    HYPOTHESES = "HYPOTHESES"
    HUNTS = "HUNTS"
    MITRE = "MITRE"
    EVIDENCE_GAPS = "EVIDENCE_GAPS"


class SharedEntity(BaseModel):
    """An entity observed across multiple investigated cases."""
    model_config = ConfigDict(extra="ignore")

    entity_type: str  # HOST, USER, IP, PROCESS, COMMAND, FILE, SESSION, SERVICE, SOCKET, CONTAINER
    entity_value: str
    case_occurrences: Dict[str, List[str]] = Field(default_factory=dict)  # str(case_id) -> list of source_ids
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    corroboration_nature: CorroborationNature = CorroborationNature.CONTEXTUAL


class TemporalComparisonWindow(BaseModel):
    """Time bounds and item volume for a single investigated case."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    event_count: int = 0


class TemporalOverlapResult(BaseModel):
    """Deterministic comparative temporal alignment."""
    model_config = ConfigDict(extra="ignore")

    relationship: str  # OVERLAPPING, SEQUENTIAL_BEFORE, SEQUENTIAL_AFTER, DISJOINT, INSUFFICIENT_DATA
    overlap_start: Optional[str] = None
    overlap_end: Optional[str] = None
    delta_seconds: Optional[int] = None
    case_windows: List[TemporalComparisonWindow] = Field(default_factory=list)


class SharedFindingPattern(BaseModel):
    """Analytical finding pattern shared across investigations."""
    model_config = ConfigDict(extra="ignore")

    pattern_type: str
    description: str
    cases_involved: List[int] = Field(default_factory=list)
    finding_ids: Dict[str, str] = Field(default_factory=dict)  # str(case_id) -> finding_id
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    corroboration_nature: CorroborationNature = CorroborationNature.SUPPORTING


class SharedHuntPattern(BaseModel):
    """Governed query template or threat hunt matching multiple cases."""
    model_config = ConfigDict(extra="ignore")

    query_template_id: str
    intent: str
    cases_involved: List[int] = Field(default_factory=list)
    query_ids: Dict[str, str] = Field(default_factory=dict)  # str(case_id) -> query_id
    result_counts: Dict[str, int] = Field(default_factory=dict)  # str(case_id) -> result_count


class EvidenceGapComparison(BaseModel):
    """Explicit negative evidence distinction preserving gaps vs lack of events."""
    model_config = ConfigDict(extra="ignore")

    gap_type: str
    description: str
    case_status: Dict[str, str] = Field(default_factory=dict)  # str(case_id) -> status
    epistemic_status: EpistemicStatus = EpistemicStatus.UNKNOWN


class CampaignCorrelationCandidate(BaseModel):
    """A derived cross-case campaign correlation candidate under analyst review.
    Does NOT assert attribution, maliciousness, or numeric confidence.
    """
    model_config = ConfigDict(extra="ignore")

    candidate_id: str
    case_ids: List[int] = Field(default_factory=list)
    correlation_type: CorrelationType
    correlation_basis: CorrelationBasis
    corroboration_nature: CorroborationNature = CorroborationNature.CONTEXTUAL
    shared_entities: List[Dict[str, Any]] = Field(default_factory=list)
    shared_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    temporal_relationships: Dict[str, Any] = Field(default_factory=dict)
    supporting_references: List[str] = Field(default_factory=list)
    contradicting_references: List[str] = Field(default_factory=list)
    evidence_gaps: List[Dict[str, Any]] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    analyst_review_status: CorrelationReviewStatus = CorrelationReviewStatus.UNREVIEWED
    created_at: str
    reviewed_by: Optional[str] = None
    review_notes: Optional[str] = None


class ComparisonProvenanceManifest(BaseModel):
    """Deterministic cryptographic manifest for a case comparison."""
    model_config = ConfigDict(extra="ignore")

    manifest_id: str
    comparison_id: str
    cases_included: List[int] = Field(default_factory=list)
    source_reference_hashes: Dict[str, str] = Field(default_factory=dict)
    provenance_digest: str
    created_at: str
    algorithm: str = "Blake2b"


class CaseComparisonResult(BaseModel):
    """Complete structured comparison between two or more investigations."""
    model_config = ConfigDict(extra="ignore")

    comparison_id: str
    primary_case_id: int
    compared_case_ids: List[int] = Field(default_factory=list)
    all_case_ids: List[int] = Field(default_factory=list)
    scope_dimensions: List[ComparisonScopeDimension] = Field(default_factory=list)
    shared_entities: List[SharedEntity] = Field(default_factory=list)
    temporal_overlap: TemporalOverlapResult
    shared_findings: List[SharedFindingPattern] = Field(default_factory=list)
    shared_hunts: List[SharedHuntPattern] = Field(default_factory=list)
    shared_mitre: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGapComparison] = Field(default_factory=list)
    correlation_candidates: List[CampaignCorrelationCandidate] = Field(default_factory=list)
    provenance_manifest: ComparisonProvenanceManifest
    created_at: str
    created_by: str = "SecAnalyst-1"
    analyst_notes: Optional[str] = None


# ---------------------------------------------------------------------------
# API Request / Response Models
# ---------------------------------------------------------------------------

class CreateCaseComparisonRequest(BaseModel):
    """Request to generate multi-case comparison."""
    model_config = ConfigDict(extra="ignore")

    compared_case_ids: List[int] = Field(..., min_length=1, max_length=4)
    dimensions: Optional[List[ComparisonScopeDimension]] = None
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    analyst_notes: Optional[str] = None


class ReviewCorrelationRequest(BaseModel):
    """Request to record analyst review on a correlation candidate."""
    model_config = ConfigDict(extra="ignore")

    status: CorrelationReviewStatus
    corroboration_nature: Optional[CorroborationNature] = None
    review_notes: Optional[str] = None


class CreateComparisonFindingRequest(BaseModel):
    """Request to create a derived cross-case finding."""
    model_config = ConfigDict(extra="ignore")

    candidate_id: str
    title: str
    statement: str
    affected_case_ids: Optional[List[int]] = None
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED


class ComparisonAISummaryRequest(BaseModel):
    """Request to generate an advisory local AI summary of comparison results."""
    model_config = ConfigDict(extra="ignore")

    prompt_instruction: Optional[str] = None


class ComparisonAISummaryResponse(BaseModel):
    """Advisory local AI summary of comparison results."""
    model_config = ConfigDict(extra="ignore")

    comparison_id: str
    draft_narrative: str
    key_observations: List[str] = Field(default_factory=list)
    recommended_questions: List[str] = Field(default_factory=list)
    advisory_only: bool = True
    content_origin: str = "AI_GENERATED"
