"""Domain models and contracts for Milestone 5.11 Case Assessment & Evidence Synthesis.

Defines schemas for:
- Evidence Sufficiency Assessment (SUFFICIENT, PARTIALLY_SUFFICIENT, INSUFFICIENT, UNKNOWN)
- Structured Case Findings with Epistemic State & Analyst Review Separation
- Competing Hypotheses Assessment (SUPPORTING, CONTRADICTING, UNRESOLVED)
- Structured Investigation Questions (OPEN, INVESTIGATING, ANSWERED, UNRESOLVED, NOT_APPLICABLE)
- Evidence Gap Prioritization (CRITICAL, HIGH, MEDIUM, LOW)
- Case State Intelligence & Advisory Closure Readiness
- Analyst Assessment vs System-Generated Analysis with Content Origin Separation
- Evidence-Backed Case Conclusion with Explicit Unknowns
- Structured 15-Section Investigation Briefing
- Final Case Report with Provenance Manifest
- Structured Case Handoff Package
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.investigation_intel import EpistemicStatus
from logintel.ai.domain.investigation_graph import GraphEvidenceItem
from logintel.ai.domain.investigation_dossier import FindingReviewState


class EvidenceSufficiencyState(str, Enum):
    """Categorical evaluation of evidence completeness without fake percentages."""
    SUFFICIENT = "SUFFICIENT"
    PARTIALLY_SUFFICIENT = "PARTIALLY_SUFFICIENT"
    INSUFFICIENT = "INSUFFICIENT"
    UNKNOWN = "UNKNOWN"


class ClosureReadinessState(str, Enum):
    """Deterministic closure readiness state evaluation."""
    READY = "READY"
    NOT_READY = "NOT_READY"
    READY_WITH_LIMITATIONS = "READY_WITH_LIMITATIONS"
    UNKNOWN = "UNKNOWN"


class AssessmentState(str, Enum):
    """Analytical progress state of the investigation assessment."""
    DRAFT = "DRAFT"
    IN_PROGRESS = "IN_PROGRESS"
    ASSESSMENT_COMPLETE = "ASSESSMENT_COMPLETE"
    PENDING_REVIEW = "PENDING_REVIEW"
    READY_FOR_CLOSURE = "READY_FOR_CLOSURE"
    FINAL = "FINAL"


class QuestionStatus(str, Enum):
    """Resolution status of investigative questions."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    ANSWERED = "ANSWERED"
    UNRESOLVED = "UNRESOLVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class QuestionCategory(str, Enum):
    """Categorization for unresolved investigative questions."""
    AUTHENTICATION = "AUTHENTICATION"
    EXECUTION = "EXECUTION"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    PERSISTENCE = "PERSISTENCE"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    TEMPORAL_GAP = "TEMPORAL_GAP"
    IDENTITY_CONTINUITY = "IDENTITY_CONTINUITY"
    HOST_ATTRIBUTION = "HOST_ATTRIBUTION"
    AUTHORIZATION = "AUTHORIZATION"


class ContentOrigin(str, Enum):
    """Explicit origin provenance separating system analysis from analyst authorship."""
    SYSTEM_DETERMINISTIC = "SYSTEM_DETERMINISTIC"
    LOCAL_AI_ADVISORY = "LOCAL_AI_ADVISORY"
    ANALYST_AUTHORED = "ANALYST_AUTHORED"


class GapPriority(str, Enum):
    """Explainable categorical priority for evidence gaps."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ProvenanceManifest(BaseModel):
    """Provenance tracking for generated assessments and briefings."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    assessment_id: str
    version: int = 1
    generation_timestamp: str
    content_origin: ContentOrigin = ContentOrigin.SYSTEM_DETERMINISTIC
    source_records: List[Dict[str, Any]] = Field(default_factory=list)
    fingerprint: str


class StructuredFinding(BaseModel):
    """Structured, evidence-grounded case finding with review state separation."""
    model_config = ConfigDict(extra="ignore")

    finding_id: str
    case_id: int
    title: str
    description: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    severity: str = "MEDIUM"
    confidence_basis: str = "Authoritative evidence match"
    evidence_references: List[str] = Field(default_factory=list)
    supporting_references: List[str] = Field(default_factory=list)
    contradicting_references: List[str] = Field(default_factory=list)
    related_entities: List[str] = Field(default_factory=list)
    related_events: List[str] = Field(default_factory=list)
    related_incidents: List[int] = Field(default_factory=list)
    related_sequences: List[str] = Field(default_factory=list)
    mitre_references: List[str] = Field(default_factory=list)
    review_state: FindingReviewState = FindingReviewState.UNREVIEWED
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_notes: Optional[str] = None
    provenance: Dict[str, Any] = Field(default_factory=dict)


class CompetingHypothesisAssessment(BaseModel):
    """Side-by-side evidence evaluation for competing hypotheses."""
    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str
    statement: str
    status: str = "OPEN"
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    determination: str = "UNRESOLVED"  # SUPPORTING, CONTRADICTING, UNRESOLVED
    analyst_assessment: Optional[str] = None
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED


class InvestigationQuestion(BaseModel):
    """Analyst-visible structured question tracking investigative inquiries."""
    model_config = ConfigDict(extra="ignore")

    question_id: str
    case_id: int
    question: str
    category: QuestionCategory = QuestionCategory.AUTHENTICATION
    status: QuestionStatus = QuestionStatus.OPEN
    related_evidence: List[str] = Field(default_factory=list)
    related_entities: List[str] = Field(default_factory=list)
    recommended_query: Optional[str] = None
    analyst_answer: Optional[str] = None
    resolution_notes: Optional[str] = None
    created_at: str
    resolved_at: Optional[str] = None
    created_by: str = "SecAnalyst-1"


class PrioritizedEvidenceGap(BaseModel):
    """Categorically prioritized evidence gap with explainable rationale."""
    model_config = ConfigDict(extra="ignore")

    gap_id: str
    title: str
    gap_type: str
    affected_area: str
    priority: GapPriority
    explanation: str
    remedy: str
    related_entities: List[str] = Field(default_factory=list)


class CaseConclusion(BaseModel):
    """Formal evidence-backed conclusion statement with explicit limitations."""
    model_config = ConfigDict(extra="ignore")

    statement: str
    epistemic_status: EpistemicStatus
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)


class EvidenceSufficiencyAssessment(BaseModel):
    """Deterministic evaluation of case evidence sufficiency without fake confidence."""
    model_config = ConfigDict(extra="ignore")

    status: EvidenceSufficiencyState
    rationale: str
    existing_evidence: List[str] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    next_useful_evidence: List[str] = Field(default_factory=list)


class ClosureReadinessAssessment(BaseModel):
    """Advisory evaluation determining whether a case satisfies closure criteria."""
    model_config = ConfigDict(extra="ignore")

    status: ClosureReadinessState
    summary: str
    blocking_factors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)


class CaseAssessment(BaseModel):
    """Top-level analytical dossier for case assessment and evidence synthesis."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    assessment_id: str
    assessment_version: int = 1
    created_at: str
    updated_at: str
    case_state: str
    evidence_state: EvidenceSufficiencyState
    assessment_state: AssessmentState = AssessmentState.DRAFT
    epistemic_summary: Dict[str, int] = Field(default_factory=dict)
    key_findings: List[StructuredFinding] = Field(default_factory=list)
    supporting_evidence: List[str] = Field(default_factory=list)
    contradicting_evidence: List[str] = Field(default_factory=list)
    evidence_gaps: List[PrioritizedEvidenceGap] = Field(default_factory=list)
    hypotheses: List[CompetingHypothesisAssessment] = Field(default_factory=list)
    questions: List[InvestigationQuestion] = Field(default_factory=list)
    evidence_sufficiency: EvidenceSufficiencyAssessment
    attack_sequence_summary: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    affected_hosts: List[str] = Field(default_factory=list)
    mitre_summary: List[str] = Field(default_factory=list)
    analyst_assessment: str = ""
    closure_readiness: ClosureReadinessAssessment
    conclusion: CaseConclusion
    provenance: ProvenanceManifest


class InvestigationBriefing(BaseModel):
    """15-section structured investigation briefing derived strictly from evidence."""
    model_config = ConfigDict(extra="ignore")

    briefing_id: str
    case_id: int
    assessment_id: str
    sections: Dict[str, str] = Field(default_factory=dict)
    briefing_text: str
    closure_readiness: ClosureReadinessState
    evidence_sufficiency: EvidenceSufficiencyState
    generated_at: str
    provenance_hash: str


class CaseHandoffPackage(BaseModel):
    """Structured handoff package assembling all analytical state for transfer."""
    model_config = ConfigDict(extra="ignore")

    handoff_id: str
    case_id: int
    created_at: str
    operator: str
    case_summary: str
    current_state: str
    key_findings: List[str] = Field(default_factory=list)
    open_questions: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    hypotheses: List[str] = Field(default_factory=list)
    affected_entities: List[str] = Field(default_factory=list)
    analyst_assessment: str = ""
    required_next_actions: List[str] = Field(default_factory=list)
    report_versions: List[int] = Field(default_factory=list)
    provenance_manifest: Dict[str, Any] = Field(default_factory=dict)


class AssessmentExplanationResponse(BaseModel):
    """Non-authoritative local AI advisory explanation of the case assessment."""
    model_config = ConfigDict(extra="ignore")

    explanation_id: str
    case_id: int
    target_id: str
    explanation_text: str
    is_authoritative: bool = False
    generated_by: ContentOrigin = ContentOrigin.LOCAL_AI_ADVISORY
    referenced_citations: List[str] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    generated_at: str
