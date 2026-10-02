"""AI Investigation Response and Claim contracts for LogIntel.

Specifies the typed output schema expected from an AI model completion,
enforcing explicit epistemic attribution and evidence linking.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from logintel.ai.domain.bundle import EvidenceConflict, EvidenceCoverage, EvidenceGap
from logintel.ai.domain.epistemic import EpistemicStatus
from logintel.ai.domain.evidence import EvidenceRef, EvidenceType
from logintel.ai.domain.intelligence import Hypothesis, InvestigationIntent, QueryProposal


class Claim(BaseModel):
    """An individual assertion made in an AI response with explicit epistemic status."""

    model_config = ConfigDict(extra="forbid")

    claim_text: str = Field(..., min_length=1)
    status: EpistemicStatus
    evidence_refs: List[EvidenceRef] = Field(default_factory=list)
    rationale: Optional[str] = Field(
        None,
        description="Mandatory rationale when status is INFERRED; explains the analytical deduction.",
    )

    @model_validator(mode="after")
    def validate_epistemic_invariants(self) -> Claim:
        if self.status == EpistemicStatus.OBSERVED:
            if not self.evidence_refs:
                raise ValueError("OBSERVED claims must have at least one authoritative supporting evidence reference.")
        elif self.status == EpistemicStatus.INFERRED:
            if not self.evidence_refs:
                raise ValueError("INFERRED claims must contain supporting evidence references.")
            if not self.rationale or not self.rationale.strip():
                raise ValueError("INFERRED claims must contain a non-empty rationale explaining the analytical deduction.")
        elif self.status == EpistemicStatus.UNKNOWN:
            if self.evidence_refs:
                raise ValueError("UNKNOWN assertions cannot be represented as observed facts with evidence references.")
        return self


class CitationRef(BaseModel):
    """Reference to an authoritative citation mentioned in the response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_type: EvidenceType
    evidence_id: str
    citation_tag: str


class AIInvestigationResponse(BaseModel):
    """Structured response schema returned to the LogIntel investigation workspace."""

    model_config = ConfigDict(extra="forbid")

    schema_version: str = "1.0.0"
    answer_markdown: str = Field(..., min_length=1)
    epistemic_status: EpistemicStatus
    claims: List[Claim] = Field(default_factory=list)
    citations: List[CitationRef] = Field(default_factory=list)
    suggested_queries: List[str] = Field(default_factory=list)
    identified_unknowns: List[str] = Field(default_factory=list)
    has_unverified_claims: bool = False
    unverified_citations: List[str] = Field(default_factory=list)
    model_identifier: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    # M5.3 Investigation Intelligence extensions
    intent: Optional[InvestigationIntent] = None
    evidence_coverage: Optional[EvidenceCoverage] = None
    hypotheses: List[Hypothesis] = Field(default_factory=list)
    evidence_gaps: List[EvidenceGap] = Field(default_factory=list)
    conflicts: List[EvidenceConflict] = Field(default_factory=list)
    suggested_query_proposals: List[QueryProposal] = Field(default_factory=list)

