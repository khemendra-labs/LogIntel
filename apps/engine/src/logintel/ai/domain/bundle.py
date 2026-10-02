"""Evidence Bundle Domain Models for LogIntel Milestone 5.3.

Provides deterministic, provenance-preserving evidence structures, evidence roles,
conflict representation, and visibility gap disclosures.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator

from logintel.ai.domain.citation import CitationManifest
from logintel.ai.domain.evidence import EvidenceType


class EvidenceRole(str, Enum):
    """Explicit evidence role within an investigation bundle."""

    PRIMARY = "PRIMARY"
    SUPPORTING = "SUPPORTING"
    CONTEXTUAL = "CONTEXTUAL"
    CORROBORATING = "CORROBORATING"
    CONTRADICTING = "CONTRADICTING"
    TEMPORAL = "TEMPORAL"
    ENTITY_LINK = "ENTITY_LINK"


class EvidenceItem(BaseModel):
    """An individual piece of structured forensic evidence retaining full lineage."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: str
    evidence_type: EvidenceType
    source_id: str
    source_table: str
    timestamp: str
    relevance_score: float = Field(default=1.0, ge=0.0, le=1.0)
    role: EvidenceRole = Field(default=EvidenceRole.SUPPORTING)
    citation_tag: str
    summary: str
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp", mode="before")
    @classmethod
    def _coerce_timestamp(cls, v: Any) -> str:
        if isinstance(v, (datetime, date)):
            return v.isoformat()
        return str(v) if v is not None else ""


class EvidenceConflict(BaseModel):
    """Explicit representation of conflicting or contradictory forensic evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    conflict_id: str
    evidence_tag_a: str
    evidence_tag_b: str
    conflict_type: str
    explanation: str


class EvidenceGap(BaseModel):
    """Explicit representation of missing telemetry or visibility gaps."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    gap_id: str
    category: str
    description: str
    impact: str
    suggested_data_source: Optional[str] = None


class EvidenceCoverage(BaseModel):
    """Deterministic metadata tracking evidence type coverage and omissions."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required_evidence_types: List[str] = Field(default_factory=list)
    available_evidence_types: List[str] = Field(default_factory=list)
    missing_evidence_types: List[str] = Field(default_factory=list)
    selected_count: int = Field(default=0, ge=0)
    omitted_count: int = Field(default=0, ge=0)
    truncation_reasons: List[str] = Field(default_factory=list)


class InvestigationEvidenceBundle(BaseModel):
    """Comprehensive, deterministic evidence bundle synthesized for an incident."""

    model_config = ConfigDict(extra="forbid")

    investigation_id: int
    generated_at: str
    items: List[EvidenceItem] = Field(default_factory=list)
    conflicts: List[EvidenceConflict] = Field(default_factory=list)
    gaps: List[EvidenceGap] = Field(default_factory=list)
    coverage: EvidenceCoverage = Field(default_factory=EvidenceCoverage)
    citation_manifest: CitationManifest = Field(default_factory=CitationManifest)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def get_items_by_role(self, role: EvidenceRole) -> List[EvidenceItem]:
        """Filter evidence items by role."""
        return [i for i in self.items if i.role == role]

    def get_items_by_type(self, ev_type: EvidenceType) -> List[EvidenceItem]:
        """Filter evidence items by evidence type."""
        return [i for i in self.items if i.evidence_type == ev_type]
