"""Investigation Intelligence Domain Contracts for LogIntel Milestone 5.3.

Defines investigation intents, hypothesis models, and structured query proposals.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class InvestigationIntent(str, Enum):
    """Structured analyst investigation intent categories."""

    SUMMARY = "SUMMARY"
    TIMELINE = "TIMELINE"
    ENTITY_ANALYSIS = "ENTITY_ANALYSIS"
    EVIDENCE_EXPLANATION = "EVIDENCE_EXPLANATION"
    ALERT_EXPLANATION = "ALERT_EXPLANATION"
    DETECTION_EXPLANATION = "DETECTION_EXPLANATION"
    ATTACK_PATH_EXPLANATION = "ATTACK_PATH_EXPLANATION"
    MITRE_EXPLANATION = "MITRE_EXPLANATION"
    HYPOTHESIS = "HYPOTHESIS"
    EVIDENCE_GAP = "EVIDENCE_GAP"
    NEXT_QUERY = "NEXT_QUERY"
    GENERAL = "GENERAL"


class HypothesisConfidence(str, Enum):
    """Explicit, calibrated confidence levels for AI-generated analytical hypotheses."""

    HIGH = "HIGH"        # Multiple corroborating independent evidence items; no contradictions
    MEDIUM = "MEDIUM"    # At least one primary evidence item and logical inferred progression
import uuid


class Hypothesis(BaseModel):
    """Structured analytical hypothesis grounded in evidence."""

    model_config = ConfigDict(extra="ignore")

    hypothesis_id: str = Field(default_factory=lambda: f"hyp-{uuid.uuid4().hex[:6]}")
    statement: str
    confidence: HypothesisConfidence = HypothesisConfidence.MEDIUM
    confidence_rationale: Optional[str] = None
    rationale: Optional[str] = None
    supporting_evidence: List[Any] = Field(default_factory=list)
    contradicting_evidence: List[Any] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    is_hypothesis: bool = True


class QueryProposal(BaseModel):
    """Structured, safe proposal for a follow-up threat hunting query.
    
    The AI proposes the structured parameters; it NEVER generates or executes raw SQL.
    """

    model_config = ConfigDict(extra="ignore")

    proposal_id: str = Field(default_factory=lambda: f"qp-{uuid.uuid4().hex[:6]}")
    title: Optional[str] = None
    description: Optional[str] = None
    intent: Optional[str] = None
    rationale: Optional[str] = None
    target_entity: Optional[str] = None
    entity_key: Optional[str] = None
    source: Optional[str] = None
    filters: Dict[str, Any] = Field(default_factory=dict)
    event_types: Optional[List[str]] = None
    host: Optional[str] = None
    username: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    process_name: Optional[str] = None
    search_text: Optional[str] = None
    relative_time_range: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=500)
    is_executed: bool = False
