"""Domain models and schemas for Milestone 5.8 Investigation Graph & Relationship Intelligence.

Defines schemas for:
- Investigation Graph Nodes and Edges with explicit epistemic and authority demarcation
- Evidence-Bound Graph Relationships linking edges to concrete forensic citations
- Temporal Relationship Intelligence (BEFORE, DURING, AFTER, OVERLAPS, SEQUENCE)
- Multi-Source Corroboration and Contradiction tracking
- Bounded Path Analysis and Investigation Chains
- Entity-Centric Pivot Graphs
- Governed Graph Explanations (advisory-only, citation-grounded)
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.investigation_intel import EpistemicStatus
from logintel.models.incidents import ConfidenceLevel


class GraphNodeType(str, Enum):
    """Categorical classification of nodes within the investigation graph."""
    # Domain entities
    HOST = "HOST"
    USER = "USER"
    IP = "IP"
    PROCESS = "PROCESS"
    COMMAND = "COMMAND"
    FILE = "FILE"
    SESSION = "SESSION"
    DOMAIN = "DOMAIN"
    CONTAINER = "CONTAINER"
    # Investigative context records
    EVENT = "EVENT"
    DETECTION = "DETECTION"
    ALERT = "ALERT"
    INCIDENT = "INCIDENT"
    FINDING = "FINDING"


class RelationshipEpistemicStatus(str, Enum):
    """Rigorous epistemic categorization of relationships."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class CorroborationStatus(str, Enum):
    """Evidence-backed corroboration status of a graph relationship."""
    DIRECT_EVIDENCE = "DIRECT_EVIDENCE"
    CORROBORATED = "CORROBORATED"
    SINGLE_SOURCE = "SINGLE_SOURCE"
    TEMPORALLY_ALIGNED = "TEMPORALLY_ALIGNED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNRESOLVED = "UNRESOLVED"


class TemporalRelation(str, Enum):
    """Qualitative temporal relationship between linked entities or events."""
    BEFORE = "BEFORE"
    DURING = "DURING"
    AFTER = "AFTER"
    OVERLAPS = "OVERLAPS"
    CO_OCCURRED = "CO_OCCURRED"
    SEQUENCE = "SEQUENCE"


class PathNature(str, Enum):
    """Epistemic nature of a reconstructed investigation path."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    MIXED = "MIXED"


class GraphEvidenceItem(BaseModel):
    """Concrete forensic evidence backing a graph relationship."""
    model_config = ConfigDict(extra="ignore")

    reference_id: str
    source_type: str  # event, alert, detection, hunt_query
    source_id: str
    source_hash: str  # sha256:...
    citation_tag: str
    timestamp: Optional[str] = None
    summary: str
    epistemic_status: EpistemicStatus
    is_authoritative: bool
    role: str = "supporting"  # primary, supporting, contradicting, contextual


class InvestigationGraphNode(BaseModel):
    """Node representation in the investigation graph."""
    model_config = ConfigDict(extra="ignore")

    node_id: str
    node_type: GraphNodeType
    display_label: str
    entity_key: Optional[str] = None
    is_authoritative: bool = True
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    source_reference: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    degree: int = 0


class InvestigationGraphEdge(BaseModel):
    """Evidence-bound relationship edge connecting two graph nodes."""
    model_config = ConfigDict(extra="ignore")

    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    epistemic_status: RelationshipEpistemicStatus = RelationshipEpistemicStatus.OBSERVED
    is_authoritative: bool = True
    confidence: ConfidenceLevel = ConfidenceLevel.CORRELATED
    corroboration_status: CorroborationStatus = CorroborationStatus.DIRECT_EVIDENCE
    evidence_references: List[GraphEvidenceItem] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    duration_seconds: Optional[float] = None
    temporal_relation: Optional[TemporalRelation] = None
    mitre_technique_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    description: str = ""
    provenance: str = ""


class InvestigationGraph(BaseModel):
    """Deterministic investigation graph aggregating nodes and evidence-bound edges."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    incident_id: int
    nodes: List[InvestigationGraphNode]
    edges: List[InvestigationGraphEdge]
    total_nodes: int
    total_edges: int
    observed_edges_count: int
    inferred_edges_count: int
    corroborated_edges_count: int
    contradicted_edges_count: int
    generated_at: str


class InvestigationPath(BaseModel):
    """Bounded, evidence-backed traversal path connecting two entities."""
    model_config = ConfigDict(extra="ignore")

    path_id: str = Field(default_factory=lambda: f"path-{uuid.uuid4().hex[:8]}")
    case_id: int
    source_node_id: str
    target_node_id: str
    nodes: List[InvestigationGraphNode]
    edges: List[InvestigationGraphEdge]
    total_steps: int
    path_nature: PathNature
    evidence_references_count: int
    total_duration_seconds: Optional[float] = None
    summary: str


class TemporalChainStep(BaseModel):
    """A single sequential step in a temporal correlation chain."""
    model_config = ConfigDict(extra="ignore")

    step_index: int
    timestamp: str
    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    delta_seconds_from_previous: Optional[float] = None
    evidence_citation: str
    epistemic_status: RelationshipEpistemicStatus


class TemporalChain(BaseModel):
    """Chronologically ordered relationship transition sequence."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    steps: List[TemporalChainStep]
    total_steps: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    total_span_seconds: Optional[float] = None


class EntityPivotGraph(BaseModel):
    """Case-bounded entity pivot showing adjacent relationships and records."""
    model_config = ConfigDict(extra="ignore")

    entity_key: str
    entity_type: str
    case_id: int
    connected_nodes: List[InvestigationGraphNode]
    connected_edges: List[InvestigationGraphEdge]
    related_alerts_count: int
    related_events_count: int
    related_findings_count: int
    timeline_occurrences_count: int


class GraphExplanationRequest(BaseModel):
    """Request payload for local AI graph explanation."""
    edge_id: Optional[str] = None
    path_nodes: Optional[List[str]] = None
    question: Optional[str] = None
    include_evidence_citations: bool = True


class GraphExplanationResponse(BaseModel):
    """Advisory-only local AI explanation of graph relationships."""
    model_config = ConfigDict(extra="ignore")

    explanation_id: str = Field(default_factory=lambda: f"gexp-{uuid.uuid4().hex[:8]}")
    case_id: int
    target_ref: str
    summary: str
    evidence_citations: List[str]
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    is_authoritative: bool = False
    generated_by: str = "LOCAL_AI_ADVISORY"
    generated_at: str
