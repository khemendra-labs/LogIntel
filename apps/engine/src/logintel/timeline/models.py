"""Domain models and schemas for Milestone 7.2 Unified Timeline & Replay.

Defines schemas for:
- Timestamp precision and deterministic ordering
- Multi-layer telemetry classification
- Epistemic status (OBSERVED / INFERRED / UNKNOWN)
- Collection status semantics
- Unified investigation timeline items with explicit provenance
- Deterministic replay frames and sessions
- Case-scoped timeline filters
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class TimestampPrecision(str, Enum):
    """Temporal precision of the originating telemetry source."""
    SECOND = "SECOND"
    MILLISECOND = "MILLISECOND"
    UNKNOWN = "UNKNOWN"


class EpistemicStatus(str, Enum):
    """Epistemic certainty status of timeline items."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class CollectionStatus(str, Enum):
    """Source collection visibility semantics from M6."""
    SOURCE_AVAILABLE = "SOURCE_AVAILABLE"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    RULE_NOT_CONFIGURED = "RULE_NOT_CONFIGURED"
    NO_EVENT_OBSERVED = "NO_EVENT_OBSERVED"
    TELEMETRY_DROPPED = "TELEMETRY_DROPPED"
    UNKNOWN = "UNKNOWN"


class TimelineSourceLayer(str, Enum):
    """Multi-layer telemetry categories encompassing M1-M6."""
    AUTH = "AUTH"
    PROCESS = "PROCESS"
    NETWORK = "NETWORK"
    FILESYSTEM = "FILESYSTEM"
    SYSTEMD = "SYSTEMD"
    KERNEL = "KERNEL"
    CONTAINER = "CONTAINER"
    ALERT = "ALERT"
    DETECTION = "DETECTION"
    INCIDENT = "INCIDENT"
    CORRELATION = "CORRELATION"
    ANALYST_NOTE = "ANALYST_NOTE"


class InvestigationTimelineItem(BaseModel):
    """Unified evidence-grounded investigation timeline item."""
    model_config = ConfigDict(extra="ignore")

    timeline_id: str
    case_id: int
    timestamp: str
    timestamp_precision: TimestampPrecision = TimestampPrecision.SECOND
    host_id: str
    layer: TimelineSourceLayer
    event_type: str
    source_type: str
    source_id: str
    title: str
    display_summary: str
    entity_refs: List[str] = Field(default_factory=list)
    relationship_refs: List[str] = Field(default_factory=list)
    detection_refs: List[str] = Field(default_factory=list)
    incident_refs: List[int] = Field(default_factory=list)
    evidence_refs: List[str] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    collection_status: CollectionStatus = CollectionStatus.SOURCE_AVAILABLE
    provenance: str
    is_bookmarked: bool = False
    bookmark_notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TimelineFilterParams(BaseModel):
    """Strictly validated and bounded case timeline query parameters."""
    model_config = ConfigDict(extra="ignore")

    time_start: Optional[str] = None
    time_end: Optional[str] = None
    host: Optional[str] = None
    layer: Optional[str] = None
    event_type: Optional[str] = None
    source: Optional[str] = None
    entity: Optional[str] = None
    epistemic_status: Optional[EpistemicStatus] = None
    collection_status: Optional[CollectionStatus] = None
    bookmarked_only: bool = False
    search: Optional[str] = Field(default=None, max_length=200)
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class TimelineReplayFrame(BaseModel):
    """Deterministic step in interactive investigation replay."""
    model_config = ConfigDict(extra="ignore")

    frame_index: int
    timeline_id: str
    timestamp: str
    title: str
    layer: TimelineSourceLayer
    epistemic_status: EpistemicStatus
    active_entities: List[str] = Field(default_factory=list)
    active_hosts: List[str] = Field(default_factory=list)
    is_evidence: bool = False
    cumulative_counts: Dict[str, int] = Field(default_factory=dict)


class TimelineReplaySession(BaseModel):
    """Complete deterministic session context for frontend replay controller."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    total_items: int
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    time_span_seconds: float = 0.0
    items: List[InvestigationTimelineItem] = Field(default_factory=list)
    frames: List[TimelineReplayFrame] = Field(default_factory=list)
    entity_index: Dict[str, List[str]] = Field(default_factory=dict)
    host_index: Dict[str, List[str]] = Field(default_factory=dict)
    evidence_index: Dict[str, str] = Field(default_factory=dict)
    epistemic_breakdown: Dict[str, int] = Field(default_factory=dict)
    layer_breakdown: Dict[str, int] = Field(default_factory=dict)
    provenance_fingerprint: str


class TimelineContextResponse(BaseModel):
    """Synchronized context linking a timeline event to graph, evidence, and raw source."""
    model_config = ConfigDict(extra="ignore")

    item: InvestigationTimelineItem
    related_graph_nodes: List[str] = Field(default_factory=list)
    related_evidence: List[str] = Field(default_factory=list)
    source_record: Dict[str, Any] = Field(default_factory=dict)


class TimelineQueryResponse(BaseModel):
    """Paginated timeline query response with layer and epistemic metrics."""
    model_config = ConfigDict(extra="ignore")

    items: List[InvestigationTimelineItem]
    total: int
    limit: int
    offset: int
    epistemic_breakdown: Dict[str, int] = Field(default_factory=dict)
    layer_breakdown: Dict[str, int] = Field(default_factory=dict)
