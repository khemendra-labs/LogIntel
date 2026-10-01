"""Domain models for security incidents, entity graph nodes, and relationships (Milestone 3)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel, Field

from logintel.models.events import Severity


class IncidentStatus(str, Enum):
    """Operational lifecycle status of a security incident."""
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    CLOSED = "CLOSED"


# Valid state machine transitions for incidents
ALLOWED_INCIDENT_STATUS_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
    IncidentStatus.OPEN: {
        IncidentStatus.INVESTIGATING,
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
    },
    IncidentStatus.INVESTIGATING: {
        IncidentStatus.CONTAINED,
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
        IncidentStatus.OPEN,
    },
    IncidentStatus.CONTAINED: {
        IncidentStatus.RESOLVED,
        IncidentStatus.FALSE_POSITIVE,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.OPEN,
    },
    IncidentStatus.RESOLVED: {
        IncidentStatus.CLOSED,
        IncidentStatus.OPEN,  # Reopen
    },
    IncidentStatus.FALSE_POSITIVE: {
        IncidentStatus.CLOSED,
        IncidentStatus.OPEN,  # Reopen
    },
    IncidentStatus.CLOSED: {
        IncidentStatus.OPEN,  # Reopen
    },
}


class InvalidIncidentStatusTransitionError(ValueError):
    """Raised when an incident status transition violates the lifecycle state machine."""

    def __init__(self, from_status: IncidentStatus, to_status: IncidentStatus):
        super().__init__(
            f"Invalid incident status transition from '{from_status.value}' to '{to_status.value}'"
        )
        self.from_status = from_status
        self.to_status = to_status


class EntityType(str, Enum):
    """Normalized categorical taxonomy for entities extracted from security telemetry."""
    HOST = "HOST"
    USER = "USER"
    IP = "IP"
    PROCESS = "PROCESS"
    COMMAND = "COMMAND"
    FILE = "FILE"
    SESSION = "SESSION"


class ConfidenceLevel(str, Enum):
    """Deterministic, categorical confidence assessment for correlated relationships."""
    DIRECT = "DIRECT"          # Unbroken forensic proof (e.g. shared session ID or PID parent-child)
    STRONG = "STRONG"          # Deterministic identity match (e.g. same user and host in 120s)
    CORRELATED = "CORRELATED"  # Multi-stage sequence pattern match
    INFERRED = "INFERRED"      # Proximity match or contextual association
    WEAK = "WEAK"              # Coincidental temporal proximity without identity binding


class RelationshipType(str, Enum):
    """Canonical relationship semantics between entities and security alerts."""
    # Network & Authentication
    AUTHENTICATED_TO = "AUTHENTICATED_TO"
    ATTEMPTED_LOGIN = "ATTEMPTED_LOGIN"
    LOGGED_INTO = "LOGGED_INTO"
    DROPPED_BY_FIREWALL = "DROPPED_BY_FIREWALL"
    PROBED_PORT = "PROBED_PORT"
    CONNECTED_TO = "CONNECTED_TO"
    MATCHED_THREAT_IOC = "MATCHED_THREAT_IOC"

    # Execution & Privilege
    EXECUTED = "EXECUTED"
    SPAWNED = "SPAWNED"
    ELEVATED_PRIVILEGE = "ELEVATED_PRIVILEGE"
    ATTEMPTED_PRIVILEGE = "ATTEMPTED_PRIVILEGE"
    VIOLATED_MAC_POLICY = "VIOLATED_MAC_POLICY"
    CRASHED_PROCESS = "CRASHED_PROCESS"

    # Account Manipulation
    CREATED_ACCOUNT = "CREATED_ACCOUNT"
    DELETED_ACCOUNT = "DELETED_ACCOUNT"
    MODIFIED_ACCOUNT = "MODIFIED_ACCOUNT"

    # Security Alert & Incident Attribution
    ATTRIBUTED_TO = "ATTRIBUTED_TO"
    FLAGGED_ENTITY = "FLAGGED_ENTITY"

    # Attack Graph & Correlation Dynamics
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    ACCESSED_FILE = "ACCESSED_FILE"
    CO_OCCURRED = "CO_OCCURRED"


class TimelineItemType(str, Enum):
    """Type of chronological item presented in the unified investigation timeline."""
    MILESTONE = "MILESTONE"
    ALERT = "ALERT"
    EVENT = "EVENT"


class Incident(BaseModel):
    """Correlated security incident aggregating related alerts and corroborating events."""
    id: Optional[int] = None
    incident_key: str
    title: str
    summary: str
    severity: Severity = Severity.WARNING
    status: IncidentStatus = IncidentStatus.OPEN
    primary_host: str
    primary_user: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    alert_count: int = 0
    event_count: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None


class IncidentEntity(BaseModel):
    """Normalized entity node participating in an incident's attack graph."""
    id: Optional[int] = None
    incident_id: int
    entity_key: str
    entity_type: EntityType
    display_name: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IncidentRelationship(BaseModel):
    """Directed edge connecting entities with confidence and supporting evidence events."""
    id: Optional[int] = None
    incident_id: int
    source_entity_key: str
    target_entity_key: str
    relationship_type: str
    confidence: ConfidenceLevel = ConfidenceLevel.CORRELATED
    evidence_event_ids: List[str] = Field(default_factory=list)
    matched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class IncidentAlertLink(BaseModel):
    """Association linking an operational alert to a security incident."""
    id: Optional[int] = None
    incident_id: int
    alert_id: int
    added_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TimelineItem(BaseModel):
    """Unified chronological item for incident investigation stream."""
    id: str
    timestamp: datetime
    item_type: TimelineItemType
    title: str
    summary: str
    severity: Optional[Severity] = None
    entity_keys: List[str] = Field(default_factory=list)
    ref_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

    def sort_key(self) -> tuple[datetime, str]:
        """Deterministic tie-breaker key (timestamp ASC, id ASC)."""
        return (self.timestamp, self.id)
