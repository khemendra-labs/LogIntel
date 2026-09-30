"""Domain models for operational security alerts, detections, and evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from logintel.models.events import Severity


class EvidenceRole(str, Enum):
    """Role played by an event in satisfying a detection rule."""
    TRIGGER = "TRIGGER"       # The specific event that caused the rule condition/threshold to fire
    AGGREGATE = "AGGREGATE"   # An earlier event in the sliding window contributing to threshold count
    CONTEXT = "CONTEXT"       # Contextual event associated with the detection


class AlertStatus(str, Enum):
    """Operational status of a security investigation alert."""
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


# Valid state machine transitions
ALLOWED_STATUS_TRANSITIONS = {
    AlertStatus.OPEN: {AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE},
    AlertStatus.ACKNOWLEDGED: {AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE, AlertStatus.OPEN},
    AlertStatus.RESOLVED: {AlertStatus.OPEN},
    AlertStatus.FALSE_POSITIVE: {AlertStatus.OPEN},
}


class InvalidStatusTransitionError(ValueError):
    """Raised when an alert status transition violates the lifecycle state machine."""
    def __init__(self, from_status: AlertStatus, to_status: AlertStatus):
        super().__init__(f"Invalid alert status transition from '{from_status.value}' to '{to_status.value}'")
        self.from_status = from_status
        self.to_status = to_status


class Alert(BaseModel):
    """Operational security alert aggregating one or more rule detections."""
    id: Optional[int] = None
    rule_id: str
    dedup_key: str
    title: str
    description: str
    severity: Severity
    status: AlertStatus = AlertStatus.OPEN
    host: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    acknowledged_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    resolution_note: Optional[str] = None


class DetectionRecord(BaseModel):
    """Recorded occurrence of a rule match associated with an alert."""
    id: Optional[int] = None
    alert_id: int
    rule_id: str
    timestamp: datetime
    host: str
    summary: str
    evidence_count: int = 0
    details: Dict[str, Any] = Field(default_factory=dict)


class DetectionEvidenceRecord(BaseModel):
    """Evidence event associated with a detection."""
    id: Optional[int] = None
    detection_id: int
    event_id: str
    role: EvidenceRole = EvidenceRole.TRIGGER
    matched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
