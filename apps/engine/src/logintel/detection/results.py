"""In-memory detection results and evidence models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


from logintel.models.alerts import EvidenceRole


class EvidenceItem(BaseModel):
    """Reference to a canonical event cited as evidence for a detection."""
    event_id: str
    role: EvidenceRole = EvidenceRole.TRIGGER
    matched_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DetectionResult(BaseModel):
    """Deterministic in-memory result produced when an atomic or threshold rule matches."""
    rule_id: str
    timestamp: datetime
    host: str
    summary: str
    evidence_event_ids: List[str]
    evidence_roles: Dict[str, EvidenceRole] = Field(default_factory=dict)
    details: Dict[str, Any] = Field(default_factory=dict)

    def get_trigger_event_id(self) -> Optional[str]:
        """Return the event ID that served as the trigger, if any."""
        for ev_id, role in self.evidence_roles.items():
            if role == EvidenceRole.TRIGGER:
                return ev_id
        return self.evidence_event_ids[-1] if self.evidence_event_ids else None
