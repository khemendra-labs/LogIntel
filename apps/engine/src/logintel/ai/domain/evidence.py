"""Evidence reference and untrusted telemetry domain models.

Provides typed pointers to authoritative forensic records without duplicating
entire database tables, and marks raw log payloads as untrusted data.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EvidenceType(str, Enum):
    """Enumeration of all supported authoritative evidence categories."""

    EVENT = "event"
    DETECTION = "detection"
    ALERT = "alert"
    INCIDENT = "incident"
    ENTITY = "entity"
    RELATIONSHIP = "relationship"
    ATTACK_PATH_STEP = "step"
    TIMELINE_STEP = "step"
    MITRE = "mitre"
    MITRE_MAPPING = "mitre"
    NOTE = "note"

    def __str__(self) -> str:
        return self.value


class EvidenceTrustLevel(str, Enum):
    """Trust classification for data ingested into AI context."""

    UNTRUSTED_FORENSIC_DATA = "UNTRUSTED_FORENSIC_DATA"
    VERIFIED_M4_METADATA = "VERIFIED_M4_METADATA"


class EvidenceRef(BaseModel):
    """Lightweight typed pointer to an authoritative evidence object."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_type: EvidenceType
    evidence_id: str = Field(..., min_length=1, max_length=256)
    citation_tag: Optional[str] = Field(None, max_length=256)
    canonical_key: Optional[str] = Field(None, max_length=512)
    description: Optional[str] = Field(None, max_length=1024)

    @field_validator("evidence_id")
    @classmethod
    def validate_id_not_blank(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("evidence_id cannot be blank")
        return cleaned

    @property
    def canonical_tag(self) -> str:
        """Return the standard bracketed tag representation, e.g. [event:evt-101]."""
        return f"[{self.evidence_type.value}:{self.evidence_id}]"


class UntrustedTelemetryPayload(BaseModel):
    """Container for raw or normalized telemetry marked strictly as untrusted forensic data.
    
    Preserves authoritative raw log messages byte-for-byte without mutation.
    Untrusted classification is enforced via trust_level, not payload modification.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(..., min_length=1)
    timestamp: str
    host: str
    source: str
    event_type: str
    severity: str
    outcome: str
    raw_message: str
    fingerprint: str
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.UNTRUSTED_FORENSIC_DATA
