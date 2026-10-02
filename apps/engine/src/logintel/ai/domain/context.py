"""Investigation context domain model for LogIntel AI assistance.

Represents a deterministic, evidence-grounded snapshot of an investigation
assembled from authoritative M4 repositories.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.citation import CitationManifest
from logintel.ai.domain.evidence import UntrustedTelemetryPayload


class ContextTier(str, Enum):
    """Hierarchical evidence priority tiers for context assembly."""

    TIER_1_DOSSIER = "Tier 1: Investigation Dossier"
    TIER_2_SUPPORTING_EVIDENCE = "Tier 2: Direct Supporting Evidence"
    TIER_3_ATTACK_PATH = "Tier 3: Attack Path Steps"
    TIER_4_CORRELATED_ALERTS = "Tier 4: Correlated Alerts"
    TIER_5_CORRELATED_ENTITIES = "Tier 5: Correlated Entities"
    TIER_6_ANALYST_NOTES = "Tier 6: Analyst Notes"
    TIER_7_CONTEXTUAL_EVENTS = "Tier 7: Contextual Telemetry"

    def __str__(self) -> str:
        return self.value


class TruncationMetadata(BaseModel):
    """Explicit disclosure of any evidence omitted due to context budget bounds."""

    model_config = ConfigDict(extra="forbid")

    is_truncated: bool = False
    omitted_events_count: int = 0
    omitted_alerts_count: int = 0
    omitted_entities_count: int = 0
    omitted_notes_count: int = 0
    truncation_reasons: List[str] = Field(default_factory=list)

    def add_omission(self, category: str, count: int, reason: str) -> None:
        if count <= 0:
            return
        self.is_truncated = True
        if category == "events":
            self.omitted_events_count += count
        elif category == "alerts":
            self.omitted_alerts_count += count
        elif category == "entities":
            self.omitted_entities_count += count
        elif category == "notes":
            self.omitted_notes_count += count
        self.truncation_reasons.append(reason)


class GenerationMetadata(BaseModel):
    """Metadata detailing the context generation execution (volatile generation layer)."""

    model_config = ConfigDict(extra="forbid")

    generated_at: str
    is_deterministic_seed: bool = False
    context_version: str = "1.0.0"


class InvestigationContext(BaseModel):
    """Structured, bounded context packet ready for local AI consumption.
    
    Maintains clean separation between authoritative evidence content and
    volatile generation metadata to guarantee bit-for-bit determinism.
    """

    model_config = ConfigDict(extra="forbid")

    context_version: str = "1.0.0"
    investigation_id: int
    generated_at: str
    generation_metadata: Optional[GenerationMetadata] = None

    # Tier 1: Investigation Dossier Header
    dossier_summary: Dict[str, Any]

    # Tier 2: Direct Supporting Evidence (Events that triggered detections/alerts)
    supporting_events: List[UntrustedTelemetryPayload] = Field(default_factory=list)

    # Tier 3: Attack Path Topological Steps
    attack_path_steps: List[Dict[str, Any]] = Field(default_factory=list)

    # Tier 4: Correlated Security Alerts
    alerts: List[Dict[str, Any]] = Field(default_factory=list)

    # Tier 5: Correlated Entities
    entities: List[Dict[str, Any]] = Field(default_factory=list)

    # Correlated Relationships (Edges)
    relationships: List[Dict[str, Any]] = Field(default_factory=list)

    # MITRE ATT&CK Mappings
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)

    # Tier 6: Non-Tombstoned Analyst Notes
    analyst_notes: List[Dict[str, Any]] = Field(default_factory=list)

    # Tier 7: Additional Contextual Events (Time-adjacent telemetry)
    contextual_events: List[UntrustedTelemetryPayload] = Field(default_factory=list)

    # Authoritative Citation Manifest
    citation_manifest: CitationManifest = Field(default_factory=CitationManifest)

    # Explicit Truncation Disclosures
    truncation: TruncationMetadata = Field(default_factory=TruncationMetadata)

    def canonical_content_dict(self, include_generated_at: bool = False) -> Dict[str, Any]:
        """Return canonical content dictionary, separating volatile generation metadata."""
        dumped = self.model_dump(mode="json")
        dumped.pop("generation_metadata", None)
        if not include_generated_at:
            dumped.pop("generated_at", None)
        return dumped

    def content_sha256(self, include_generated_at: bool = False) -> str:
        """Compute deterministic SHA-256 hash of canonical serialized context content."""
        import hashlib
        import json
        c_dict = self.canonical_content_dict(include_generated_at=include_generated_at)
        canonical_json = json.dumps(c_dict, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()

    @property
    def canonical_content_hash(self) -> str:
        """Return deterministic SHA-256 hash of canonical content."""
        return self.content_sha256(include_generated_at=False)

