"""Domain models for Milestone 7.12 Multi-Host Investigation.

Defines schemas for:
- CaseHostSummary: Case-scoped summary of a participating host with metadata, counts,
  timestamps, lateral hops, visibility gaps, and source evidence.
- HostVisibilityGap: Explicitly recorded telemetry visibility and collection limitations.
- HostDiscrepancy: Conflicting host identity, naming, or attributes across sources.
- CaseMultiHostDossier: Unified case-scoped multi-host dossier preserving forensic invariants.
- HostTimelineResponse: Host-scoped timeline projection response.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.investigation_temporal import EntityContinuity, MultiHostTrace
from logintel.timeline.models import InvestigationTimelineItem


class HostEpistemicStatus(str, Enum):
    """Forensic epistemic boundary for host existence and attribution."""
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class HostDiscrepancy(BaseModel):
    """Explicitly recorded discrepancy between host identity sources."""
    model_config = ConfigDict(extra="ignore")

    field: str = Field(description="Name of the attribute with conflicting values")
    catalog_value: Optional[str] = Field(default=None, description="Value from authoritative host catalog (logintel.db:hosts)")
    telemetry_value: Optional[str] = Field(default=None, description="Value observed in telemetry events or alerts")
    sources: List[str] = Field(default_factory=list, description="Source identifiers reporting conflicting data")
    description: str = Field(description="Clear explanation of the detected conflict")


class HostVisibilityGap(BaseModel):
    """Identified observability or telemetry visibility limitation for a host."""
    model_config = ConfigDict(extra="ignore")

    gap_type: str = Field(description="Categorical gap identifier (e.g. MISSING_HOST_CATALOG_ENTRY, TARGET_HOST_TELEMETRY_ABSENT, TELEMETRY_SILENCE)")
    host_identifier: str = Field(description="Host identifier or hostname affected by this visibility gap")
    description: str = Field(description="Factual statement describing the missing telemetry or visibility boundary")
    remedy_suggestion: Optional[str] = Field(default=None, description="Governed recommendation for analyst review")


class CaseHostSummary(BaseModel):
    """Deterministic, case-scoped view of a participating host."""
    model_config = ConfigDict(extra="ignore")

    host_id: str = Field(description="Stable primary host identifier")
    hostname: str = Field(description="Display or catalog hostname, distinguished from host_id")
    os_name: Optional[str] = Field(default=None, description="Authoritative OS name from logintel.db:hosts if present; None if unavailable")
    os_version: Optional[str] = Field(default=None, description="Authoritative OS version from logintel.db:hosts if present; None if unavailable")
    is_in_target_scope: bool = Field(default=False, description="True if explicitly specified in investigation scope target_hosts")
    first_seen: Optional[str] = Field(default=None, description="Earliest ISO-8601 timestamp observed for this host in case evidence")
    last_seen: Optional[str] = Field(default=None, description="Latest ISO-8601 timestamp observed for this host in case evidence")
    event_count: int = Field(default=0, description="Authoritative event count associated with this host in case bounds")
    alert_count: int = Field(default=0, description="Authoritative alert count associated with this host in case bounds")
    inbound_lateral_hops: int = Field(default=0, description="Count of inbound lateral movement hops targeting this host")
    outbound_lateral_hops: int = Field(default=0, description="Count of outbound lateral movement hops originating from this host")
    evidence_references: List[str] = Field(default_factory=list, description="Sorted citation tags of evidence referencing this host")
    telemetry_gaps: List[HostVisibilityGap] = Field(default_factory=list, description="Explicit visibility gaps identified for this host")
    discrepancies: List[HostDiscrepancy] = Field(default_factory=list, description="Identity or attribute discrepancies detected across sources")
    host_graph_available: bool = Field(default=False, description="True if host attack graph can be generated from available telemetry")
    epistemic_status: HostEpistemicStatus = Field(default=HostEpistemicStatus.OBSERVED, description="Epistemic demarcation: OBSERVED, INFERRED, or UNKNOWN")


class CaseMultiHostDossier(BaseModel):
    """Case-scoped multi-host dossier assembling authoritative evidence across participating hosts."""
    model_config = ConfigDict(extra="ignore")

    case_id: int = Field(description="Case identifier")
    incident_id: Optional[int] = Field(default=None, description="Associated incident identifier if linked")
    scope_target_hosts: List[str] = Field(default_factory=list, description="Explicit target hosts configured in scope. Empty means unspecified/dynamic.")
    is_scope_unspecified: bool = Field(default=False, description="True when scope target_hosts was empty, meaning all participating hosts are included")
    participating_hosts: List[CaseHostSummary] = Field(default_factory=list, description="Deterministically sorted list of participating hosts")
    lateral_traces: List[MultiHostTrace] = Field(default_factory=list, description="Reconstructed lateral movement traces between hosts")
    entity_continuity: List[EntityContinuity] = Field(default_factory=list, description="Cross-host user, process, or network continuity records")
    total_hosts_count: int = Field(default=0, description="Total number of participating hosts")
    scoped_hosts_count: int = Field(default=0, description="Number of participating hosts matching explicit scope")
    cross_host_hops_count: int = Field(default=0, description="Total count of reconstructed lateral hops")
    overall_visibility_gaps: List[HostVisibilityGap] = Field(default_factory=list, description="Overall case-level visibility and collection limitations")
    completeness_limitations: List[str] = Field(default_factory=list, description="Explicit boundary statements regarding telemetry completeness")
    generated_at: str = Field(description="ISO-8601 generation timestamp")
    provenance_hash: str = Field(description="Deterministic SHA-256 fingerprint over the dossier content")


class HostTimelineResponse(BaseModel):
    """Host-scoped unified timeline projection."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    host_id: str
    hostname: str
    items: List[InvestigationTimelineItem] = Field(default_factory=list)
    total: int = 0
    limit: int = 100
    offset: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    epistemic_breakdown: Dict[str, int] = Field(default_factory=dict)
    layer_breakdown: Dict[str, int] = Field(default_factory=dict)


class HostTimelineLane(BaseModel):
    """Synchronized timeline projection lane for an individual host (M7.12.4)."""
    model_config = ConfigDict(extra="ignore")

    host_id: str
    hostname: str
    items: List[InvestigationTimelineItem] = Field(default_factory=list)
    total: int = 0
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


class ComparativeTimelineResponse(BaseModel):
    """Multi-host comparative timeline projection across synchronized host lanes (M7.12.4)."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    time_start: Optional[str] = None
    time_end: Optional[str] = None
    lanes: List[HostTimelineLane] = Field(default_factory=list)
    total_events: int = 0
    aligned_min_time: Optional[str] = None
    aligned_max_time: Optional[str] = None


class MultiHostExportResponse(BaseModel):
    """Case-scoped multi-host dossier export payload (M7.12.5)."""
    model_config = ConfigDict(extra="ignore")

    case_id: int
    format: str
    filename: str
    content: str
    root_digest: str

