"""Domain models for Milestone 7.6 Investigation Reporting, Evidence Package & Case Handoff.

Defines schemas for:
- 20 structured report sections
- Report lifecycle states (DRAFT -> REVIEW_READY -> UNDER_REVIEW -> FINALIZED -> SUPERSEDED)
- Content origin classifications
- Deterministic provenance manifests
- Evidence packages and package manifests
- Case handoff workflow and packet schemas
- Structured report version comparison
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ReportLifecycleStatus(str, Enum):
    """Deterministic report lifecycle states."""
    DRAFT = "DRAFT"
    REVIEW_READY = "REVIEW_READY"
    UNDER_REVIEW = "UNDER_REVIEW"
    FINALIZED = "FINALIZED"
    SUPERSEDED = "SUPERSEDED"


class ReportContentOrigin(str, Enum):
    """Origin classification for investigation report content elements."""
    AUTHORITATIVE_REFERENCE = "AUTHORITATIVE_REFERENCE"
    ANALYST_AUTHORED = "ANALYST_AUTHORED"
    SYSTEM_GENERATED = "SYSTEM_GENERATED"
    AI_GENERATED_DRAFT = "AI_GENERATED_DRAFT"
    DERIVED_SUMMARY = "DERIVED_SUMMARY"


class HandoffStatus(str, Enum):
    """Analyst-to-analyst case handoff operational lifecycle states."""
    NOT_READY = "NOT_READY"
    READY_FOR_HANDOFF = "READY_FOR_HANDOFF"
    HANDED_OFF = "HANDED_OFF"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RETURNED_FOR_FOLLOWUP = "RETURNED_FOR_FOLLOWUP"


class PackageLifecycleStatus(str, Enum):
    """Evidence package generation lifecycle states."""
    CREATING = "CREATING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class EvidenceGapCategory(str, Enum):
    """Forensic evidence gap classifications preserving non-negative epistemic boundaries."""
    NO_EVENT_OBSERVED = "NO_EVENT_OBSERVED"
    RULE_NOT_CONFIGURED = "RULE_NOT_CONFIGURED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    TELEMETRY_DROPPED = "TELEMETRY_DROPPED"
    UNKNOWN = "UNKNOWN"
    NOT_IN_SCOPE = "NOT_IN_SCOPE"
    NOT_EXECUTED = "NOT_EXECUTED"


# =============================================================================
# Provenance Manifest Models
# =============================================================================

class ProvenanceManifestEntry(BaseModel):
    """Cryptographic lineage record for an individual evidence reference included in a report."""
    model_config = ConfigDict(extra="forbid")

    source_type: str
    source_id: str
    citation_tag: str
    epistemic_status: str  # OBSERVED, INFERRED, UNKNOWN
    cryptographic_source_hash: str
    selection_reason: Optional[str] = None


class DeterministicProvenanceManifest(BaseModel):
    """Complete deterministic provenance manifest mapping all evidence references in a report version."""
    model_config = ConfigDict(extra="forbid")

    case_id: int
    report_id: str
    report_version: int
    generated_at: str
    total_references: int
    entries: List[ProvenanceManifestEntry] = Field(default_factory=list)
    manifest_blake2b_digest: str


# =============================================================================
# 20 Structured Report Sections
# =============================================================================

class CaseIdentificationSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    case_id: int
    title: str
    incident_id: int
    owner: str
    status: str
    case_version: int
    created_at: str
    updated_at: str


class InvestigationScopeSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hosts: List[str] = Field(default_factory=list)
    users: List[str] = Field(default_factory=list)
    ip_subnets: List[str] = Field(default_factory=list)
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    boundary_notes: Optional[str] = None


class ExecutiveSummarySection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    summary_text: str = ""
    content_origin: ReportContentOrigin = ReportContentOrigin.ANALYST_AUTHORED
    generated_by_model: Optional[str] = None


class InvestigationObjectiveSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    primary_objective: str = ""
    triggering_indicators: List[str] = Field(default_factory=list)


class EvidenceSourcesSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    sources_inspected: List[str] = Field(default_factory=list)  # auth.log, auditd, syslog, network
    total_telemetry_events_considered: int = 0


class EvidenceCollectionsSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    collections: List[Dict[str, Any]] = Field(default_factory=list)


class UnifiedTimelineSummarySection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    milestones: List[Dict[str, Any]] = Field(default_factory=list)
    earliest_observed_event: Optional[str] = None
    latest_observed_event: Optional[str] = None


class KeyFindingsSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    findings: List[Dict[str, Any]] = Field(default_factory=list)


class HypothesesSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)


class ThreatHuntingActivitySection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    hunts_executed: List[Dict[str, Any]] = Field(default_factory=list)


class EvidenceCorrelationSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    correlated_clusters: List[Dict[str, Any]] = Field(default_factory=list)
    multi_host_traces: List[Dict[str, Any]] = Field(default_factory=list)


class CaseAssessmentSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    assessment_state: Optional[str] = None
    closure_readiness: Optional[str] = None
    analyst_assessment_text: Optional[str] = None


class EvidenceGapsSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    gaps: List[Dict[str, Any]] = Field(default_factory=list)


class OutstandingQuestionsSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    questions: List[Dict[str, Any]] = Field(default_factory=list)


class AnalystInterpretationSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    interpretation_notes: str = ""
    author: str = "SecAnalyst-1"


class ConclusionSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    current_conclusion: str = ""
    requires_further_monitoring: bool = False


class LimitationsSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    limitations: List[str] = Field(default_factory=list)


class HandoffNotesSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    handoff_instructions: str = ""
    recommended_next_actions: List[str] = Field(default_factory=list)


class ReportMetadataSection(BaseModel):
    model_config = ConfigDict(extra="ignore")
    report_id: str
    case_id: int
    version: int
    lifecycle_status: ReportLifecycleStatus
    created_by: str
    created_at: str
    updated_at: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    blake2b_fingerprint: str = ""


# =============================================================================
# Complete Structured Investigation Report Model
# =============================================================================

class StructuredReport(BaseModel):
    """Complete 20-section structured forensic investigation report."""
    model_config = ConfigDict(extra="ignore")

    report_id: str
    case_id: int
    version: int = 1
    lifecycle_status: ReportLifecycleStatus = ReportLifecycleStatus.DRAFT
    created_by: str = "SecAnalyst-1"
    created_at: str
    updated_at: str
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None

    # 20 Typed Sections
    case_identification: CaseIdentificationSection
    investigation_scope: InvestigationScopeSection
    executive_summary: ExecutiveSummarySection
    investigation_objective: InvestigationObjectiveSection
    evidence_sources: EvidenceSourcesSection
    evidence_collections: EvidenceCollectionsSection
    unified_timeline_summary: UnifiedTimelineSummarySection
    key_findings: KeyFindingsSection
    hypotheses: HypothesesSection
    threat_hunting_activity: ThreatHuntingActivitySection
    evidence_correlation: EvidenceCorrelationSection
    case_assessment: CaseAssessmentSection
    evidence_gaps: EvidenceGapsSection
    outstanding_questions: OutstandingQuestionsSection
    analyst_interpretation: AnalystInterpretationSection
    conclusion: ConclusionSection
    limitations: LimitationsSection
    handoff_notes: HandoffNotesSection
    provenance_manifest: DeterministicProvenanceManifest
    metadata: ReportMetadataSection


# =============================================================================
# Evidence Package Models
# =============================================================================

class EvidencePackageManifest(BaseModel):
    """Deterministic manifest indexing all components of an evidence package."""
    model_config = ConfigDict(extra="forbid")

    package_id: str
    case_id: int
    report_id: str
    report_version: int
    created_by: str
    created_at: str
    status: PackageLifecycleStatus
    schema_version: str = "m7.6-package-v1"
    generator_version: str = "logintel-engine-0.1.0"
    included_artifacts: List[str] = Field(default_factory=list)
    source_reference_count: int
    package_blake2b_digest: str


class EvidencePackage(BaseModel):
    """Self-contained, deterministic forensic evidence package referencing case materials."""
    model_config = ConfigDict(extra="ignore")

    manifest: EvidencePackageManifest
    report_snapshot: StructuredReport
    artifacts_json: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Case Handoff Packet Models
# =============================================================================

class CaseHandoffPacket(BaseModel):
    """Operational case handoff package transferring investigative context between analysts."""
    model_config = ConfigDict(extra="ignore")

    handoff_id: str
    case_id: int
    report_id: str
    report_version: int
    status: HandoffStatus = HandoffStatus.READY_FOR_HANDOFF
    prepared_by: str
    prepared_at: str
    handed_off_to: Optional[str] = None
    handed_off_at: Optional[str] = None
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[str] = None
    return_reason: Optional[str] = None

    investigated_scope_summary: str
    observed_facts_count: int
    active_hypotheses_count: int
    evidence_gaps_count: int
    outstanding_questions: List[str] = Field(default_factory=list)
    recommended_next_actions: List[str] = Field(default_factory=list)
    operational_notes: Optional[str] = None


# =============================================================================
# Request and Comparison Models
# =============================================================================

class CreateReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=256)
    objective: Optional[str] = Field(default="", max_length=1000)
    selected_evidence_ids: List[str] = Field(default_factory=list, max_length=1000)
    selected_collection_ids: List[str] = Field(default_factory=list, max_length=100)
    selected_finding_ids: List[str] = Field(default_factory=list, max_length=100)
    selected_hypothesis_ids: List[str] = Field(default_factory=list, max_length=100)
    selected_hunt_ids: List[str] = Field(default_factory=list, max_length=100)
    analyst_notes: Optional[str] = Field(default=None, max_length=4000)


class UpdateReportDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(default=None, min_length=1, max_length=256)
    executive_summary: Optional[str] = Field(default=None, max_length=8000)
    analyst_interpretation: Optional[str] = Field(default=None, max_length=8000)
    conclusion: Optional[str] = Field(default=None, max_length=4000)
    handoff_instructions: Optional[str] = Field(default=None, max_length=4000)
    recommended_next_actions: Optional[List[str]] = Field(default=None, max_length=50)
    limitations: Optional[List[str]] = Field(default=None, max_length=50)


class SubmitReportReviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    review_notes: Optional[str] = Field(default=None, max_length=2000)


class FinalizeReportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finalization_notes: Optional[str] = Field(default=None, max_length=2000)
    reviewed_by: str = Field(..., min_length=1, max_length=100)


class ReportComparisonSectionDiff(BaseModel):
    section_name: str
    status: str  # IDENTICAL, MODIFIED, ADDED, REMOVED
    details: Dict[str, Any] = Field(default_factory=dict)


class ReportComparisonResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    case_id: int
    report_id: str
    version_older: int
    version_newer: int
    compared_at: str
    differences_count: int
    section_diffs: List[ReportComparisonSectionDiff] = Field(default_factory=list)
    older_fingerprint: str
    newer_fingerprint: str


class CreateEvidencePackageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_version: Optional[int] = None
    package_notes: Optional[str] = Field(default=None, max_length=1000)


class PrepareHandoffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    report_version: Optional[int] = None
    target_operator: str = Field(..., min_length=1, max_length=100)
    operational_notes: Optional[str] = Field(default=None, max_length=4000)
    recommended_next_actions: List[str] = Field(default_factory=list, max_length=50)


class AcknowledgeHandoffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    acknowledgement_notes: Optional[str] = Field(default=None, max_length=2000)


class ReturnHandoffRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    return_reason: str = Field(..., min_length=1, max_length=2000)


class AIReportDraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    section_to_draft: str = Field(default="executive_summary", max_length=100)
    custom_guidance: Optional[str] = Field(default=None, max_length=2000)


class ReportExportResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    case_id: int
    report_id: str
    version: int
    format: str  # json, csv, markdown
    content: str
    fingerprint: str
    exported_at: str
