"""Domain models and schemas for Milestone 5.10 Temporal Investigation Reconstruction.

Defines schemas for:
- Temporal Evidence Models & Reconstructions
- Deterministic Temporal Episodes (neutral, evidence-derived episode categories)
- Episode & Entity Transitions with explicit epistemic status (OBSERVED / INFERRED / UNKNOWN)
- Multi-Step Temporal Evidence Chains linking events, relationships, and entities
- Temporal & Telemetry Gap Intelligence
- Multi-Host Movement Reconstruction
- Account, Process, and Network Continuity
- Deterministic Campaign-Level Correlation across incidents (non-probabilistic)
- Attack Sequence Reconstruction with MITRE ATT&CK integration
- Transition Analyst Review tracking (epistemic status vs review state independence)
- Temporal Reconstructions Export (JSON, CSV, GraphML)
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from logintel.ai.domain.investigation_graph import CorroborationStatus, GraphEvidenceItem
from logintel.ai.domain.investigation_intel import EpistemicStatus, QueryProposal


class EpisodeType(str, Enum):
    """Categorical classification of evidence-derived temporal episodes."""
    AUTHENTICATION_BURST = "AUTHENTICATION_BURST"
    PROCESS_EXECUTION_EPISODE = "PROCESS_EXECUTION_EPISODE"
    PRIVILEGE_CHANGE_EPISODE = "PRIVILEGE_CHANGE_EPISODE"
    LATERAL_MOVEMENT_EPISODE = "LATERAL_MOVEMENT_EPISODE"
    NETWORK_ACTIVITY_EPISODE = "NETWORK_ACTIVITY_EPISODE"
    PERSISTENCE_EPISODE = "PERSISTENCE_EPISODE"
    GENERIC_EPISODE = "GENERIC_EPISODE"


class TransitionType(str, Enum):
    """Type of entity or episode progression transition."""
    USER_TO_HOST = "USER_TO_HOST"
    HOST_TO_HOST = "HOST_TO_HOST"
    USER_TO_PROCESS = "USER_TO_PROCESS"
    PROCESS_TO_NETWORK_DESTINATION = "PROCESS_TO_NETWORK_DESTINATION"
    PROCESS_TO_FILE = "PROCESS_TO_FILE"
    ALERT_TO_INCIDENT = "ALERT_TO_INCIDENT"
    INCIDENT_TO_ENTITY = "INCIDENT_TO_ENTITY"
    STAGE_PROGRESSION = "STAGE_PROGRESSION"
    SESSION_HANDOFF = "SESSION_HANDOFF"


class TemporalGapType(str, Enum):
    """Specific telemetry visibility or temporal discontinuity gap."""
    NO_TELEMETRY = "NO_TELEMETRY"
    MISSING_HOST_VISIBILITY = "MISSING_HOST_VISIBILITY"
    MISSING_PROCESS_TELEMETRY = "MISSING_PROCESS_TELEMETRY"
    MISSING_NETWORK_TELEMETRY = "MISSING_NETWORK_TELEMETRY"
    TIMESTAMP_GAP = "TIMESTAMP_GAP"
    UNRESOLVED_TRANSITION = "UNRESOLVED_TRANSITION"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class CampaignCorrelationStatus(str, Enum):
    """Categorical, non-probabilistic relationship between incidents."""
    POTENTIALLY_RELATED = "POTENTIALLY_RELATED"
    CORRELATED = "CORRELATED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNRELATED = "UNRELATED"


class CampaignRelationReason(str, Enum):
    """Explicit, inspectable justification for linking incidents."""
    SHARED_ENTITY = "SHARED_ENTITY"
    SHARED_ACCOUNT = "SHARED_ACCOUNT"
    SHARED_SOURCE = "SHARED_SOURCE"
    SHARED_DESTINATION = "SHARED_DESTINATION"
    TEMPORAL_PROXIMITY = "TEMPORAL_PROXIMITY"
    COMMON_SEQUENCE = "COMMON_SEQUENCE"
    COMMON_EVIDENCE = "COMMON_EVIDENCE"
    COMMON_TECHNIQUE = "COMMON_TECHNIQUE"


class TransitionReviewState(str, Enum):
    """Independent analyst review status for reconstructed transitions."""
    UNREVIEWED = "UNREVIEWED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    DISPUTED = "DISPUTED"


class ContinuityType(str, Enum):
    """Type of entity continuity observed across investigative bounds."""
    SAME_ACCOUNT_ACROSS_HOSTS = "SAME_ACCOUNT_ACROSS_HOSTS"
    SAME_PROCESS_LINEAGE = "SAME_PROCESS_LINEAGE"
    SAME_SOURCE_IP = "SAME_SOURCE_IP"
    SAME_DESTINATION = "SAME_DESTINATION"
    SAME_ENTITY_MULTIPLE_INCIDENTS = "SAME_ENTITY_MULTIPLE_INCIDENTS"


class TemporalEpisode(BaseModel):
    """A discrete temporal grouping of related forensic records, detections, and alerts."""
    model_config = ConfigDict(extra="ignore")

    episode_id: str = Field(default_factory=lambda: f"ep-{uuid.uuid4().hex[:8]}")
    case_id: int
    episode_type: EpisodeType
    title: str
    summary: str
    start_time: str
    end_time: str
    duration_seconds: float
    entities: List[str] = Field(default_factory=list)
    evidence_references: List[GraphEvidenceItem] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    corroboration_status: CorroborationStatus = CorroborationStatus.DIRECT_EVIDENCE


class TemporalTransition(BaseModel):
    """Evidence-grounded directional progression between entities or temporal episodes."""
    model_config = ConfigDict(extra="ignore")

    transition_id: str = Field(default_factory=lambda: f"trans-{uuid.uuid4().hex[:8]}")
    case_id: int
    transition_type: TransitionType
    from_entity: str
    to_entity: str
    from_episode_id: Optional[str] = None
    to_episode_id: Optional[str] = None
    timestamp: str
    reason: str
    correlation_basis: str = "Deterministic temporal and relational evidence"
    evidence_references: List[GraphEvidenceItem] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    review_state: TransitionReviewState = TransitionReviewState.UNREVIEWED
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[str] = None
    review_notes: Optional[str] = None


class EvidenceChainStep(BaseModel):
    """Discrete step in a multi-hop temporal evidence chain."""
    model_config = ConfigDict(extra="ignore")

    step_index: int
    source_record_type: str
    source_record_id: str
    citation_tag: str
    timestamp: str
    entity_key: str
    action_or_relation: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED


class TemporalEvidenceChain(BaseModel):
    """Traceable evidence chain connecting records, entities, and transitions."""
    model_config = ConfigDict(extra="ignore")

    chain_id: str = Field(default_factory=lambda: f"chain-{uuid.uuid4().hex[:8]}")
    case_id: int
    name: str
    description: str
    steps: List[EvidenceChainStep] = Field(default_factory=list)
    total_steps: int
    start_time: str
    end_time: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED


class TemporalGap(BaseModel):
    """Explicit temporal or telemetry gap identified in the investigation."""
    model_config = ConfigDict(extra="ignore")

    gap_id: str = Field(default_factory=lambda: f"tgap-{uuid.uuid4().hex[:8]}")
    case_id: int
    gap_type: TemporalGapType
    title: str
    description: str
    affected_entities: List[str] = Field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: Optional[float] = None
    remedy: str
    governed_hunt_proposal: Optional[QueryProposal] = None


class MultiHostTrace(BaseModel):
    """Cross-host movement reconstruction preserving host identity and timestamps."""
    model_config = ConfigDict(extra="ignore")

    trace_id: str = Field(default_factory=lambda: f"mhost-{uuid.uuid4().hex[:8]}")
    case_id: int
    source_host: str
    target_host: str
    actor: str
    hop_count: int
    transitions: List[TemporalTransition] = Field(default_factory=list)
    evidence_references: List[GraphEvidenceItem] = Field(default_factory=list)
    start_time: str
    end_time: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED


class EntityContinuity(BaseModel):
    """Continuity of accounts, processes, or network addresses across episodes."""
    model_config = ConfigDict(extra="ignore")

    continuity_id: str = Field(default_factory=lambda: f"cont-{uuid.uuid4().hex[:8]}")
    case_id: int
    continuity_type: ContinuityType
    entity_key: str
    occurrences_count: int
    participating_hosts: List[str] = Field(default_factory=list)
    evidence_references: List[GraphEvidenceItem] = Field(default_factory=list)
    description: str


class IncidentCampaignCorrelation(BaseModel):
    """Categorical, deterministic campaign-level correlation between incidents."""
    model_config = ConfigDict(extra="ignore")

    correlation_id: str = Field(default_factory=lambda: f"camp-{uuid.uuid4().hex[:8]}")
    primary_incident_id: int
    related_incident_id: int
    related_incident_title: str
    relationship_reason: CampaignRelationReason
    correlation_status: CampaignCorrelationStatus
    shared_entities: List[str] = Field(default_factory=list)
    shared_evidence_count: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    summary: str


class AttackSequenceStep(BaseModel):
    """A discrete chronological step in an attack sequence reconstruction."""
    model_config = ConfigDict(extra="ignore")

    step_number: int
    timestamp: str
    stage_name: str
    entity: str
    evidence_citation: str
    reason: str
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    rule_id: Optional[str] = None


class AttackSequenceReconstruction(BaseModel):
    """Evidence-bound temporal attack sequence reconstruction."""
    model_config = ConfigDict(extra="ignore")

    sequence_id: str = Field(default_factory=lambda: f"atkseq-{uuid.uuid4().hex[:8]}")
    case_id: int
    name: str
    description: str
    steps: List[AttackSequenceStep] = Field(default_factory=list)
    total_steps: int
    start_time: str
    end_time: str
    duration_seconds: float
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED


class TemporalReconstructionDossier(BaseModel):
    """Comprehensive investigation temporal reconstruction combining all dimensions."""
    model_config = ConfigDict(extra="ignore")

    reconstruction_id: str = Field(default_factory=lambda: f"recon-{uuid.uuid4().hex[:8]}")
    case_id: int
    incident_id: int
    generated_at: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    episodes: List[TemporalEpisode] = Field(default_factory=list)
    transitions: List[TemporalTransition] = Field(default_factory=list)
    evidence_chains: List[TemporalEvidenceChain] = Field(default_factory=list)
    gaps: List[TemporalGap] = Field(default_factory=list)
    multi_host_traces: List[MultiHostTrace] = Field(default_factory=list)
    continuities: List[EntityContinuity] = Field(default_factory=list)
    campaign_correlations: List[IncidentCampaignCorrelation] = Field(default_factory=list)
    attack_sequences: List[AttackSequenceReconstruction] = Field(default_factory=list)
    mitre_summary: List[Dict[str, Any]] = Field(default_factory=list)
    provenance_hash: str  # sha256:hex64


class TemporalExplanationResponse(BaseModel):
    """Advisory-only local AI explanation of a temporal reconstruction or transition."""
    model_config = ConfigDict(extra="ignore")

    explanation_id: str = Field(default_factory=lambda: f"txp-{uuid.uuid4().hex[:8]}")
    case_id: int
    target_id: str  # transition_id, episode_id, or reconstruction_id
    explanation_text: str
    is_authoritative: bool = False
    generated_by: str = "LOCAL_AI_ADVISORY"
    referenced_citations: List[str] = Field(default_factory=list)
    epistemic_status: EpistemicStatus = EpistemicStatus.INFERRED
    generated_at: str
