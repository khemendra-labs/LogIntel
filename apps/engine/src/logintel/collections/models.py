from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field

from logintel.timeline.models import EpistemicStatus, CollectionStatus


class EvidenceCollectionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class EvidenceItemRole(str, Enum):
    INITIAL_ACCESS = "INITIAL_ACCESS"
    EXECUTION = "EXECUTION"
    PERSISTENCE = "PERSISTENCE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    DEFENSE_EVASION = "DEFENSE_EVASION"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    DISCOVERY = "DISCOVERY"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    COLLECTION = "COLLECTION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    EXFILTRATION = "EXFILTRATION"
    IMPACT = "IMPACT"
    SUPPORTING = "SUPPORTING"
    CONTRADICTING = "CONTRADICTING"
    NEUTRAL = "NEUTRAL"


class EvidenceCollectionItem(BaseModel):
    item_id: str
    collection_id: str
    case_id: int
    source_type: str
    source_id: str
    role: str = "SUPPORTING"
    epistemic_status: EpistemicStatus = EpistemicStatus.OBSERVED
    collection_status: CollectionStatus = CollectionStatus.SOURCE_AVAILABLE
    citation_tag: str
    analyst_annotation: Optional[str] = None
    order_index: int = 0
    added_at: str
    added_by: str = "SecAnalyst-1"
    host_id: Optional[str] = None
    event_type: Optional[str] = None
    timestamp: Optional[str] = None
    display_summary: Optional[str] = None
    provenance: dict[str, Any] = Field(default_factory=dict)


class EvidenceCollection(BaseModel):
    collection_id: str
    case_id: int
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    status: EvidenceCollectionStatus = EvidenceCollectionStatus.ACTIVE
    tags: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    created_by: str = "SecAnalyst-1"
    items_count: int = 0
    items: list[EvidenceCollectionItem] = Field(default_factory=list)


class CreateCollectionRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    tags: Optional[list[str]] = Field(default=None)


class UpdateCollectionRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    description: Optional[str] = Field(default=None, max_length=512)
    status: Optional[EvidenceCollectionStatus] = None
    tags: Optional[list[str]] = None


class AddCollectionItemRequest(BaseModel):
    source_type: str = Field(..., min_length=1, max_length=64)
    source_id: str = Field(..., min_length=1, max_length=128)
    role: Optional[str] = Field(default="SUPPORTING", max_length=64)
    epistemic_status: Optional[EpistemicStatus] = EpistemicStatus.OBSERVED
    citation_tag: Optional[str] = Field(default=None, max_length=128)
    analyst_annotation: Optional[str] = Field(default=None, max_length=1024)


class UpdateCollectionItemRequest(BaseModel):
    role: Optional[str] = Field(default=None, max_length=64)
    analyst_annotation: Optional[str] = Field(default=None, max_length=1024)
    order_index: Optional[int] = None


class CollectionFilterParams(BaseModel):
    status: Optional[EvidenceCollectionStatus] = None
    search_text: Optional[str] = Field(default=None, max_length=512)
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class WorkbenchFilterParams(BaseModel):
    collection_id: Optional[str] = Field(default=None, max_length=128)
    source_type: Optional[str] = Field(default=None, max_length=64)
    epistemic_status: Optional[EpistemicStatus] = None
    host: Optional[str] = Field(default=None, max_length=128)
    search_text: Optional[str] = Field(default=None, max_length=512)
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class EvidenceWorkbenchResponse(BaseModel):
    case_id: int
    total_evidence_count: int
    collections: list[EvidenceCollection]
    items: list[EvidenceCollectionItem]
    filter_applied: dict[str, Any]
    deterministic_hash: str


class CollectionExportResponse(BaseModel):
    case_id: int
    collection_id: str
    name: str
    description: Optional[str]
    tags: list[str]
    exported_at: str
    items: list[dict[str, Any]]
    export_sha256: str
