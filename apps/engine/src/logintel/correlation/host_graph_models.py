"""Unified Linux Host Graph and Causal Telemetry Models (Milestone M6.8).

Represents multi-layer host entities (processes, users, files, sockets, containers, services)
and their causal relationships (spawned, executed, connected_to, accessed_file, contained_in).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field

from logintel.models.incidents import ConfidenceLevel, EntityType, IncidentEntity, IncidentRelationship


class HostNodeType(str, Enum):
    """Categorical node types for the Unified Linux Host Graph."""
    HOST = "HOST"
    USER = "USER"
    IP = "IP"
    PROCESS = "PROCESS"
    COMMAND = "COMMAND"
    FILE = "FILE"
    SESSION = "SESSION"
    CONTAINER = "CONTAINER"
    SERVICE = "SERVICE"
    SOCKET = "SOCKET"
    KERNEL_MODULE = "KERNEL_MODULE"


class HostEdgeType(str, Enum):
    """Causal and behavioral relationships between host entities."""
    # Process & Execution
    SPAWNED = "SPAWNED"
    EXECUTED = "EXECUTED"
    AUTHENTICATED_TO = "AUTHENTICATED_TO"

    # Network & Sockets
    CONNECTED_TO = "CONNECTED_TO"
    BOUND_TO = "BOUND_TO"

    # Filesystem & Persistence
    ACCESSED_FILE = "ACCESSED_FILE"
    MODIFIED_PERSISTENCE = "MODIFIED_PERSISTENCE"

    # Systemd & Workload Isolation
    MANAGED_BY = "MANAGED_BY"
    CONTAINED_IN = "CONTAINED_IN"
    ESCAPED_FROM = "ESCAPED_FROM"

    # Kernel & Drivers
    LOADED_MODULE = "LOADED_MODULE"

    # Generic & Temporal
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    CO_OCCURRED = "CO_OCCURRED"


class HostGraphNode(BaseModel):
    """Individual entity node in the unified host graph."""
    id: str
    node_type: HostNodeType
    label: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    epistemic_status: str = "OBSERVED"  # OBSERVED, INFERRED, UNKNOWN
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    def to_incident_entity(self, incident_id: int = 0) -> IncidentEntity:
        """Map safely into standard IncidentEntity for SQLite storage."""
        # SQLite CHECK allows ('HOST', 'USER', 'IP', 'PROCESS', 'COMMAND', 'FILE', 'SESSION')
        db_type = EntityType.PROCESS
        if self.node_type.value in EntityType.__members__:
            db_type = EntityType(self.node_type.value)
        else:
            # CONTAINER, SERVICE, SOCKET, KERNEL_MODULE map to PROCESS with custom metadata
            db_type = EntityType.PROCESS

        meta = dict(self.properties)
        meta["unified_node_type"] = self.node_type.value
        meta["epistemic_status"] = self.epistemic_status
        if self.first_seen:
            meta["first_seen"] = self.first_seen.isoformat()
        if self.last_seen:
            meta["last_seen"] = self.last_seen.isoformat()

        return IncidentEntity(
            incident_id=incident_id,
            entity_key=self.id,
            entity_type=db_type,
            display_name=self.label,
            metadata=meta,
        )


class HostGraphEdge(BaseModel):
    """Directed causal or behavioral relationship between host entities."""
    id: str
    source: str
    target: str
    edge_type: HostEdgeType
    confidence: ConfidenceLevel = ConfidenceLevel.DIRECT
    evidence_event_ids: List[Union[str, int]] = Field(default_factory=list)
    properties: Dict[str, Any] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None

    def to_incident_relationship(self, incident_id: int = 0) -> IncidentRelationship:
        """Map safely into standard IncidentRelationship for SQLite storage."""
        # SQLite CHECK allows ('AUTHENTICATED_TO', 'EXECUTED', 'SPAWNED', 'CONNECTED_TO', 'ACCESSED_FILE', 'LATERAL_MOVEMENT', 'CO_OCCURRED')
        allowed_rels = {
            "AUTHENTICATED_TO",
            "EXECUTED",
            "SPAWNED",
            "CONNECTED_TO",
            "ACCESSED_FILE",
            "LATERAL_MOVEMENT",
            "CO_OCCURRED",
        }
        rel_str = self.edge_type.value
        if rel_str not in allowed_rels:
            # Map extended relationships to CO_OCCURRED with extended metadata
            db_rel = "CO_OCCURRED"
        else:
            db_rel = rel_str

        return IncidentRelationship(
            incident_id=incident_id,
            source_entity_key=self.source,
            target_entity_key=self.target,
            relationship_type=db_rel,
            confidence=self.confidence,
            evidence_event_ids=self.evidence_event_ids,
            matched_at=self.timestamp or datetime.now(timezone.utc),
        )


class UnifiedHostGraph(BaseModel):
    """Complete correlated graph representation of a Linux host."""
    host: str
    nodes: List[HostGraphNode] = Field(default_factory=list)
    edges: List[HostGraphEdge] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_processes: int = 0
    total_connections: int = 0
    total_containers: int = 0
    total_services: int = 0
    total_files: int = 0
    summary: str = ""
