"""Unit tests for Unified Linux Host Graph models (Milestone M6.8)."""

from datetime import datetime, timezone
from logintel.correlation.host_graph_models import (
    HostEdgeType,
    HostGraphEdge,
    HostGraphNode,
    HostNodeType,
    UnifiedHostGraph,
)
from logintel.models.incidents import ConfidenceLevel, EntityType


def test_host_graph_node_initialization():
    """Verify HostGraphNode initializes with correct defaults and properties."""
    node = HostGraphNode(
        id="process:workstation:1234:bash",
        node_type=HostNodeType.PROCESS,
        label="bash",
        properties={"pid": 1234, "cmdline": "/bin/bash"},
        epistemic_status="OBSERVED",
    )
    assert node.id == "process:workstation:1234:bash"
    assert node.node_type == HostNodeType.PROCESS
    assert node.label == "bash"
    assert node.properties["pid"] == 1234
    assert node.epistemic_status == "OBSERVED"

    # Test conversion to standard IncidentEntity
    inc_ent = node.to_incident_entity(incident_id=1)
    assert inc_ent.incident_id == 1
    assert inc_ent.entity_key == node.id
    assert inc_ent.entity_type == EntityType.PROCESS
    assert inc_ent.metadata["unified_node_type"] == "PROCESS"


def test_extended_node_types_map_safely_to_incident_entity():
    """Verify CONTAINER, SERVICE, and SOCKET nodes map safely without breaking SQLite CHECK constraints."""
    container_node = HostGraphNode(
        id="container:abc123def456",
        node_type=HostNodeType.CONTAINER,
        label="web-app",
        properties={"image": "nginx:latest"},
    )
    inc_ent = container_node.to_incident_entity(incident_id=42)
    # Must be valid for SQLite CHECK (HOST, USER, IP, PROCESS, COMMAND, FILE, SESSION)
    assert inc_ent.entity_type in (EntityType.HOST, EntityType.USER, EntityType.IP, EntityType.PROCESS, EntityType.COMMAND, EntityType.FILE, EntityType.SESSION)
    assert inc_ent.metadata["unified_node_type"] == "CONTAINER"


def test_host_graph_edge_initialization_and_incident_mapping():
    """Verify HostGraphEdge converts safely to IncidentRelationship."""
    edge = HostGraphEdge(
        id="proc1->proc2:SPAWNED",
        source="process:workstation:100:systemd",
        target="process:workstation:200:nginx",
        edge_type=HostEdgeType.SPAWNED,
        confidence=ConfidenceLevel.DIRECT,
        evidence_event_ids=["evt-001"],
    )
    assert edge.source == "process:workstation:100:systemd"
    assert edge.edge_type == HostEdgeType.SPAWNED

    inc_rel = edge.to_incident_relationship(incident_id=10)
    assert inc_rel.incident_id == 10
    assert inc_rel.source_entity_key == edge.source
    assert inc_rel.relationship_type == "SPAWNED"
    assert inc_rel.confidence == ConfidenceLevel.DIRECT


def test_unified_host_graph_metrics():
    """Verify UnifiedHostGraph correctly summarizes nodes and edges."""
    now = datetime.now(timezone.utc)
    n1 = HostGraphNode(id="host:srv01", node_type=HostNodeType.HOST, label="srv01")
    n2 = HostGraphNode(id="process:srv01:1:init", node_type=HostNodeType.PROCESS, label="init")
    n3 = HostGraphNode(id="container:c123", node_type=HostNodeType.CONTAINER, label="c123")
    e1 = HostGraphEdge(
        id="e1",
        source="host:srv01",
        target="process:srv01:1:init",
        edge_type=HostEdgeType.SPAWNED,
        confidence=ConfidenceLevel.DIRECT,
    )
    graph = UnifiedHostGraph(
        host="srv01",
        nodes=[n1, n2, n3],
        edges=[e1],
        total_processes=1,
        total_containers=1,
        summary="Test graph",
    )
    assert graph.host == "srv01"
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 1
    assert graph.total_processes == 1
    assert graph.total_containers == 1
