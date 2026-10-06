"""Determinism certification test suite for Unified Host Graph (Milestone M6.8)."""

import hashlib
import json
from logintel.correlation.host_graph import HostGraphBuilder


def test_host_graph_determinism():
    """Verify HostGraphBuilder produces bit-for-bit identical graphs across 10 evaluations."""
    builder = HostGraphBuilder()
    events = [
        {"id": f"ev-{i}", "host": "srv-det", "pid": 1000 + i, "ppid": 1000, "username": "operator", "process_name": f"worker_{i}"}
        for i in range(25)
    ]

    digests = set()
    for _ in range(10):
        graph = builder.build_from_events(host="srv-det", events=events)
        graph_dict = graph.model_dump(mode="json")
        # Remove generated_at timestamp for semantic determinism comparison
        graph_dict.pop("generated_at", None)
        serialized = json.dumps(graph_dict, sort_keys=True)
        h = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        digests.add(h)

    assert len(digests) == 1, f"Expected exactly 1 unique digest, got {len(digests)}: {digests}"
