#!/usr/bin/env python3
"""M5.8 Performance Benchmark Suite.

Forensic Workstation Benchmark evaluating M5.8 Graph Operations:
1. Small Graph Construction (N=30)
2. Medium Graph Construction (N=30)
3. Large Representative Graph Construction (N=30)
4. Entity Pivot Graph Exploration (N=30)
5. Investigation Path Traversal (N=30)
6. Temporal Chain Chronological Sequencing (N=30)
7. JSON Graph Export Serialization (N=30)
8. GraphML XML Graph Export Serialization (N=30)

Measures: Samples (N=30), Node Count, Edge Count, Min, Median, P95, Max latencies in milliseconds.
"""

from __future__ import annotations

import json
from pathlib import Path
import statistics
import tempfile
import time
from typing import Any, Callable, Dict, List

from logintel.ai.case_service import CaseService
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database


def measure_op(fn: Callable[[], Any], iterations: int = 30) -> Dict[str, float]:
    latencies: List[float] = []
    # Warmup
    fn()
    for _ in range(iterations):
        t0 = time.perf_counter()
        fn()
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    latencies.sort()
    p95_idx = int(0.95 * len(latencies))
    return {
        "samples": len(latencies),
        "min": round(min(latencies), 3),
        "median": round(statistics.median(latencies), 3),
        "p95": round(latencies[min(p95_idx, len(latencies) - 1)], 3),
        "max": round(max(latencies), 3),
    }


def populate_benchmark_dataset(forensic_db: Database, node_target: int = 50):
    with forensic_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES ('rule.bench58', 'Benchmark Attack Rule', 'Rule', 'CRITICAL', 'Auth', 'threshold', 'yaml')
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
            VALUES (800, 'INC-800', 'Benchmark Investigation Graph', 'Summary', 'CRITICAL', 'OPEN', 'srv-bench-0', 'user-0', '2026-10-03T10:00:00Z', '2026-10-03T10:30:00Z', 1, 100)
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES (801, 'rule.bench58', 'dedup-bench-801', 'SSH Alert', 'Desc', 'ALERT', 'OPEN', 'srv-bench-0', '2026-10-03T10:00:00Z', '2026-10-03T10:00:00Z', 1)
            """
        )
        cur.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (800, 801)")

        # Populate nodes & relationships
        for i in range(node_target):
            host = f"srv-bench-{i}"
            user = f"user-{i}"
            ip = f"10.0.{i // 256}.{i % 256}"
            cur.execute(
                """
                INSERT OR IGNORE INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES
                (800, 'HOST', ?, ?),
                (800, 'USER', ?, ?),
                (800, 'IP', ?, ?)
                """,
                (f"host:{host}", host, f"user:{user}", user, f"ip:{ip}", ip),
            )
            cur.execute(
                """
                INSERT OR IGNORE INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence)
                VALUES
                (800, ?, ?, 'AUTHENTICATED_TO', 'STRONG'),
                (800, ?, ?, 'CONNECTED_TO', 'STRONG')
                """,
                (f"user:{user}", f"host:{host}", f"host:{host}", f"ip:{ip}"),
            )
            # Add forensic events
            cur.execute(
                """
                INSERT OR IGNORE INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES (?, '2026-10-03T10:00:00Z', '2026-10-03T10:00:01Z', ?, 'auth.log', 'authentication_success', 'INFO', 'login', 'success', 'Login bench', 'raw', 'openssh', ?, ?, ?)
                """,
                (f"ev-bench-800-{i}", host, f"fp-bench-800-{i}", user, ip),
            )
        conn.commit()


def run_benchmarks() -> Dict[str, Dict[str, Any]]:
    with tempfile.TemporaryDirectory() as td:
        forensic_path = Path(td) / "forensic.db"
        case_path = Path(td) / "cases.db"

        forensic_db = Database(forensic_path)
        forensic_db.initialize()

        populate_benchmark_dataset(forensic_db, node_target=50)

        case_repo = CaseRepository(db_path=case_path, forensic_db=forensic_db)
        service = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Open case
        case = service.create_or_open_case(incident_id=800, title="Benchmark Graph Case", actor="bench-runner")
        case_id = case.case_id

        results: Dict[str, Dict[str, Any]] = {}

        # 1. Small Graph (max_nodes = 10)
        small_stats = measure_op(lambda: service.get_investigation_graph(case_id, max_nodes=10), iterations=30)
        g_small = service.get_investigation_graph(case_id, max_nodes=10)
        small_stats["node_count"] = g_small.total_nodes
        small_stats["edge_count"] = g_small.total_edges
        results["small_graph_construction"] = small_stats

        # 2. Medium Graph (max_nodes = 50)
        med_stats = measure_op(lambda: service.get_investigation_graph(case_id, max_nodes=50), iterations=30)
        g_med = service.get_investigation_graph(case_id, max_nodes=50)
        med_stats["node_count"] = g_med.total_nodes
        med_stats["edge_count"] = g_med.total_edges
        results["medium_graph_construction"] = med_stats

        # 3. Large Representative Graph (max_nodes = 200)
        large_stats = measure_op(lambda: service.get_investigation_graph(case_id, max_nodes=200), iterations=30)
        g_large = service.get_investigation_graph(case_id, max_nodes=200)
        large_stats["node_count"] = g_large.total_nodes
        large_stats["edge_count"] = g_large.total_edges
        results["large_graph_construction"] = large_stats

        # 4. Entity Pivot Graph Exploration
        pivot_stats = measure_op(lambda: service.get_entity_pivot_graph(case_id, "host", "srv-bench-0"), iterations=30)
        p_res = service.get_entity_pivot_graph(case_id, "host", "srv-bench-0")
        pivot_stats["node_count"] = len(p_res.connected_nodes)
        pivot_stats["edge_count"] = len(p_res.connected_edges)
        results["entity_pivot_exploration"] = pivot_stats

        # 5. Investigation Path Traversal
        path_stats = measure_op(
            lambda: service.get_investigation_path(case_id, "user:user-0", "ip:10.0.0.0", max_depth=5),
            iterations=30,
        )
        path_res = service.get_investigation_path(case_id, "user:user-0", "ip:10.0.0.0", max_depth=5)
        path_stats["node_count"] = len(path_res.nodes)
        path_stats["edge_count"] = len(path_res.edges)
        results["investigation_path_traversal"] = path_stats

        # 6. Temporal Chain Chronological Sequencing
        temporal_stats = measure_op(lambda: service.get_temporal_chain(case_id), iterations=30)
        t_res = service.get_temporal_chain(case_id)
        temporal_stats["node_count"] = 0
        temporal_stats["edge_count"] = t_res.total_steps
        results["temporal_chain_sequencing"] = temporal_stats

        # 7. JSON Graph Export
        json_export_stats = measure_op(lambda: service.export_investigation_graph(case_id, format="json"), iterations=30)
        json_export_stats["node_count"] = g_large.total_nodes
        json_export_stats["edge_count"] = g_large.total_edges
        results["json_graph_export"] = json_export_stats

        # 8. GraphML XML Graph Export
        graphml_export_stats = measure_op(lambda: service.export_investigation_graph(case_id, format="graphml"), iterations=30)
        graphml_export_stats["node_count"] = g_large.total_nodes
        graphml_export_stats["edge_count"] = g_large.total_edges
        results["graphml_graph_export"] = graphml_export_stats

        return results


if __name__ == "__main__":
    bench_results = run_benchmarks()
    print(json.dumps(bench_results, indent=2))
