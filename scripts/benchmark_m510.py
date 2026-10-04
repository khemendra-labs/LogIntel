#!/usr/bin/env python3
"""M5.10 Performance Benchmark Suite.

Forensic Workstation Benchmark evaluating M5.10 Temporal Attack Reconstruction & Investigation Timeline:
1. Timeline reconstruction (N=30)
2. Episode generation (N=30)
3. Transition generation (N=30)
4. Multi-host reconstruction (N=30)
5. Incident correlation (N=30)
6. Sequence generation (N=30)
7. Gap detection (N=30)
8. Entity pivot (N=30)
9. Export (N=30)
10. Combined reconstruction (N=30)

Measures: Samples (N=30), Dataset Size, Min, Median, P95, Max latencies in milliseconds, and Failure count.
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


def measure_op(fn: Callable[[], Any], iterations: int = 30) -> Dict[str, Any]:
    latencies: List[float] = []
    failures = 0
    # Warmup
    try:
        fn()
    except Exception as e:
        print(f"Warmup error: {e}")
        failures += 1

    for _ in range(iterations):
        t0 = time.perf_counter()
        try:
            fn()
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)
        except Exception:
            failures += 1

    if not latencies:
        return {"samples": 0, "min": 0.0, "median": 0.0, "p95": 0.0, "max": 0.0, "failures": failures}

    latencies.sort()
    p95_idx = int(0.95 * len(latencies))
    return {
        "samples": len(latencies),
        "min": round(min(latencies), 3),
        "median": round(statistics.median(latencies), 3),
        "p95": round(latencies[min(p95_idx, len(latencies) - 1)], 3),
        "max": round(max(latencies), 3),
        "failures": failures,
    }


def populate_benchmark_dataset(forensic_db: Database, entity_count: int = 30):
    with forensic_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES
            ('rule.bench10_auth', 'Benchmark Auth Rule', 'Rule Auth', 'ALERT', 'Auth', 'threshold', 'yaml'),
            ('rule.bench10_priv', 'Benchmark Priv Rule', 'Rule Priv', 'CRITICAL', 'Priv', 'threshold', 'yaml'),
            ('rule.bench10_net', 'Benchmark Net Rule', 'Rule Net', 'ALERT', 'Net', 'threshold', 'yaml')
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
            VALUES
            (910, 'INC-910', 'Primary Benchmark Incident', 'Intrusion reconstruction', 'CRITICAL', 'OPEN', 'srv-bench-0', 'user-0', '2026-10-04T10:00:00Z', '2026-10-04T10:30:00Z', 3, 60),
            (911, 'INC-911', 'Correlated Secondary Incident', 'Related activity', 'ALERT', 'OPEN', 'srv-bench-1', 'user-0', '2026-10-04T10:20:00Z', '2026-10-04T10:40:00Z', 1, 10)
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES
            (911, 'rule.bench10_auth', 'dedup-bench-911', 'Auth Alert', 'Desc', 'ALERT', 'OPEN', 'srv-bench-0', '2026-10-04T10:00:00Z', '2026-10-04T10:00:00Z', 1),
            (912, 'rule.bench10_priv', 'dedup-bench-912', 'Priv Alert', 'Desc', 'CRITICAL', 'OPEN', 'srv-bench-0', '2026-10-04T10:05:00Z', '2026-10-04T10:05:00Z', 1),
            (913, 'rule.bench10_net', 'dedup-bench-913', 'Net Alert', 'Desc', 'ALERT', 'OPEN', 'srv-bench-1', '2026-10-04T10:15:00Z', '2026-10-04T10:15:00Z', 1)
            """
        )
        cur.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (910, 911), (910, 912), (910, 913)")
        cur.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (911, 913)")

        # Populate events, entities, and relationships
        for i in range(entity_count):
            host = f"srv-bench-{i % 5}"
            user = f"user-{i % 3}"
            ip = f"192.168.1.{i + 1}"
            ev_id = f"ev-bench-{i}"
            ts = f"2026-10-04T10:{i:02d}:00Z"

            cur.execute(
                """
                INSERT OR IGNORE INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES (?, ?, ?, ?, 'syslog', 'login', 'INFORMATIONAL', 'login', 'success', 'Bench event', 'msg', 'p', ?, ?, ?)
                """,
                (ev_id, ts, ts, host, f"fp-{i}", user, ip),
            )
            cur.execute(
                """
                INSERT OR IGNORE INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES (910, 'USER', ?, ?), (910, 'HOST', ?, ?)
                """,
                (f"user:{user}", user, f"host:{host}", host),
            )
            if i > 0:
                prev_host = f"srv-bench-{(i - 1) % 5}"
                cur.execute(
                    """
                    INSERT OR IGNORE INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json, matched_at)
                    VALUES (910, ?, ?, 'LATERAL_MOVEMENT', 'CORRELATED', ?, ?)
                    """,
                    (f"host:{prev_host}", f"host:{host}", json.dumps([ev_id]), ts),
                )
        conn.commit()


def run_benchmark():
    with tempfile.TemporaryDirectory() as td:
        forensic_path = Path(td) / "forensic.db"
        cases_path = Path(td) / "cases.db"

        forensic_db = Database(forensic_path)
        forensic_db.initialize()
        populate_benchmark_dataset(forensic_db, entity_count=30)

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        case = case_svc.create_or_open_case(incident_id=910, title="Benchmark Case 910")
        for i in range(25):
            case_svc.associate_evidence(case.case_id, "event", f"ev-bench-{i}", citation_tag=f"[event:ev-bench-{i}]")

        print("=" * 80)
        print("LOGINTEL — M5.10 TEMPORAL RECONSTRUCTION & TIMELINE BENCHMARK (N=30)")
        print("=" * 80)
        print(f"Dataset Scope: 25 events, 30 entities, 5 hosts, 3 users, 3 alerts, 2 incidents")
        print(f"Target Case ID: {case.case_id} (Incident 910)")
        print("-" * 80)

        results = {}

        # 1. Timeline reconstruction
        results["timeline_reconstruction"] = measure_op(lambda: case_svc.get_temporal_reconstruction(case.case_id), 30)

        # 2. Episode generation
        results["episode_generation"] = measure_op(lambda: case_svc.get_temporal_episodes(case.case_id), 30)

        # 3. Transition generation
        results["transition_generation"] = measure_op(lambda: case_svc.get_temporal_transitions(case.case_id), 30)

        # 4. Multi-host reconstruction
        results["multihost_reconstruction"] = measure_op(
            lambda: case_svc.get_temporal_reconstruction(case.case_id).multi_host_traces, 30
        )

        # 5. Incident correlation
        results["incident_correlation"] = measure_op(lambda: case_svc.get_campaign_correlations(case.case_id), 30)

        # 6. Sequence generation
        results["sequence_generation"] = measure_op(lambda: case_svc.get_temporal_sequences(case.case_id), 30)

        # 7. Gap detection
        results["gap_detection"] = measure_op(lambda: case_svc.get_temporal_gaps(case.case_id), 30)

        # 8. Entity pivot
        results["entity_pivot"] = measure_op(
            lambda: case_svc.temporal_engine.detect_entity_continuity(case, case_svc.temporal_engine._harvest_case_evidence(case)), 30
        )

        # 9. Export
        results["export"] = measure_op(lambda: case_svc.export_temporal_reconstruction(case.case_id, "json"), 30)

        # 10. Combined reconstruction
        results["combined_reconstruction"] = measure_op(
            lambda: (
                case_svc.get_temporal_reconstruction(case.case_id),
                case_svc.export_temporal_reconstruction(case.case_id, "graphml"),
            ),
            30,
        )

        print(f"{'Operation':<30} | {'Samples':<7} | {'Median (ms)':<11} | {'P95 (ms)':<9} | {'Max (ms)':<9} | {'Failures'}")
        print("-" * 80)
        for op_name, metric in results.items():
            print(
                f"{op_name:<30} | {metric['samples']:<7} | {metric['median']:<11.3f} | {metric['p95']:<9.3f} | {metric['max']:<9.3f} | {metric['failures']}"
            )
        print("=" * 80)
        return results


if __name__ == "__main__":
    run_benchmark()
