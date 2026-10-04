#!/usr/bin/env python3
"""M5.9 Performance Benchmark Suite.

Forensic Workstation Benchmark evaluating M5.9 Evidence Correlation & Intelligence Operations:
1. Correlation (N=30)
2. Evidence clustering (N=30)
3. Temporal correlation (N=30)
4. Hypothesis analysis (N=30)
5. Evidence gaps (N=30)
6. Finding generation (N=30)
7. Entity pivot / Workbench (N=30)
8. Combined graph/correlation (N=30)

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
        except Exception as e:
            failures += 1

    if not latencies:
        return {"samples": 0, "median": 0.0, "p95": 0.0, "max": 0.0, "failures": failures}

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


def populate_benchmark_dataset(forensic_db: Database, entity_count: int = 40):
    with forensic_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES
            ('rule.bench59_auth', 'Benchmark Auth Rule', 'Rule Auth', 'ALERT', 'Auth', 'threshold', 'yaml'),
            ('rule.bench59_priv', 'Benchmark Priv Rule', 'Rule Priv', 'CRITICAL', 'Priv', 'threshold', 'yaml')
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
            VALUES (900, 'INC-900', 'Benchmark Evidence Correlation', 'Summary', 'CRITICAL', 'OPEN', 'srv-bench-0', 'user-0', '2026-10-04T10:00:00Z', '2026-10-04T10:30:00Z', 2, 80)
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES
            (901, 'rule.bench59_auth', 'dedup-bench-901', 'Auth Alert', 'Desc', 'ALERT', 'OPEN', 'srv-bench-0', '2026-10-04T10:00:00Z', '2026-10-04T10:00:00Z', 1),
            (902, 'rule.bench59_priv', 'dedup-bench-902', 'Priv Alert', 'Desc', 'CRITICAL', 'OPEN', 'srv-bench-0', '2026-10-04T10:05:00Z', '2026-10-04T10:05:00Z', 1)
            """
        )
        cur.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (900, 901), (900, 902)")

        # Populate entities and relationships
        for i in range(entity_count):
            host = f"srv-node-{i}"
            user = f"analyst-{i}"
            ip = f"192.168.1.{i + 1}"
            cur.execute(
                """
                INSERT OR IGNORE INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES
                (900, 'HOST', ?, ?),
                (900, 'USER', ?, ?),
                (900, 'IP', ?, ?)
                """,
                (f"host:{host}", host, f"user:{user}", user, f"ip:{ip}", ip),
            )
            cur.execute(
                """
                INSERT OR IGNORE INTO incident_relationships (incident_id, source_entity_key, target_entity_key, relationship_type, confidence, matched_at)
                VALUES
                (900, ?, ?, 'AUTHENTICATED_TO', 'DIRECT', '2026-10-04T10:00:00Z'),
                (900, ?, ?, 'CONNECTED_TO', 'DIRECT', '2026-10-04T10:02:00Z')
                """,
                (f"user:{user}", f"host:{host}", f"host:{host}", f"ip:{ip}"),
            )
            # Add forensic events
            cur.execute(
                """
                INSERT OR IGNORE INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                VALUES
                (?, '2026-10-04T10:00:00Z', '2026-10-04T10:00:01Z', ?, 'auth.log', 'login', 'INFO', 'login', 'success', 'Login', 'raw', 'p', ?, ?, ?)
                """,
                (f"bench-ev-{i}", host, f"fp-bench-{i}", user, ip),
            )
        conn.commit()


def main():
    print("=" * 80)
    print("LOGINTEL MILESTONE 5.9 EVIDENCE CORRELATION & DECISION SUPPORT BENCHMARK")
    print("Forensic Workstation Latency Benchmark (N=30 Iterations per Workload)")
    print("=" * 80)

    with tempfile.TemporaryDirectory() as td:
        forensic_path = Path(td) / "forensic_bench.db"
        cases_path = Path(td) / "cases_bench.db"

        forensic_db = Database(forensic_path)
        forensic_db.initialize()
        populate_benchmark_dataset(forensic_db, entity_count=40)

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create case and associate evidence
        case = case_svc.create_or_open_case(incident_id=900, title="Benchmark Case 900")
        case_id = case.case_id

        for i in range(20):
            case_svc.associate_evidence(case_id, "event", f"bench-ev-{i}", citation_tag=f"[event:bench-ev-{i}]")
        case_svc.associate_evidence(case_id, "alert", "901", citation_tag="[alert:901]")
        case_svc.associate_evidence(case_id, "alert", "902", citation_tag="[alert:902]")

        # Create hypothesis
        case_svc.create_hypothesis(
            case_id=case_id,
            statement="Observed multiple lateral authentication events across workstation subnets.",
            actor="Benchmarker",
        )
        hyp_id = case_svc.get_case(case_id).hypotheses[0].hypothesis_id

        # 1. Correlation
        m_corr = measure_op(lambda: case_svc.get_evidence_clusters(case_id))

        # 2. Evidence clustering
        m_clust = measure_op(lambda: case_svc.advanced_correlator.build_evidence_clusters(case_svc.get_case(case_id)))

        # 3. Temporal correlation
        m_temp = measure_op(lambda: case_svc.get_evidence_clusters(case_id, cluster_type="TEMPORAL"))

        # 4. Hypothesis analysis
        m_hyp = measure_op(lambda: case_svc.get_hypothesis_correlation_support(case_id, hyp_id))

        # 5. Evidence gaps
        m_gaps = measure_op(lambda: case_svc.get_correlation_evidence_gaps(case_id))

        # 6. Finding generation
        m_findings = measure_op(lambda: case_svc.generate_findings_from_clusters(case_id))

        # 7. Entity pivot
        m_pivot = measure_op(lambda: case_svc.get_entity_workbench_dossier(case_id, "user", "analyst-0"))

        # 8. Combined graph/correlation view
        def combined_view():
            g = case_svc.get_investigation_graph(case_id)
            c, s, gp = case_svc.get_evidence_clusters(case_id)
            return len(g.nodes), len(c)

        m_comb = measure_op(combined_view)

        results = [
            ("Correlation", 30, "120 Entities, 80 Rels, 22 Evid", m_corr),
            ("Evidence clustering", 30, "120 Entities, 80 Rels, 22 Evid", m_clust),
            ("Temporal correlation", 30, "120 Entities, 80 Rels, 22 Evid", m_temp),
            ("Hypothesis analysis", 30, "1 Hyp, 22 Evid, Multi-cluster", m_hyp),
            ("Evidence gaps", 30, "120 Entities, Telemetry Census", m_gaps),
            ("Finding generation", 30, "Multi-cluster derivation", m_findings),
            ("Entity pivot", 30, "user:analyst-0 2-hop radius", m_pivot),
            ("Combined graph/correlation", 30, "Full Graph + Clusters", m_comb),
        ]

        print(f"\n{'Workload':<28} | {'N':>3} | {'Dataset':<30} | {'Median (ms)':>11} | {'P95 (ms)':>9} | {'Max (ms)':>9} | {'Failures':>8} | {'Result':<6}")
        print("-" * 125)
        for name, n, ds, m in results:
            res_str = "PASS" if m["failures"] == 0 and m["median"] < 500.0 else "WARN"
            print(f"{name:<28} | {n:>3} | {ds:<30} | {m['median']:>11.3f} | {m['p95']:>9.3f} | {m['max']:>9.3f} | {m['failures']:>8} | {res_str:<6}")

        print("\nBenchmark completed successfully.")


if __name__ == "__main__":
    main()
