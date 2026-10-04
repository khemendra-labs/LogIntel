#!/usr/bin/env python3
"""M5.12 Master Performance Benchmark Suite.

Synthetic Workstation Benchmark (N=30) covering the full M5 investigation pipeline:
1. Case Assessment Generation
2. Key Findings Synthesis
3. Competing Hypotheses Assessment
4. Evidence Gaps Prioritization
5. Investigation Questions Generation
6. Closure Readiness Evaluation
7. 15-Section Investigation Briefing Generation
8. Case Handoff Package Generation
9. Multi-dimensional Evidence Correlation
10. Temporal Attack Reconstruction & Episodes
11. Investigation Graph Generation
12. Entity Pivot & Workbench Dossier
13. Forensic Dossier & Evidence Export
14. Local AI Advisory Explanation Generation

Measures: Samples (N=30), Min, Median, P95, Max latencies in milliseconds, and Failure count.
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
            print(f"Execution error: {e}")
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


def populate_benchmark_dataset(forensic_db: Database, event_count: int = 50):
    with forensic_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES
            ('rule.bench12_auth', 'Benchmark Auth Rule', 'Rule Auth', 'ALERT', 'Auth', 'threshold', 'yaml'),
            ('rule.bench12_priv', 'Benchmark Priv Rule', 'Rule Priv', 'CRITICAL', 'Priv', 'threshold', 'yaml'),
            ('rule.bench12_net', 'Benchmark Net Rule', 'Rule Net', 'ALERT', 'Net', 'threshold', 'yaml')
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
            VALUES
            (990, 'INC-990', 'Benchmark Intrusion Incident', 'Analytical decision intelligence benchmark case', 'CRITICAL', 'OPEN', 'host-bench-0', 'user-0', '2026-10-04T10:00:00Z', '2026-10-04T10:45:00Z', 3, 50)
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES
            (991, 'rule.bench12_auth', 'dedup-bench-991', 'Auth Alert', 'Desc', 'ALERT', 'OPEN', 'host-bench-0', '2026-10-04T10:00:00Z', '2026-10-04T10:00:00Z', 1),
            (992, 'rule.bench12_priv', 'dedup-bench-992', 'Priv Alert', 'Desc', 'CRITICAL', 'OPEN', 'host-bench-0', '2026-10-04T10:15:00Z', '2026-10-04T10:15:00Z', 1),
            (993, 'rule.bench12_net', 'dedup-bench-993', 'Net Alert', 'Desc', 'ALERT', 'OPEN', 'host-bench-1', '2026-10-04T10:30:00Z', '2026-10-04T10:30:00Z', 1)
            """
        )
        cur.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (990, 991), (990, 992), (990, 993)")

        # Populate events
        for i in range(event_count):
            host = f"host-bench-{i % 3}"
            user = f"user-{i % 4}"
            ts = f"2026-10-04T10:{i:02d}:00Z"
            cur.execute(
                """
                INSERT OR IGNORE INTO events (
                    id, timestamp, ingested_at, host, source, event_type, severity,
                    action, outcome, summary, raw_message, parser, event_fingerprint,
                    username, src_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"ev-bench12-{i}",
                    ts,
                    ts,
                    host,
                    "auth.log",
                    "login",
                    "ALERT" if i % 3 == 0 else "INFORMATIONAL",
                    "auth",
                    "success",
                    f"Accepted publickey for {user} from 10.10.10.{i} port 4000 ssh2",
                    f"Accepted publickey for {user} from 10.10.10.{i} port 4000 ssh2",
                    "benchmark_parser",
                    f"fp-bench12-{i}",
                    user,
                    f"10.10.10.{i}",
                ),
            )
        # Incident entities
        entities = [
            ("HOST", "host:host-bench-0", "host-bench-0"),
            ("HOST", "host:host-bench-1", "host-bench-1"),
            ("USER", "user:user-0", "user-0"),
            ("USER", "user:user-admin", "user-admin"),
            ("IP", "ip:10.10.10.50", "10.10.10.50"),
        ]
        for ent_type, ent_key, disp_name in entities:
            cur.execute(
                """
                INSERT OR IGNORE INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES (990, ?, ?, ?)
                """,
                (ent_type, ent_key, disp_name),
            )

        # Relationships
        cur.execute(
            """
            INSERT OR IGNORE INTO incident_relationships (id, incident_id, source_entity_key, target_entity_key, relationship_type, confidence)
            VALUES
            (501, 990, 'user:user-0', 'host:host-bench-0', 'AUTHENTICATED_TO', 'DIRECT'),
            (502, 990, 'host:host-bench-0', 'host:host-bench-1', 'LATERAL_MOVEMENT', 'STRONG'),
            (503, 990, 'user:user-0', 'ip:10.10.10.50', 'CONNECTED_TO', 'DIRECT')
            """
        )
        conn.commit()


def main():
    print("=" * 80)
    print("LOGINTEL M5.12 MASTER WORKSTATION BENCHMARK (N=30)")
    print("=" * 80)

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        forensic_db_path = tmp_path / "forensic.db"
        case_db_path = tmp_path / "cases.db"

        forensic_db = Database(forensic_db_path)
        forensic_db.initialize()
        populate_benchmark_dataset(forensic_db, event_count=50)

        case_repo = CaseRepository(db_path=case_db_path, forensic_db=forensic_db)
        service = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create benchmark case
        case = service.create_or_open_case(
            incident_id=990,
            title="M5.12 Master Benchmark Intrusion",
        )
        case_id = case.case_id

        # Associate sample evidence
        for i in range(15):
            service.associate_evidence(
                case_id=case_id,
                source_type="event",
                source_id=f"ev-bench12-{i}",
                citation_tag=f"[event:ev-bench12-{i}]",
            )

        # Seed question and reviewed finding
        service.create_case_question(
            case_id=case_id,
            question="Was credential dumping performed on host-bench-0?",
            category="AUTHENTICATION",
            actor="bench-analyst",
        )
        findings = service.get_case_findings(case_id)
        if findings:
            service.review_case_finding(
                case_id=case_id,
                finding_id=findings[0].finding_id,
                review_state="ACCEPTED",
                notes="Benchmarked review verification",
                actor="BenchmarkAnalyst",
            )

        benchmarks: Dict[str, Dict[str, Any]] = {}

        print("\nRunning benchmarks (N=30 iterations each)...")

        # 1. Assessment Generation
        print("  [1/14] Case Assessment Generation...")
        benchmarks["Case Assessment Generation"] = measure_op(
            lambda: service.get_case_assessment(case_id, refresh=True), iterations=30
        )

        # 2. Findings Synthesis
        print("  [2/14] Key Findings Synthesis...")
        benchmarks["Key Findings Synthesis"] = measure_op(
            lambda: service.get_case_findings(case_id), iterations=30
        )

        # 3. Hypotheses Assessment
        print("  [3/14] Competing Hypotheses Assessment...")
        benchmarks["Competing Hypotheses Assessment"] = measure_op(
            lambda: service.get_case_hypotheses(case_id), iterations=30
        )

        # 4. Evidence Gaps Prioritization
        print("  [4/14] Evidence Gaps Prioritization...")
        benchmarks["Evidence Gaps Prioritization"] = measure_op(
            lambda: service.get_case_gaps(case_id), iterations=30
        )

        # 5. Questions Generation
        print("  [5/14] Investigation Questions Generation...")
        benchmarks["Investigation Questions Generation"] = measure_op(
            lambda: service.get_case_questions(case_id), iterations=30
        )

        # 6. Closure Readiness
        print("  [6/14] Closure Readiness Evaluation...")
        benchmarks["Closure Readiness Evaluation"] = measure_op(
            lambda: service.get_closure_readiness(case_id), iterations=30
        )

        # 7. 15-Section Briefing
        print("  [7/14] 15-Section Briefing Generation...")
        benchmarks["15-Section Briefing Generation"] = measure_op(
            lambda: service.get_investigation_briefing(case_id), iterations=30
        )

        # 8. Case Handoff
        print("  [8/14] Case Handoff Package Generation...")
        benchmarks["Case Handoff Package Generation"] = measure_op(
            lambda: service.get_case_handoff(
                case_id=case_id,
                actor="BenchmarkAnalyst",
            ),
            iterations=30,
        )

        # 9. Evidence Correlation
        print("  [9/14] Multi-dimensional Correlation...")
        benchmarks["Multi-dimensional Correlation"] = measure_op(
            lambda: service.get_findings_and_correlations(case_id), iterations=30
        )

        # 10. Temporal Reconstruction
        print("  [10/14] Temporal Reconstruction...")
        benchmarks["Temporal Reconstruction"] = measure_op(
            lambda: service.get_temporal_reconstruction(case_id), iterations=30
        )

        # 11. Investigation Graph
        print("  [11/14] Investigation Graph Generation...")
        benchmarks["Investigation Graph Generation"] = measure_op(
            lambda: service.get_investigation_graph(case_id), iterations=30
        )

        # 12. Entity Pivot
        print("  [12/14] Entity Pivot & Dossier...")
        benchmarks["Entity Pivot & Dossier"] = measure_op(
            lambda: service.get_entity_workbench_dossier(case_id, entity_type="USER", entity_value="user-0"), iterations=30
        )

        # 13. Dossier / Export
        print("  [13/14] Forensic Dossier & Export...")
        benchmarks["Forensic Dossier & Export"] = measure_op(
            lambda: service.get_investigation_dossier(case_id), iterations=30
        )

        # 14. Advisory AI Explanation
        print("  [14/14] Advisory AI Explanation...")
        benchmarks["Advisory AI Explanation"] = measure_op(
            lambda: service.explain_case_assessment(
                case_id=case_id,
                query="Explain lateral movement between host-bench-0 and host-bench-1",
            ),
            iterations=30,
        )

        print("\n" + "=" * 94)
        print(f"{'Workload / Operation':<38} | {'Samples':<7} | {'Min (ms)':<9} | {'Median (ms)':<11} | {'P95 (ms)':<9} | {'Max (ms)':<9} | {'Failures':<8}")
        print("-" * 94)
        for name, res in benchmarks.items():
            print(
                f"{name:<38} | {res['samples']:<7} | {res['min']:<9.2f} | {res['median']:<11.2f} | {res['p95']:<9.2f} | {res['max']:<9.2f} | {res['failures']:<8}"
            )
        print("=" * 94)

        # Save JSON results
        results_file = Path("docs/m512_benchmark_results.json")
        results_file.parent.mkdir(parents=True, exist_ok=True)
        results_file.write_text(json.dumps(benchmarks, indent=2))
        print(f"\nSaved benchmark results to {results_file}")


if __name__ == "__main__":
    main()
