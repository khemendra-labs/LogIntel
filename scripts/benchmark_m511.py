#!/usr/bin/env python3
"""M5.11 Performance Benchmark Suite.

Forensic Workstation Benchmark evaluating M5.11 Analyst Decision Intelligence, Case Assessment, Evidence Synthesis & Investigation Closure:
1. Full Case Assessment Generation (N=30)
2. Key Findings Synthesis (N=30)
3. Competing Hypotheses Assessment (N=30)
4. Investigation Questions Generation (N=30)
5. Evidence Gaps Prioritization (N=30)
6. Advisory Closure Readiness Evaluation (N=30)
7. 15-Section Investigation Briefing Generation (N=30)
8. Case Handoff Package Generation (N=30)
9. Finding Review & Epistemic Preservation Flow (N=30)
10. Advisory Local AI Explanation Generation (N=30)

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


def populate_benchmark_dataset(forensic_db: Database, event_count: int = 40):
    with forensic_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT OR IGNORE INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES
            ('rule.bench11_auth', 'Benchmark Auth Rule', 'Rule Auth', 'ALERT', 'Auth', 'threshold', 'yaml'),
            ('rule.bench11_priv', 'Benchmark Priv Rule', 'Rule Priv', 'CRITICAL', 'Priv', 'threshold', 'yaml'),
            ('rule.bench11_net', 'Benchmark Net Rule', 'Rule Net', 'ALERT', 'Net', 'threshold', 'yaml')
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
            VALUES
            (990, 'INC-990', 'Benchmark Intrusion Incident', 'Analytical decision intelligence benchmark case', 'CRITICAL', 'OPEN', 'host-bench-0', 'user-0', '2026-10-04T10:00:00Z', '2026-10-04T10:45:00Z', 3, 40)
            """
        )
        cur.execute(
            """
            INSERT OR IGNORE INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES
            (991, 'rule.bench11_auth', 'dedup-bench-991', 'Auth Alert', 'Desc', 'ALERT', 'OPEN', 'host-bench-0', '2026-10-04T10:00:00Z', '2026-10-04T10:00:00Z', 1),
            (992, 'rule.bench11_priv', 'dedup-bench-992', 'Priv Alert', 'Desc', 'CRITICAL', 'OPEN', 'host-bench-0', '2026-10-04T10:15:00Z', '2026-10-04T10:15:00Z', 1),
            (993, 'rule.bench11_net', 'dedup-bench-993', 'Net Alert', 'Desc', 'ALERT', 'OPEN', 'host-bench-1', '2026-10-04T10:30:00Z', '2026-10-04T10:30:00Z', 1)
            """
        )
        cur.execute("INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id) VALUES (990, 991), (990, 992), (990, 993)")

        # Populate events
        for i in range(event_count):
            host = f"host-bench-{i % 3}"
            user = f"user-{i % 2}"
            ev_id = f"ev-bench11-{i}"
            cur.execute(
                """
                INSERT OR IGNORE INTO events (
                    id, timestamp, ingested_at, host, source, event_type, severity,
                    action, outcome, summary, raw_message, parser, event_fingerprint,
                    username, src_ip
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev_id,
                    f"2026-10-04T10:{i:02d}:00Z",
                    f"2026-10-04T10:{i:02d}:01Z",
                    host,
                    "auth.log" if i % 2 == 0 else "audit.log",
                    "login" if i % 2 == 0 else "process",
                    "ALERT" if i % 3 == 0 else "INFORMATIONAL",
                    "auth" if i % 2 == 0 else "exec",
                    "success" if i % 4 != 0 else "failure",
                    f"Synthetic benchmark event {i} on {host}",
                    f"raw-msg-{i}",
                    "benchmark_parser",
                    f"fp-bench11-{i}",
                    user,
                    f"192.168.1.{100 + (i % 5)}",
                ),
            )

        conn.commit()


def main():
    with tempfile.TemporaryDirectory() as td:
        forensic_path = Path(td) / "forensic.db"
        cases_path = Path(td) / "cases.db"

        forensic_db = Database(forensic_path)
        forensic_db.initialize()

        populate_benchmark_dataset(forensic_db, event_count=35)

        case_repo = CaseRepository(db_path=cases_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create benchmark case and associate evidence
        case = case_svc.create_or_open_case(incident_id=990, title="M5.11 Benchmark Case")
        for i in range(20):
            case_svc.associate_evidence(case.case_id, "event", f"ev-bench11-{i}", citation_tag=f"[event:ev-bench11-{i}]")

        # Operations to benchmark
        benchmarks = {
            "Assessment Generation": lambda: case_svc.get_case_assessment(case.case_id, refresh=True),
            "Findings Synthesis": lambda: case_svc.get_case_findings(case.case_id),
            "Hypotheses Assessment": lambda: case_svc.get_case_hypotheses(case.case_id),
            "Questions Generation": lambda: case_svc.get_case_questions(case.case_id),
            "Evidence Gaps Prioritization": lambda: case_svc.get_case_gaps(case.case_id),
            "Closure Readiness Evaluation": lambda: case_svc.get_closure_readiness(case.case_id),
            "Briefing Generation (15-Section)": lambda: case_svc.get_investigation_briefing(case.case_id),
            "Case Handoff Package Generation": lambda: case_svc.get_case_handoff(case.case_id, actor="BenchmarkAnalyst"),
            "Finding Review Flow": lambda: case_svc.review_case_finding(case.case_id, f"f-ev-ref-event-ev-bench11-0", "ACCEPTED", notes="Benchmarked verification", actor="BenchmarkAnalyst"),
            "Advisory Local AI Explanation": lambda: case_svc.explain_case_assessment(case.case_id, query="Explain evidence sufficiency status"),
        }

        results = {}
        print("================================================================================")
        print("          LOGINTEL M5.11 ANALYTICAL DECISION INTELLIGENCE BENCHMARK            ")
        print("================================================================================")
        print(f"{'Operation':<35} | {'Samples':<7} | {'Min (ms)':<9} | {'Median (ms)':<11} | {'P95 (ms)':<9} | {'Max (ms)':<9} | {'Failures':<8}")
        print("--------------------------------------------------------------------------------")

        for name, fn in benchmarks.items():
            stats = measure_op(fn, iterations=30)
            results[name] = stats
            print(
                f"{name:<35} | {stats['samples']:<7} | {stats['min']:<9.2f} | "
                f"{stats['median']:<11.2f} | {stats['p95']:<9.2f} | {stats['max']:<9.2f} | {stats['failures']:<8}"
            )

        print("================================================================================")
        print(f"Benchmark completed successfully for all 10 operations (N=30 iterations each).")
        return results


if __name__ == "__main__":
    main()
