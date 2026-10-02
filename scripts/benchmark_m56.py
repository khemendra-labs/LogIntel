#!/usr/bin/env python3
"""M5.6 Performance Benchmark Suite.

Workstation synthetic benchmark evaluating:
1. Finding generation
2. Multi-attribute correlation
3. Temporal window analysis
4. Evidence-gap analysis
5. Entity pivot resolution
6. Timeline construction
7. Approved threat hunt query execution
8. Hypothesis evidence analysis
9. AI context & dossier reconstruction

Measures: Median, P95, Min, Max, N across 30 iterations per operation.
"""

from __future__ import annotations

import json
from pathlib import Path
import statistics
import tempfile
import time
from typing import Any, Callable, Dict, List

from logintel.ai.case_service import CaseService
from logintel.ai.domain.investigation_intel import QueryProposal
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
        "median": round(statistics.median(latencies), 3),
        "p95": round(latencies[min(p95_idx, len(latencies) - 1)], 3),
        "min": round(min(latencies), 3),
        "max": round(max(latencies), 3),
        "samples": len(latencies),
    }


def run_benchmarks():
    with tempfile.TemporaryDirectory() as td:
        forensic_path = Path(td) / "forensic.db"
        case_path = Path(td) / "cases.db"

        forensic_db = Database(forensic_path)
        forensic_db.initialize()

        with forensic_db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES ('rule.bench', 'Benchmark Attack', 'Rule', 'CRITICAL', 'Auth', 'threshold', 'yaml')
                """
            )
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (100, 'INC-100', 'Benchmark APT Intrusion', 'Summary', 'CRITICAL', 'OPEN', 'srv-bench-01', 'deployer', '2026-10-02T10:00:00Z', '2026-10-02T10:05:00Z', 1, 100)
                """
            )
            for i in range(1, 101):
                cur.execute(
                    """
                    INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username, src_ip)
                    VALUES (?, '2026-10-02T10:00:00Z', '2026-10-02T10:00:01Z', 'srv-bench-01', 'auth.log', 'authentication_failure', 'ALERT', 'login', 'failure', 'Failed login bench', 'raw', 'openssh', ?, 'deployer', '10.0.0.50')
                    """,
                    (f"ev-bench-{i}", f"fp-bench-{i}"),
                )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (101, 'rule.bench', 'dedup-bench-101', 'SSH Alert', 'Desc', 'ALERT', 'OPEN', 'srv-bench-01', '2026-10-02T10:00:00Z', '2026-10-02T10:00:00Z', 1)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (100, 101)")
            cur.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name)
                VALUES 
                (100, 'HOST', 'host:srv-bench-01', 'srv-bench-01'),
                (100, 'USER', 'user:deployer', 'deployer')
                """
            )
            conn.commit()

        case_repo = CaseRepository(db_path=case_path, forensic_db=forensic_db)
        case_svc = CaseService(case_repository=case_repo, forensic_database=forensic_db)

        # Create persistent case with 20 evidence items and hypothesis
        case = case_svc.create_or_open_case(incident_id=100, title="M5.6 Benchmark Case")
        case_id = case.case_id

        for i in range(1, 21):
            case_svc.associate_evidence(case_id, "event", f"ev-bench-{i}", citation_tag=f"[event:ev-bench-{i}]")
        case_svc.associate_evidence(case_id, "alert", "101", citation_tag="[alert:101]")

        hyp = case_svc.create_hypothesis(
            case_id=case_id,
            statement="Attacker attempted brute force authentication sequence against deployer",
            actor="analyst-bench",
            supporting_tags=["[event:ev-bench-1]", "[event:ev-bench-2]"],
        )

        proposal = case_svc.create_hunt_proposal(
            case_id=case_id,
            template_id="search_auth_failures",
            parameters={"username": "deployer", "limit": 25},
            rationale="Benchmark hunt proposal",
            suggested_by="analyst-bench",
        )

        print("=" * 80)
        print("LOGINTEL M5.6 — LOCAL WORKSTATION SYNTHETIC BENCHMARK RESULTS")
        print("=" * 80)

        results: Dict[str, Dict[str, Any]] = {}

        # 1. Finding generation & correlation
        results["finding_and_correlation_generation"] = measure_op(
            lambda: case_svc.get_findings_and_correlations(case_id)
        )

        # 2. Temporal correlation window analysis
        results["temporal_window_analysis"] = measure_op(
            lambda: case_svc.analyze_temporal_window(
                case_id=case_id,
                anchor_type="alert",
                anchor_id="101",
                anchor_timestamp="2026-10-02T10:00:00Z",
                window_seconds=300,
            )
        )

        # 3. Evidence-gap analysis
        results["evidence_gap_analysis"] = measure_op(
            lambda: case_svc.get_evidence_gaps(case_id)
        )

        # 4. Entity pivot resolution
        results["entity_pivot_resolution"] = measure_op(
            lambda: case_svc.resolve_entity_pivot(case_id, "HOST", "srv-bench-01")
        )

        # 5. Timeline construction
        results["timeline_construction"] = measure_op(
            lambda: case_svc.get_case_timeline(case_id)
        )

        # 6. Approved query execution
        results["approved_query_execution"] = measure_op(
            lambda: case_svc.execute_hunt_query(proposal, approved_by="analyst-bench")
        )

        # 7. Hypothesis analysis
        results["hypothesis_evidence_analysis"] = measure_op(
            lambda: case_svc.analyze_hypothesis(case_id, hyp.hypothesis_id)
        )

        # 8. Complete case intelligence dossier reconstruction
        results["case_intelligence_dossier"] = measure_op(
            lambda: case_svc.get_case_intelligence_dossier(case_id)
        )

        # 9. AI context & deterministic synthesis
        results["ai_investigation_intelligence_synthesis"] = measure_op(
            lambda: case_svc.generate_ai_investigation_intelligence(case_id)
        )

        for op_name, metric in results.items():
            print(f"\nOperation: {op_name}")
            print(f"  Samples: {metric['samples']}")
            print(f"  Median:  {metric['median']} ms")
            print(f"  P95:     {metric['p95']} ms")
            print(f"  Min:     {metric['min']} ms")
            print(f"  Max:     {metric['max']} ms")

        print("\n" + "=" * 80)
        return results


if __name__ == "__main__":
    run_benchmarks()
