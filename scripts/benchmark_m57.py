#!/usr/bin/env python3
"""M5.7 Performance Benchmark Suite.

Workstation synthetic benchmark evaluating M5.7 operations:
1. Dossier generation
2. Finding review lifecycle
3. Evidence matrix evaluation
4. Timeline construction
5. Case briefing generation
6. Report drafting from dossier
7. Provenance manifest extraction
8. Threat-hunt result integration
9. Local AI advisory synthesis

Measures: Samples (N=30), Min, Median, P95, Max latencies in milliseconds.
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


def run_benchmarks() -> Dict[str, Dict[str, Any]]:
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
        case = case_svc.create_or_open_case(incident_id=100, title="M5.7 Benchmark Case")
        case_id = case.case_id

        for i in range(1, 21):
            case_svc.associate_evidence(case_id, "event", f"ev-bench-{i}", citation_tag=f"[event:ev-bench-{i}]")
        case_svc.associate_evidence(case_id, "alert", "101", citation_tag="[alert:101]")

        case_svc.create_hypothesis(
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
        case_svc.execute_hunt_query(proposal, approved_by="analyst-bench")

        dossier = case_svc.get_investigation_dossier(case_id)
        first_finding_id = dossier.findings[0]["finding_id"] if dossier.findings else "fnd-1"

        print("=" * 80)
        print("LOGINTEL M5.7 — LOCAL WORKSTATION SYNTHETIC BENCHMARK RESULTS")
        print("=" * 80)

        results: Dict[str, Dict[str, Any]] = {}

        # 1. Dossier generation
        results["dossier_generation"] = measure_op(
            lambda: case_svc.get_investigation_dossier(case_id)
        )

        # 2. Finding review
        results["finding_review"] = measure_op(
            lambda: case_svc.update_finding_review(
                case_id=case_id,
                finding_id=first_finding_id,
                review_state="ACCEPTED",
                analyst_notes="Bench reviewed",
                reviewer="bench-analyst",
            )
        )

        # 3. Evidence matrix
        results["evidence_matrix"] = measure_op(
            lambda: case_svc.get_evidence_matrix(case_id)
        )

        # 4. Timeline construction
        results["timeline_construction"] = measure_op(
            lambda: case_svc.get_refined_timeline(case_id)
        )

        # 5. Case briefing
        results["case_briefing"] = measure_op(
            lambda: case_svc.get_case_briefing(case_id)
        )

        # 6. Report drafting
        results["report_drafting"] = measure_op(
            lambda: case_svc.draft_report_from_dossier(case_id, title="Benchmark Report")
        )

        # 7. Provenance manifest
        results["provenance_manifest"] = measure_op(
            lambda: case_svc.get_provenance_manifest(case_id)
        )

        # 8. Threat-hunt integration
        results["threat_hunt_integration"] = measure_op(
            lambda: case_svc.get_threat_hunt_results(case_id)
        )

        # 9. AI synthesis
        results["ai_synthesis"] = measure_op(
            lambda: case_svc.generate_ai_investigation_intelligence(case_id)
        )

        for op_name, metric in results.items():
            print(f"\nOperation: {op_name}")
            print(f"  Samples (N): {metric['samples']}")
            print(f"  Min:         {metric['min']} ms")
            print(f"  Median:      {metric['median']} ms")
            print(f"  P95:         {metric['p95']} ms")
            print(f"  Max:         {metric['max']} ms")

        print("\n" + "=" * 80)
        return results


if __name__ == "__main__":
    run_benchmarks()
