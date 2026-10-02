#!/usr/bin/env python3
"""M5.5 Performance Benchmark Suite.

Benchmarks representative investigation case persistence, handoff, report versioning,
and deterministic AI context reconstruction operations across multiple iterations.
"""

from __future__ import annotations

import json
from pathlib import Path
import statistics
import tempfile
import time
from typing import Any, Callable, Dict, List

from logintel.ai.case_service import CaseService
from logintel.ai.domain.case import CaseStatus
from logintel.ai.domain.intelligence import QueryProposal
from logintel.ai.domain.workspace import InvestigationScope
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
            for i in range(1, 51):
                cur.execute(
                    """
                    INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, action, outcome, summary, raw_message, parser, event_fingerprint, username)
                    VALUES (?, '2026-09-30T10:00:00Z', '2026-09-30T10:00:01Z', 'srv-bench', 'auth.log', 'auth', 'ALERT', 'login', 'failure', 'Failed login bench', 'raw', 'openssh', ?, 'deployer')
                    """,
                    (f"ev-bench-{i}", f"fp-bench-{i}"),
                )
            cur.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
                VALUES (101, 'rule.bench', 'dedup-bench-101', 'SSH Alert', 'Desc', 'ALERT', 'OPEN', 'srv-bench', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1)
                """
            )
            cur.execute("INSERT INTO detections (id, alert_id, rule_id, timestamp, host, summary, evidence_count) VALUES (101, 101, 'rule.bench', '2026-09-30T10:00:00Z', 'srv-bench', 'SSH Failure', 1)")
            cur.execute("INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (101, 'ev-bench-1', 'primary')")
            cur.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, status, primary_host, primary_user, first_seen, last_seen, alert_count, event_count)
                VALUES (101, 'INC-BENCH-101', 'Persistent Compromise', 'Summary', 'CRITICAL', 'OPEN', 'srv-bench', 'deployer', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1, 1)
                """
            )
            cur.execute("INSERT INTO incident_alerts (incident_id, alert_id) VALUES (101, 101)")
            cur.execute("INSERT INTO incident_entities (incident_id, entity_type, entity_key, display_name) VALUES (101, 'HOST', 'host:srv-bench', 'srv-bench')")
            conn.commit()

        repo = CaseRepository(db_path=case_path, forensic_db=forensic_db)
        svc = CaseService(case_repository=repo, forensic_database=forensic_db)

        # Pre-create case 101
        svc.create_or_open_case(101)

        results: Dict[str, Any] = {}

        # 1. create_or_open_case
        inc_counter = [200]
        def op_create_case():
            c_id = inc_counter[0]
            inc_counter[0] += 1
            with forensic_db.connection() as c:
                c.execute("INSERT OR IGNORE INTO incidents (id, incident_key, title, summary, severity, status) VALUES (?, ?, 'Bench', 'Sum', 'INFO', 'OPEN')", (c_id, f"INC-{c_id}"))
                c.commit()
            return svc.create_or_open_case(c_id)
        results["case_creation"] = measure_op(op_create_case, iterations=30)

        # 2. get_case with evidence resolution
        results["case_loading_and_resolution"] = measure_op(lambda: svc.get_case(101), iterations=30)

        # 3. transition_case_state
        state_cycle = [CaseStatus.ACTIVE, CaseStatus.PAUSED]
        def op_state():
            s = state_cycle[0]
            state_cycle[0] = CaseStatus.PAUSED if s == CaseStatus.ACTIVE else CaseStatus.ACTIVE
            return svc.transition_case_state(101, s, actor="bench_analyst", reason="bench transition")
        results["case_state_transition"] = measure_op(op_state, iterations=30)

        # 4. update_scope
        def op_scope():
            sc = InvestigationScope(investigation_id=101, subject_id="101", time_start="2026-09-30T00:00:00Z", time_end="2026-09-30T23:59:59Z")
            return svc.update_scope(101, sc, actor="bench_analyst")
        results["case_scope_update"] = measure_op(op_scope, iterations=30)

        # 5. create_hypothesis
        hyp_idx = [1]
        def op_hyp():
            h_num = hyp_idx[0]
            hyp_idx[0] += 1
            return svc.create_hypothesis(101, f"Hypothesis {h_num} for benchmark", actor="bench_analyst")
        results["hypothesis_creation"] = measure_op(op_hyp, iterations=30)

        # 6. transfer_case (handoff)
        handoff_owners = ["SecAnalyst-Alpha", "SecAnalyst-Beta"]
        def op_handoff():
            owner = handoff_owners[0]
            handoff_owners[0] = "SecAnalyst-Beta" if owner == "SecAnalyst-Alpha" else "SecAnalyst-Alpha"
            return svc.transfer_case(101, new_owner=owner, actor="lead_analyst", handoff_notes="shift rotation")
        results["case_handoff"] = measure_op(op_handoff, iterations=30)

        # 7. execute_approved_query
        q_prop = QueryProposal(proposal_id="qp-bench", query_template_id="query_events", username="deployer", rationale="Bench query")
        results["approved_query_execution"] = measure_op(lambda: svc.execute_approved_query(101, q_prop, actor="bench_analyst"), iterations=30)

        # 8. draft_or_revise_report
        results["report_draft_generation"] = measure_op(lambda: svc.draft_or_revise_report(101, "Bench Dossier", actor="bench_analyst"), iterations=20)

        # 9. compare_report_versions
        svc.draft_or_revise_report(101, "Version A")
        svc.draft_or_revise_report(101, "Version B")
        reports = repo.get_case(101).reports
        v1, v2 = reports[0].version, reports[1].version
        results["report_version_comparison"] = measure_op(lambda: svc.compare_report_versions(101, reports[0].report_id, v1, v2), iterations=30)

        # 10. reconstruct_ai_context
        results["ai_context_reconstruction"] = measure_op(lambda: svc.reconstruct_ai_context(101), iterations=30)

        print("\n=== M5.5 PERFORMANCE BENCHMARK RESULTS ===")
        print(f"{'Operation':<35} | {'Median':<8} | {'P95':<8} | {'Min':<8} | {'Max':<8} | {'Samples':<8}")
        print("-" * 85)
        for op, data in results.items():
            print(f"{op:<35} | {data['median']:<6} ms | {data['p95']:<6} ms | {data['min']:<6} ms | {data['max']:<6} ms | {data['samples']}")

        return results


if __name__ == "__main__":
    run_benchmarks()
