"""Performance and latency benchmark suite for M7.5 Advanced Threat Hunting & Governed Queries.

Benchmarks synthetic workloads at 100 evidence items across N=10 iterations,
capturing Median, P95, and Maximum latencies.
"""

from __future__ import annotations

import statistics
import time
import pytest

from logintel.hunting.models import (
    ApproveHuntRequest,
    CreateHuntProposalRequest,
    FieldFilter,
    HuntIntent,
    HuntSequenceProposal,
    HuntSequenceStep,
    QueryOperator,
)
from logintel.hunting.service import threat_hunting_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def bench_case():
    case = case_repo.get_case_by_incident(7531, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=7531,
            title="M7.5 Performance Benchmark Case",
            description="Synthetic case for measuring hunting latencies",
            created_by="SecAnalyst-1",
        )
    case_id = case.case_id
    # Clean up any previous benchmark queries for idempotency
    conn = case_repo._get_connection()
    with conn:
        conn.execute("DELETE FROM case_query_history WHERE case_id = ?", (case_id,))
    return case_id


def compute_stats(latencies_ms: list[float]) -> dict[str, float]:
    sorted_l = sorted(latencies_ms)
    p95_idx = int(0.95 * len(sorted_l))
    return {
        "median": float(statistics.median(sorted_l)),
        "p95": float(sorted_l[min(p95_idx, len(sorted_l) - 1)]),
        "max": float(max(sorted_l)),
    }


def test_m75_performance_benchmarks(bench_case):
    """Benchmark hunting operations across N=10 iterations on local workstation."""
    case_id = bench_case
    iterations = 10

    validation_times = []
    hunt_exec_times = []
    entity_pivot_times = []
    temporal_hunt_times = []
    sequence_hunt_times = []
    export_times = []

    proposal_req = CreateHuntProposalRequest(
        intent=HuntIntent.PROCESS_EXECUTION,
        question="Find all process executions with process_name specified",
        field_filters=[
            FieldFilter(field="process_name", operator=QueryOperator.EXISTS, value=""),
        ],
        limit=100,
    )

    sequence_req = HuntSequenceProposal(
        case_id=case_id,
        sequence_name="Benchmark Attack Sequence",
        description="Login -> Sudo -> Exec",
        steps=[
            HuntSequenceStep(step_number=1, name="Login", action_type="login", field_filters=[FieldFilter(field="action", operator=QueryOperator.EQUALS, value="login")]),
            HuntSequenceStep(step_number=2, name="Sudo", action_type="sudo", field_filters=[FieldFilter(field="action", operator=QueryOperator.EQUALS, value="sudo")]),
        ],
    )

    last_hunt_id: str = ""

    for _ in range(iterations):
        # 1. Query Validation & Preview
        t0 = time.perf_counter()
        preview = threat_hunting_service.validate_and_preview_hunt(case_id, proposal_req)
        validation_times.append((time.perf_counter() - t0) * 1000)

        # 2. Proposal creation, approval, and execution
        t1 = time.perf_counter()
        hunt_id, _ = threat_hunting_service.create_hunt_proposal(case_id, proposal_req)
        threat_hunting_service.approve_hunt(case_id, hunt_id, ApproveHuntRequest(approved_by="BenchmarkAnalyst"))
        res = threat_hunting_service.execute_hunt(case_id, hunt_id)
        hunt_exec_times.append((time.perf_counter() - t1) * 1000)
        last_hunt_id = hunt_id

        # 3. Entity Pivot
        t2 = time.perf_counter()
        ent_res = threat_hunting_service.pivot_hunt_by_entity(case_id, "HOST", "srv-web-01")
        entity_pivot_times.append((time.perf_counter() - t2) * 1000)

        # 4. Temporal Hunt
        t3 = time.perf_counter()
        temp_res = threat_hunting_service.pivot_hunt_temporal(case_id, "2026-10-07T10:05:00Z", window_minutes=15)
        temporal_hunt_times.append((time.perf_counter() - t3) * 1000)

        # 5. Sequence Hunt
        t4 = time.perf_counter()
        seq_res = threat_hunting_service.execute_sequence_hunt(case_id, sequence_req)
        sequence_hunt_times.append((time.perf_counter() - t4) * 1000)

        # 6. Export JSON
        t5 = time.perf_counter()
        exp_res = threat_hunting_service.export_hunt(case_id, last_hunt_id, format_type="json")
        export_times.append((time.perf_counter() - t5) * 1000)

    stats_val = compute_stats(validation_times)
    stats_hunt = compute_stats(hunt_exec_times)
    stats_pivot = compute_stats(entity_pivot_times)
    stats_temp = compute_stats(temporal_hunt_times)
    stats_seq = compute_stats(sequence_hunt_times)
    stats_exp = compute_stats(export_times)

    print("\n--- M7.5 Threat Hunting Performance Benchmark (N=10 iterations) ---")
    print(f"Query Validation:   median={stats_val['median']:.3f}ms, P95={stats_val['p95']:.3f}ms, max={stats_val['max']:.3f}ms")
    print(f"Governed Hunt Exec: median={stats_hunt['median']:.3f}ms, P95={stats_hunt['p95']:.3f}ms, max={stats_hunt['max']:.3f}ms")
    print(f"Entity Pivot:       median={stats_pivot['median']:.3f}ms, P95={stats_pivot['p95']:.3f}ms, max={stats_pivot['max']:.3f}ms")
    print(f"Temporal Hunt:      median={stats_temp['median']:.3f}ms, P95={stats_temp['p95']:.3f}ms, max={stats_temp['max']:.3f}ms")
    print(f"Sequence Hunt:      median={stats_seq['median']:.3f}ms, P95={stats_seq['p95']:.3f}ms, max={stats_seq['max']:.3f}ms")
    print(f"Export JSON:        median={stats_exp['median']:.3f}ms, P95={stats_exp['p95']:.3f}ms, max={stats_exp['max']:.3f}ms")

    # Assert bounded latencies on local workstation
    assert stats_val["median"] < 50.0, f"Query validation median too high: {stats_val['median']}ms"
    assert stats_hunt["median"] < 100.0, f"Governed hunt median too high: {stats_hunt['median']}ms"
    assert stats_pivot["median"] < 100.0, f"Entity pivot median too high: {stats_pivot['median']}ms"
    assert stats_temp["median"] < 100.0, f"Temporal hunt median too high: {stats_temp['median']}ms"
    assert stats_seq["median"] < 150.0, f"Sequence hunt median too high: {stats_seq['median']}ms"
    assert stats_exp["median"] < 50.0, f"Export median too high: {stats_exp['median']}ms"
