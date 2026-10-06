"""Performance and resource benchmark for Milestone M7.2."""

from __future__ import annotations

import time
import statistics
import pytest

from logintel.storage.case_repo import case_repo
from logintel.timeline.models import TimelineFilterParams
from logintel.timeline.service import timeline_service


@pytest.fixture
def perf_case():
    case = case_repo.get_case_by_incident(7299, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=7299,
            title="M7.2 Performance Test Case",
            description="Synthetic case for measuring M7.2 operation latencies",
            created_by="SecAnalyst-1",
        )
    case_id = case.case_id

    # Clean up previous synthetic performance evidence references for test idempotency
    if case and case.evidence_references:
        for ref in case.evidence_references:
            if ref.source_id.startswith("perf-"):
                case_repo.remove_evidence_reference(case_id=case_id, reference_id=ref.reference_id)

    # Populate 50 synthetic evidence references
    for i in range(1, 51):
        case_repo.add_evidence_reference(
            case_id=case_id,
            source_type="event",
            source_id=f"perf-{i}",
            role="SUPPORTING",
            epistemic_status="OBSERVED",
            citation_tag=f"[event:perf-{i}]",
            analyst_annotation=f"Performance event {i}",
        )
    return case_id


def compute_stats(latencies_ms: list[float]) -> dict[str, float]:
    sorted_l = sorted(latencies_ms)
    p95_idx = int(0.95 * len(sorted_l))
    return {
        "median": float(statistics.median(sorted_l)),
        "p95": float(sorted_l[min(p95_idx, len(sorted_l) - 1)]),
        "max": float(max(sorted_l)),
    }


def test_m72_benchmark_operations(perf_case):
    case_id = perf_case
    N = 20

    # 1. Timeline construction
    construction_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        items = timeline_service.build_raw_timeline_items(case_id)
        construction_times.append((time.perf_counter() - t0) * 1000)
    stats_const = compute_stats(construction_times)

    # 2. Timeline filtering
    filter_times = []
    params = TimelineFilterParams(search="Performance", limit=50)
    for _ in range(N):
        t0 = time.perf_counter()
        res = timeline_service.query_timeline(case_id, params)
        filter_times.append((time.perf_counter() - t0) * 1000)
    stats_filter = compute_stats(filter_times)

    # 3. Timeline context lookup
    target_id = items[0].timeline_id if items else "tl-ev-perf-1"
    context_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        ctx = timeline_service.get_timeline_context(case_id, target_id)
        context_times.append((time.perf_counter() - t0) * 1000)
    stats_ctx = compute_stats(context_times)

    # 4. Replay initialization
    replay_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        session = timeline_service.get_replay_session(case_id)
        replay_times.append((time.perf_counter() - t0) * 1000)
    stats_replay = compute_stats(replay_times)

    # 5. Export JSON
    export_times = []
    for _ in range(N):
        t0 = time.perf_counter()
        out, _ = timeline_service.export_timeline(case_id, export_format="json")
        export_times.append((time.perf_counter() - t0) * 1000)
    stats_export = compute_stats(export_times)

    print(f"\n--- M7.2 Performance Benchmark (N={N}) ---")
    print(f"Construction: median={stats_const['median']:.2f}ms, P95={stats_const['p95']:.2f}ms, max={stats_const['max']:.2f}ms")
    print(f"Filtering:    median={stats_filter['median']:.2f}ms, P95={stats_filter['p95']:.2f}ms, max={stats_filter['max']:.2f}ms")
    print(f"Context:      median={stats_ctx['median']:.2f}ms, P95={stats_ctx['p95']:.2f}ms, max={stats_ctx['max']:.2f}ms")
    print(f"Replay Init:  median={stats_replay['median']:.2f}ms, P95={stats_replay['p95']:.2f}ms, max={stats_replay['max']:.2f}ms")
    print(f"Export JSON:  median={stats_export['median']:.2f}ms, P95={stats_export['p95']:.2f}ms, max={stats_export['max']:.2f}ms")

    # Assert bounded latencies on local workstation
    assert stats_const["median"] < 50.0
    assert stats_filter["median"] < 50.0
    assert stats_replay["median"] < 100.0
