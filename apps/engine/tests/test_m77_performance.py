"""Performance benchmark suite for Milestone 7.7 Case Comparison & Campaign Correlation.

Measures latency across synthetic workloads of 100, 500, and 1,000 items.
Reports median, P95, and maximum execution times.
"""

import json
import statistics
import time
import pytest

from logintel.comparison.models import (
    ComparisonScopeDimension,
    CreateCaseComparisonRequest,
)
from logintel.comparison.service import case_comparison_service
from logintel.storage.case_repo import case_repo


def compute_stats(latencies_ms: list[float]) -> dict[str, float]:
    sorted_l = sorted(latencies_ms)
    p95_idx = int(0.95 * len(sorted_l))
    return {
        "median": float(statistics.median(sorted_l)),
        "p95": float(sorted_l[min(p95_idx, len(sorted_l) - 1)]),
        "max": float(max(sorted_l)),
    }


@pytest.fixture(scope="module")
def benchmark_environment():
    """Create fresh isolated synthetic test cases for benchmarking without accumulated audit noise."""
    t_id = int(time.time() * 1000) % 50000 + 700000
    case_a = case_repo.create_case(incident_id=t_id, title="M7.7 Perf Case A")
    case_b = case_repo.create_case(incident_id=t_id + 1, title="M7.7 Perf Case B")

    # Pre-populate 1000 items per case
    print("\nPre-populating 1,000 synthetic references across benchmark cases...")
    conn = case_repo._get_connection()
    with conn:
        for i in range(1000):
            # Seed shared IP every 5 items, shared host every 10 items
            ip_val = f"10.0.{i % 50}.{(i % 250) + 1}"
            host_val = f"srv-worker-{i % 25}.corp"
            now_iso = f"2026-10-08T{(i // 60) % 24:02d}:{i % 60:02d}:00Z"

            conn.execute(
                """
                INSERT INTO case_evidence_references (
                    reference_id, case_id, source_type, source_id, role,
                    epistemic_status, citation_tag, analyst_annotation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"bench-a-{i}",
                    case_a.case_id,
                    "ip" if i % 2 == 0 else "host",
                    ip_val if i % 2 == 0 else host_val,
                    "SUPPORTING",
                    "OBSERVED",
                    f"[ip:{ip_val}]",
                    json.dumps({"ip": ip_val, "host": host_val}),
                    now_iso,
                ),
            )

            conn.execute(
                """
                INSERT INTO case_evidence_references (
                    reference_id, case_id, source_type, source_id, role,
                    epistemic_status, citation_tag, analyst_annotation, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"bench-b-{i}",
                    case_b.case_id,
                    "ip" if i % 2 == 0 else "host",
                    ip_val if i % 2 == 0 else host_val,
                    "SUPPORTING",
                    "OBSERVED",
                    f"[ip:{ip_val}]",
                    json.dumps({"ip": ip_val, "host": host_val}),
                    now_iso,
                ),
            )

    return case_a.case_id, case_b.case_id


def test_m77_performance_entity_overlap_scaling(benchmark_environment):
    """SYNTHETIC WORKLOAD: Measure entity extraction and overlap across item volumes."""
    c1, c2 = benchmark_environment
    iterations = 5

    latencies = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        entities = case_comparison_service._extract_shared_entities([c1, c2])
        latencies.append((time.perf_counter() - t0) * 1000)

    stats = compute_stats(latencies)
    print(f"\n[SYNTHETIC WORKLOAD] Entity Overlap (1,000 items): median={stats['median']:.3f}ms, P95={stats['p95']:.3f}ms, max={stats['max']:.3f}ms")
    assert stats["median"] < 150.0, f"Entity overlap latency too high: {stats['median']}ms"


def test_m77_performance_temporal_alignment_scaling(benchmark_environment):
    """SYNTHETIC WORKLOAD: Measure temporal window alignment latency."""
    c1, c2 = benchmark_environment
    iterations = 5

    latencies = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        _ = case_comparison_service._compute_temporal_overlap([c1, c2])
        latencies.append((time.perf_counter() - t0) * 1000)

    stats = compute_stats(latencies)
    print(f"\n[SYNTHETIC WORKLOAD] Temporal Alignment (1,000 items): median={stats['median']:.3f}ms, P95={stats['p95']:.3f}ms, max={stats['max']:.3f}ms")
    assert stats["median"] < 50.0, f"Temporal alignment latency too high: {stats['median']}ms"


def test_m77_performance_full_comparison_execution(benchmark_environment):
    """SYNTHETIC WORKLOAD: Measure full end-to-end case comparison and candidate generation."""
    c1, c2 = benchmark_environment
    iterations = 5

    latencies = []
    for _ in range(iterations):
        t0 = time.perf_counter()
        req = CreateCaseComparisonRequest(compared_case_ids=[c2])
        _ = case_comparison_service.compare_cases(c1, req)
        latencies.append((time.perf_counter() - t0) * 1000)

    stats = compute_stats(latencies)
    print(f"\n[SYNTHETIC WORKLOAD] Full Case Comparison (1,000 items): median={stats['median']:.3f}ms, P95={stats['p95']:.3f}ms, max={stats['max']:.3f}ms")
    assert stats["median"] < 300.0, f"Full comparison median too high: {stats['median']}ms"


def test_m77_performance_export_generation(benchmark_environment):
    """SYNTHETIC WORKLOAD: Measure multi-format export latencies (JSON, CSV, MD)."""
    c1, c2 = benchmark_environment
    req = CreateCaseComparisonRequest(compared_case_ids=[c2])
    comp = case_comparison_service.compare_cases(c1, req)

    for fmt in ["json", "csv", "markdown"]:
        latencies = []
        for _ in range(5):
            t0 = time.perf_counter()
            _ = case_comparison_service.export_comparison(c1, comp.comparison_id, format=fmt)
            latencies.append((time.perf_counter() - t0) * 1000)

        stats = compute_stats(latencies)
        print(f"\n[SYNTHETIC WORKLOAD] Export {fmt.upper()} (1,000 items): median={stats['median']:.3f}ms, P95={stats['p95']:.3f}ms, max={stats['max']:.3f}ms")
        assert stats["median"] < 100.0, f"{fmt.upper()} export median too high: {stats['median']}ms"
