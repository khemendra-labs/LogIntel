"""Performance benchmark suite for Milestone 7.8 Investigation Quality, Closure & Forensic Review.

Measures latency across synthetic workloads of 100, 500, and 1,000 items.
Reports median, P95, and maximum execution times.
"""

import json
import statistics
import time
import pytest

from logintel.ai.domain.case import InvestigationScope
from logintel.review.models import ExportFormat
from logintel.review.service import InvestigationReviewService
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
def perf_environment():
    """Create isolated synthetic cases with 100, 500, and 1,000 evidence references."""
    t_id = int(time.time() * 1000) % 50000 + 750000

    c_100 = case_repo.create_case(incident_id=t_id + 1, title="Perf Case 100")
    c_500 = case_repo.create_case(incident_id=t_id + 2, title="Perf Case 500")
    c_1000 = case_repo.create_case(incident_id=t_id + 3, title="Perf Case 1000")

    cases = [(c_100, 100), (c_500, 500), (c_1000, 1000)]
    conn = case_repo._get_connection()

    for c, count in cases:
        case_repo.update_case_scope(
            case_id=c.case_id,
            scope=InvestigationScope(
                investigation_id=c.incident_id,
                subject_id=f"inc-{c.incident_id}",
                time_start="2026-10-01T00:00:00Z",
                time_end="2026-10-02T00:00:00Z",
                selected_entity_ids=["host:srv-01", "user:admin"],
            ),
        )
        with conn:
            for i in range(count):
                conn.execute(
                    """
                    INSERT INTO case_evidence_references (
                        reference_id, case_id, source_type, source_id, role,
                        epistemic_status, citation_tag, analyst_annotation, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"perf-ref-{c.case_id}-{i}",
                        c.case_id,
                        "ip" if i % 2 == 0 else "host",
                        f"10.0.{i % 50}.{i % 250}",
                        "SUPPORTING",
                        "OBSERVED",
                        f"[ref:{i}]",
                        json.dumps({"index": i}),
                        "2026-10-08T00:00:00Z",
                    ),
                )

    return {100: c_100.case_id, 500: c_500.case_id, 1000: c_1000.case_id}


def test_m78_perf_001_100_items_review_benchmark(perf_environment):
    """Benchmark full 12-gate forensic review on 100 items."""
    service = InvestigationReviewService()
    case_id = perf_environment[100]
    latencies = []

    for _ in range(15):
        t0 = time.perf_counter()
        snapshot = service.run_forensic_review(case_id)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    stats = compute_stats(latencies)
    print(f"\n[PERF-100-ITEMS] Forensic Review: median={stats['median']:.2f}ms, P95={stats['p95']:.2f}ms, max={stats['max']:.2f}ms")
    assert stats["median"] < 100.0, f"100-item review exceeded SLA: {stats['median']:.2f}ms"


def test_m78_perf_002_500_items_review_benchmark(perf_environment):
    """Benchmark full 12-gate forensic review on 500 items."""
    service = InvestigationReviewService()
    case_id = perf_environment[500]
    latencies = []

    for _ in range(10):
        t0 = time.perf_counter()
        snapshot = service.run_forensic_review(case_id)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    stats = compute_stats(latencies)
    print(f"\n[PERF-500-ITEMS] Forensic Review: median={stats['median']:.2f}ms, P95={stats['p95']:.2f}ms, max={stats['max']:.2f}ms")
    assert stats["median"] < 250.0, f"500-item review exceeded SLA: {stats['median']:.2f}ms"


def test_m78_perf_003_1000_items_review_benchmark(perf_environment):
    """Benchmark full 12-gate forensic review on 1,000 items."""
    service = InvestigationReviewService()
    case_id = perf_environment[1000]
    latencies = []

    for _ in range(10):
        t0 = time.perf_counter()
        snapshot = service.run_forensic_review(case_id)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    stats = compute_stats(latencies)
    print(f"\n[PERF-1000-ITEMS] Forensic Review: median={stats['median']:.2f}ms, P95={stats['p95']:.2f}ms, max={stats['max']:.2f}ms")
    assert stats["median"] < 500.0, f"1000-item review exceeded SLA: {stats['median']:.2f}ms"


def test_m78_perf_004_1000_items_export_benchmark(perf_environment):
    """Benchmark deterministic multi-format exports on 1,000 items."""
    service = InvestigationReviewService()
    case_id = perf_environment[1000]
    service.run_forensic_review(case_id)

    formats = [ExportFormat.JSON, ExportFormat.CSV, ExportFormat.MARKDOWN]
    for fmt in formats:
        latencies = []
        for _ in range(10):
            t0 = time.perf_counter()
            exp = service.export_review(case_id, export_format=fmt)
            t1 = time.perf_counter()
            latencies.append((t1 - t0) * 1000.0)

        stats = compute_stats(latencies)
        print(f"\n[PERF-1000-{fmt.value}] Export: median={stats['median']:.2f}ms, P95={stats['p95']:.2f}ms, max={stats['max']:.2f}ms")
        assert stats["median"] < 100.0, f"{fmt.value} export exceeded SLA: {stats['median']:.2f}ms"
