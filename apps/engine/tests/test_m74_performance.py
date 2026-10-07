import statistics
import time
import pytest

from logintel.findings.models import (
    AddFindingEvidenceRequest,
    CreateFindingRequest,
    CreateHypothesisM74Request,
    FindingEvidenceRole,
)
from logintel.findings.service import findings_workbench_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def bench_case():
    case = case_repo.get_case_by_incident(200, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=200,
            title="M7.4 Benchmark Case",
            description="Synthetic case for performance measurements",
            created_by="SecAnalyst-1",
        )
    case_id = case.case_id
    # Clean up previous benchmark findings and hypotheses for test idempotency
    existing = findings_workbench_service.get_findings(case_id)
    for f in existing:
        findings_workbench_service.delete_finding(case_id, f.finding_id)
    conn = case_repo._get_connection()
    with conn:
        conn.execute("DELETE FROM case_hypotheses WHERE case_id = ?", (case_id,))
    return case_id


def compute_stats(latencies_ms: list[float]) -> dict[str, float]:
    sorted_l = sorted(latencies_ms)
    p95_idx = int(0.95 * len(sorted_l))
    return {
        "median": float(statistics.median(sorted_l)),
        "p95": float(sorted_l[min(p95_idx, len(sorted_l) - 1)]),
        "max": float(max(sorted_l)),
    }


def test_m74_performance_benchmarks(bench_case):
    """Benchmark synthetic workload with 100 evidence items across 10 iterations."""
    iterations = 10
    finding_creation_times = []
    evidence_addition_times = []
    hypothesis_comparison_times = []
    export_times = []

    for i in range(iterations):
        # 1. Create finding
        t0 = time.perf_counter()
        finding = findings_workbench_service.create_finding(
            bench_case,
            CreateFindingRequest(
                title=f"Benchmark Finding {i}",
                statement=f"Synthetic finding statement {i}",
            ),
        )
        finding_creation_times.append((time.perf_counter() - t0) * 1000)

        # 2. Attach 10 evidence items (total 100 across 10 iterations)
        t1 = time.perf_counter()
        for k in range(10):
            findings_workbench_service.add_finding_evidence(
                bench_case,
                finding.finding_id,
                AddFindingEvidenceRequest(
                    source_type="event",
                    source_id=f"bench-evt-{i}-{k}",
                    role=FindingEvidenceRole.SUPPORTING,
                ),
            )
        evidence_addition_times.append((time.perf_counter() - t1) * 1000)

        # 3. Create hypothesis and compare
        findings_workbench_service.create_hypothesis(
            bench_case,
            CreateHypothesisM74Request(
                statement=f"Benchmark hypothesis {i}",
                supporting_evidence=[f"bench-evt-{i}-0"],
            ),
        )
        t2 = time.perf_counter()
        findings_workbench_service.compare_hypotheses(bench_case)
        hypothesis_comparison_times.append((time.perf_counter() - t2) * 1000)

        # 4. Export
        t3 = time.perf_counter()
        findings_workbench_service.export_findings(bench_case, format="json")
        export_times.append((time.perf_counter() - t3) * 1000)

    stats_finding = compute_stats(finding_creation_times)
    stats_evidence = compute_stats(evidence_addition_times)
    stats_hypothesis = compute_stats(hypothesis_comparison_times)
    stats_export = compute_stats(export_times)

    print("\n--- M7.4 Performance Benchmark (N=10 iterations, 100 evidence items) ---")
    print(f"Finding Creation:       median={stats_finding['median']:.3f}ms, P95={stats_finding['p95']:.3f}ms, max={stats_finding['max']:.3f}ms")
    print(f"Evidence Addition (10): median={stats_evidence['median']:.3f}ms, P95={stats_evidence['p95']:.3f}ms, max={stats_evidence['max']:.3f}ms")
    print(f"Hypothesis Comparison:  median={stats_hypothesis['median']:.3f}ms, P95={stats_hypothesis['p95']:.3f}ms, max={stats_hypothesis['max']:.3f}ms")
    print(f"Findings Export JSON:   median={stats_export['median']:.3f}ms, P95={stats_export['p95']:.3f}ms, max={stats_export['max']:.3f}ms")

    # Assert bounded latencies on local workstation
    assert stats_finding["median"] < 50.0, f"Finding creation median too high: {stats_finding['median']}ms"
    assert stats_evidence["median"] < 250.0, f"10-item evidence addition median too high: {stats_evidence['median']}ms"
    assert stats_hypothesis["median"] < 100.0, f"Hypothesis comparison median too high: {stats_hypothesis['median']}ms"
    assert stats_export["median"] < 150.0, f"Export median too high: {stats_export['median']}ms"
