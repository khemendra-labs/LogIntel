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
    case = case_repo.get_case(200, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=200,
            title="M7.4 Benchmark Case",
            description="Synthetic case for performance measurements",
            created_by="SecAnalyst-1",
        )
    return case.case_id


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

        # 2. Attach 10 evidence items
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

    f_med = statistics.median(finding_creation_times)
    e_med = statistics.median(evidence_addition_times)
    h_med = statistics.median(hypothesis_comparison_times)
    exp_med = statistics.median(export_times)

    # Sub-50ms assertions for synthetic benchmark
    assert f_med < 50.0, f"Finding creation median too high: {f_med}ms"
    assert e_med < 100.0, f"10-item evidence addition median too high: {e_med}ms"
    assert h_med < 50.0, f"Hypothesis comparison median too high: {h_med}ms"
    assert exp_med < 50.0, f"Export median too high: {exp_med}ms"
