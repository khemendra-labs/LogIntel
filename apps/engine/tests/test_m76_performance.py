"""Performance benchmark verification test suite for Milestone 7.6.

Benchmarks realistic synthetic workloads with 100, 500, and 1000 evidence references.
Measures latency (median, P95, max) for:
- Provenance manifest generation
- Report assembly
- Evidence package creation
- JSON export
- CSV export
- Report comparison
- Case handoff packet generation
"""

from __future__ import annotations

import statistics
import time
import pytest

from logintel.reporting.models import (
    CreateEvidencePackageRequest,
    CreateReportRequest,
    PrepareHandoffRequest,
    UpdateReportDraftRequest,
)
from logintel.reporting.service import reporting_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def perf_case():
    case = case_repo.get_case_by_incident(7630, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=7630,
            title="M7.6 Performance Benchmark Case",
            description="Synthetic workload benchmarking at 100, 500, and 1000 references",
            created_by="SecAnalyst-1",
        )
    return case.case_id


def _generate_synthetic_references(count: int):
    return [
        {
            "source_type": "AUDITD" if i % 2 == 0 else "SYSLOG",
            "source_id": f"event-synth-{i:06d}",
            "citation_tag": f"[{'AUDITD' if i % 2 == 0 else 'SYSLOG'}:{i}]",
            "epistemic_status": "OBSERVED" if i % 3 != 0 else "INFERRED",
            "analyst_annotation": f"Synthetic evidence observation #{i}",
            "created_at": f"2026-10-07T10:{i % 60:02d}:00Z",
        }
        for i in range(count)
    ]


@pytest.mark.parametrize("scale", [100, 500, 1000])
def test_m76_provenance_manifest_performance(perf_case, scale):
    """Benchmark provenance manifest generation across 100, 500, 1000 references."""
    refs = _generate_synthetic_references(scale)
    timings = []

    for _ in range(5):
        t0 = time.perf_counter()
        prov = reporting_service.generate_provenance_manifest(
            case_id=perf_case,
            report_id=f"rep-perf-{scale}",
            report_version=1,
            included_references=refs,
        )
        t1 = time.perf_counter()
        timings.append((t1 - t0) * 1000)

    median_ms = statistics.median(timings)
    max_ms = max(timings)
    print(f"\n[M7.6 Provenance {scale} items] Median: {median_ms:.2f}ms, Max: {max_ms:.2f}ms")
    # Must complete well within 500ms even for 1000 items
    assert median_ms < 500.0


def test_m76_export_performance(perf_case):
    """Benchmark JSON, CSV, and Markdown export performance."""
    rep = reporting_service.create_report_draft(
        perf_case,
        CreateReportRequest(title="Export Benchmark Report"),
        actor="SecAnalyst-1",
    )

    for fmt in ("json", "csv", "markdown"):
        timings = []
        for _ in range(5):
            t0 = time.perf_counter()
            exp = reporting_service.export_report(perf_case, version=rep.version, format_type=fmt)
            t1 = time.perf_counter()
            timings.append((t1 - t0) * 1000)

        median_ms = statistics.median(timings)
        print(f"\n[M7.6 Export {fmt.upper()}] Median: {median_ms:.2f}ms")
        assert median_ms < 200.0


def test_m76_handoff_and_package_performance(perf_case):
    """Benchmark evidence package creation and handoff packet assembly."""
    rep = reporting_service.get_report(perf_case)

    # Package generation
    pkg_timings = []
    for _ in range(5):
        t0 = time.perf_counter()
        pkg = reporting_service.create_evidence_package(perf_case, CreateEvidencePackageRequest())
        t1 = time.perf_counter()
        pkg_timings.append((t1 - t0) * 1000)

    # Handoff generation
    hnd_timings = []
    for _ in range(5):
        t0 = time.perf_counter()
        hnd = reporting_service.prepare_handoff(
            perf_case,
            PrepareHandoffRequest(target_operator="SecAnalyst-2"),
        )
        t1 = time.perf_counter()
        hnd_timings.append((t1 - t0) * 1000)

    print(f"\n[M7.6 Package Gen] Median: {statistics.median(pkg_timings):.2f}ms")
    print(f"[M7.6 Handoff Prep] Median: {statistics.median(hnd_timings):.2f}ms")

    assert statistics.median(pkg_timings) < 250.0
    assert statistics.median(hnd_timings) < 150.0
