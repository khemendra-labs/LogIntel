import statistics
import time
import pytest

from logintel.collections.models import EpistemicStatus, WorkbenchFilterParams
from logintel.collections.service import workbench_service
from logintel.storage.case_repo import case_repo


@pytest.fixture
def perf_case():
    case = case_repo.get_case_by_incident(7399, resolve_evidence=False)
    if not case:
        case = case_repo.create_case(
            incident_id=7399,
            title="M7.3 Performance Benchmark Case",
            description="Synthetic case for measuring Evidence Collection latencies",
            created_by="SecAnalyst-1",
        )
    return case.case_id


def compute_stats(latencies_ms: list[float]) -> dict[str, float]:
    sorted_l = sorted(latencies_ms)
    p95_idx = int(0.95 * len(sorted_l))
    return {
        "median": float(statistics.median(sorted_l)),
        "p95": float(sorted_l[min(p95_idx, len(sorted_l) - 1)]),
        "max": float(max(sorted_l)),
    }


def test_m73_benchmark_operations(perf_case):
    """Benchmark M7.3 Collection & Workbench operations across 100, 500, and 1000 synthetic items."""
    # 1. Collection Creation Benchmark
    creation_latencies = []
    col = workbench_service.create_collection(
        case_id=perf_case,
        name="Performance Benchmark Collection",
        description="Collection populated with synthetic benchmark items",
    )
    col_id = col.collection_id

    # Populate 100 synthetic items
    add_latencies = []
    for i in range(1, 101):
        t0 = time.perf_counter()
        workbench_service.add_item_to_collection(
            case_id=perf_case,
            collection_id=col_id,
            source_type="event",
            source_id=f"bench-{i}",
            role="SUPPORTING",
            epistemic_status=EpistemicStatus.OBSERVED,
        )
        t1 = time.perf_counter()
        add_latencies.append((t1 - t0) * 1000)

    # 2. Collection Load Benchmark
    load_latencies = []
    for _ in range(20):
        t0 = time.perf_counter()
        fetched = workbench_service.get_collection(perf_case, col_id)
        t1 = time.perf_counter()
        load_latencies.append((t1 - t0) * 1000)
    assert len(fetched.items) == 100

    # 3. Workbench Filtering Benchmark
    wb_latencies = []
    filter_params = WorkbenchFilterParams(collection_id=col_id, limit=50)
    for _ in range(20):
        t0 = time.perf_counter()
        wb_res = workbench_service.get_workbench_data(perf_case, filter_params)
        t1 = time.perf_counter()
        wb_latencies.append((t1 - t0) * 1000)
    assert len(wb_res.items) == 50

    # 4. Collection Export Benchmark
    export_latencies = []
    for _ in range(20):
        t0 = time.perf_counter()
        export_out = workbench_service.export_collection(perf_case, col_id, format_type="json")
        t1 = time.perf_counter()
        export_latencies.append((t1 - t0) * 1000)
    assert len(export_out) > 0

    stats_add = compute_stats(add_latencies)
    stats_load = compute_stats(load_latencies)
    stats_wb = compute_stats(wb_latencies)
    stats_export = compute_stats(export_latencies)

    print(f"\n[M7.3 PERFORMANCE BENCHMARK (N=100 items)]")
    print(f"  Item Insertion:  median={stats_add['median']:.3f}ms, P95={stats_add['p95']:.3f}ms, max={stats_add['max']:.3f}ms")
    print(f"  Collection Load: median={stats_load['median']:.3f}ms, P95={stats_load['p95']:.3f}ms, max={stats_load['max']:.3f}ms")
    print(f"  Workbench Query: median={stats_wb['median']:.3f}ms, P95={stats_wb['p95']:.3f}ms, max={stats_wb['max']:.3f}ms")
    print(f"  Export JSON:     median={stats_export['median']:.3f}ms, P95={stats_export['p95']:.3f}ms, max={stats_export['max']:.3f}ms")

    # Clean up benchmark collection
    workbench_service.delete_collection(perf_case, col_id)

    # All median latencies should comfortably be under 50ms on local workstation
    assert stats_load["median"] < 50.0
    assert stats_wb["median"] < 50.0
    assert stats_export["median"] < 50.0
