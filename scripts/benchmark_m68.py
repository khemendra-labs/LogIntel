"""Performance and memory benchmark for Unified Host Graph (Milestone M6.8)."""

import resource
import time
from logintel.correlation.host_graph import HostGraphBuilder


def run_benchmark():
    builder = HostGraphBuilder()
    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    mem_before_kb = rusage_before.ru_maxrss

    n_events = 2000
    events = []
    for i in range(n_events):
        events.append({
            "id": f"bench-ev-{i}",
            "host": "benchmark-host",
            "username": f"user_{i % 10}",
            "pid": 1000 + i,
            "ppid": 1000 + (i % 20),
            "process_name": f"proc_{i % 50}",
            "dst_ip": f"10.0.{i % 256}.{i % 254 + 1}",
            "event_type": "PROCESS_EXECUTION" if i % 2 == 0 else "NETWORK_CONNECTION_OUTBOUND",
            "metadata": {
                "file_path": f"/tmp/file_{i % 30}.txt",
                "unit_name": f"service_{i % 10}.service",
                "container_id": f"cont_{i % 5}",
            },
        })

    t0 = time.perf_counter()
    graph = builder.build_from_events(host="benchmark-host", events=events)
    elapsed = time.perf_counter() - t0

    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    mem_after_kb = rusage_after.ru_maxrss
    rss_delta_kb = mem_after_kb - mem_before_kb
    throughput = n_events / elapsed if elapsed > 0 else float("inf")

    print(f"=== M6.8 HOST GRAPH BENCHMARK ===")
    print(f"Events processed: {n_events}")
    print(f"Graph nodes: {len(graph.nodes)}")
    print(f"Graph edges: {len(graph.edges)}")
    print(f"Total time: {elapsed * 1000:.2f} ms")
    print(f"Throughput: {throughput:.2f} events/sec")
    print(f"RSS Memory Delta: {rss_delta_kb:.2f} KB")

    assert throughput > 5000, f"Expected >5,000 eps, got {throughput:.2f}"
    print("M6.8 Benchmark Passed Successfully!")


if __name__ == "__main__":
    run_benchmark()
