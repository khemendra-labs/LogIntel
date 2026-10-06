#!/usr/bin/env python3
"""High-volume performance and memory benchmark for Container & Namespace Telemetry (M6.7).

Benchmarks:
1. ContainerParser parsing throughput across N = 10,000 synthetic records.
2. CanonicalEvent generation, IOC extraction, and fingerprint calculation.
3. Memory RSS delta and resource leak evaluation.
"""

import resource
import time
from typing import List

from logintel.models import RawRecord
from logintel.parsers.container import ContainerParser


def run_benchmark():
    n_records = 10000
    print(f"=== LogIntel M6.7 Container & Namespace Telemetry Benchmark (N={n_records}) ===")

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    mem_before_kb = rusage_before.ru_maxrss

    records: List[RawRecord] = []
    templates = [
        ("docker", "dockerd[1]: Container {cid} created"),
        ("docker", "dockerd[1]: Container {cid} started"),
        ("docker", "dockerd[1]: Container {cid} started in privileged mode"),
        ("docker", "dockerd[1]: Container {cid} stopped"),
        ("docker", "dockerd[1]: Container {cid} died"),
        ("docker", "dockerd[1]: Container {cid} killed"),
        ("docker", "dockerd[1]: Container {cid} destroyed"),
        ("docker", "dockerd[1]: Container {cid} attempted namespace escape"),
        ("docker", 'msg="container started" container={cid} image="alpine:latest"'),
        ("docker", 'msg="container stopped" container={cid} image="redis:alpine"'),
    ]

    for i in range(n_records):
        src, template = templates[i % len(templates)]
        cid = f"{i:012x}"
        content = template.format(cid=cid)
        records.append(RawRecord(source=src, raw_content=content))

    parser = ContainerParser()

    t0 = time.perf_counter()
    parsed_events = []
    for r in records:
        if parser.can_parse(r):
            ev = parser.parse(r)
            if ev:
                _ = ev.compute_fingerprint()
                parsed_events.append(ev)
    t_parse = time.perf_counter() - t0
    parse_eps = len(parsed_events) / t_parse if t_parse > 0 else 0

    print(f"1. Container Event Parsing:")
    print(f"   Records processed: {len(parsed_events)}")
    print(f"   Duration:          {t_parse*1000:.2f} ms")
    print(f"   Throughput:        {parse_eps:,.2f} events/sec")
    print(f"   Avg per event:     {(t_parse / len(parsed_events))*1000:.4f} ms")

    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    mem_after_kb = rusage_after.ru_maxrss
    mem_delta_kb = max(0, mem_after_kb - mem_before_kb)

    print(f"\n2. Memory & Resource Leak Evaluation:")
    print(f"   Baseline RSS:      {mem_before_kb} KB")
    print(f"   Post-Run RSS:      {mem_after_kb} KB")
    print(f"   Memory Delta:      {mem_delta_kb} KB")

    print(f"\n=== M6.7 Benchmark Complete ===")


if __name__ == "__main__":
    run_benchmark()
