#!/usr/bin/env python3
"""High-volume performance and memory benchmark for Systemd & Kernel Telemetry (M6.6).

Benchmarks:
1. SystemdParser & KernelParser parsing throughput across N = 10,000 synthetic records.
2. CanonicalEvent generation, IOC extraction, and fingerprint calculation.
3. Memory RSS delta and resource leak evaluation.
"""

import resource
import time
from typing import List

from logintel.models import RawRecord
from logintel.parsers.kernel import KernelParser
from logintel.parsers.systemd import SystemdParser


def run_benchmark():
    n_records = 10000
    print(f"=== LogIntel M6.6 Systemd & Kernel Telemetry Benchmark (N={n_records}) ===")

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    mem_before_kb = rusage_before.ru_maxrss

    # Generate synthetic stream of systemd and kernel security records
    records: List[RawRecord] = []
    templates = [
        ("syslog", "Oct 06 12:00:01 ubuntu systemd[1]: Starting OpenBSD Secure Shell server..."),
        ("syslog", "Oct 06 12:00:02 ubuntu systemd[1]: Started OpenBSD Secure Shell server."),
        ("syslog", "Oct 06 12:00:03 ubuntu systemd[1]: Failed to start malicious_{i}.service."),
        ("syslog", "Oct 06 12:00:04 ubuntu systemd[1]: Reloaded nginx.service."),
        ("syslog", "Oct 06 12:00:05 ubuntu systemd[1]: Stopping User Manager for UID {i}..."),
        ("syslog", "Oct 06 12:00:06 ubuntu systemd[1]: Stopped User Manager for UID {i}."),
        ("kern.log", "Oct 06 12:00:07 ubuntu kernel: module: loading out-of-tree module taints kernel."),
        ("kern.log", "Oct 06 12:00:08 ubuntu kernel: device eth{i} entered promiscuous mode"),
        ("kern.log", "Oct 06 12:00:09 ubuntu kernel: module verification failed: signature and/or required key missing"),
        ("kern.log", "Oct 06 12:00:10 ubuntu kernel: loading module wireguard_{i}"),
    ]

    for i in range(n_records):
        src, template = templates[i % len(templates)]
        content = template.format(i=i)
        records.append(RawRecord(source=src, raw_content=content))

    sys_parser = SystemdParser()
    kern_parser = KernelParser()

    t0 = time.perf_counter()
    parsed_events = []
    for r in records:
        if sys_parser.can_parse(r):
            ev = sys_parser.parse(r)
        elif kern_parser.can_parse(r):
            ev = kern_parser.parse(r)
        else:
            ev = None
        if ev:
            _ = ev.compute_fingerprint()
            parsed_events.append(ev)
    t_parse = time.perf_counter() - t0
    parse_eps = len(parsed_events) / t_parse if t_parse > 0 else 0

    print(f"1. Systemd & Kernel Event Parsing:")
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

    print(f"\n=== M6.6 Benchmark Complete ===")


if __name__ == "__main__":
    run_benchmark()
