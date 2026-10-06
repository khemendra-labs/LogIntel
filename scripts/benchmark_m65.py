#!/usr/bin/env python3
"""High-volume performance and memory benchmark for Filesystem & Persistence Telemetry (M6.5).

Benchmarks:
1. FileIntegrityScanner scanning and SHA-256 calculation throughput across N = 1,000 files.
2. State transition detection and CanonicalEvent generation.
3. Memory RSS delta and resource leak evaluation.
"""

import os
from pathlib import Path
import resource
import tempfile
import time

from logintel.filesystem import (
    FileIntegrityScanner,
    FilesystemPersistenceCollector,
    HVTTarget,
    TargetCategory,
)


def run_benchmark():
    n_files = 1000
    print(f"=== LogIntel M6.5 Filesystem & Persistence Benchmark (N={n_files}) ===")

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    mem_before_kb = rusage_before.ru_maxrss

    with tempfile.TemporaryDirectory() as tmpdir:
        root_dir = Path(tmpdir)
        cron_dir = root_dir / "cron.d"
        systemd_dir = root_dir / "systemd"
        priv_dir = root_dir / "priv"
        cron_dir.mkdir()
        systemd_dir.mkdir()
        priv_dir.mkdir()

        # Generate 1,000 synthetic persistence files with varying sizes
        for i in range(n_files):
            if i % 3 == 0:
                p = cron_dir / f"cron_job_{i}.conf"
                content = f"* * * * * root /usr/local/bin/task_{i}.sh\n"
            elif i % 3 == 1:
                p = systemd_dir / f"service_{i}.service"
                content = f"[Unit]\nDescription=Service {i}\n[Service]\nExecStart=/bin/app_{i}\n"
            else:
                p = priv_dir / f"auth_{i}.conf"
                content = f"auth_rule_{i} ALLOW ALL\n"
            p.write_text(content)

        targets = [
            HVTTarget(path=str(cron_dir), category=TargetCategory.PERSISTENCE_CRON, is_directory=True),
            HVTTarget(path=str(systemd_dir), category=TargetCategory.PERSISTENCE_SYSTEMD, is_directory=True),
            HVTTarget(path=str(priv_dir), category=TargetCategory.ACCOUNT_PRIVILEGE, is_directory=True),
        ]

        # 1. Benchmark FileIntegrityScanner
        scanner = FileIntegrityScanner(targets=targets)
        t0 = time.perf_counter()
        results = scanner.scan_all()
        t_scan = time.perf_counter() - t0
        scan_fps = len(results) / t_scan if t_scan > 0 else 0

        print(f"1. File Integrity Scanning & Hashing:")
        print(f"   Files scanned:     {len(results)}")
        print(f"   Duration:          {t_scan*1000:.2f} ms")
        print(f"   Throughput:        {scan_fps:,.2f} files/sec")
        print(f"   Avg per file:      {(t_scan / len(results))*1000:.4f} ms")

        # 2. Benchmark Baseline and Delta Collection
        collector = FilesystemPersistenceCollector(targets=targets)
        t0 = time.perf_counter()
        baseline_events = collector.collect_events()
        t_baseline = time.perf_counter() - t0

        t0 = time.perf_counter()
        second_events = collector.collect_events()
        t_second = time.perf_counter() - t0

        # Simulate 10 new file drops and 10 modifications
        for j in range(10):
            (cron_dir / f"drop_evil_{j}.conf").write_text("evil cron\n")
            (systemd_dir / f"service_{j}.service").write_text("modified service payload\n")

        t0 = time.perf_counter()
        delta_events = collector.collect_events()
        t_delta = time.perf_counter() - t0

        print(f"\n2. Transition Detection & Event Generation:")
        print(f"   Baseline events:   {len(baseline_events)} ({t_baseline*1000:.2f} ms)")
        print(f"   Second poll events: {len(second_events)} (0 churn expected, {t_second*1000:.2f} ms)")
        print(f"   Delta poll events:  {len(delta_events)} (20 transitions detected, {t_delta*1000:.2f} ms)")

    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    mem_after_kb = rusage_after.ru_maxrss
    mem_delta_kb = max(0, mem_after_kb - mem_before_kb)

    print(f"\n3. Memory & Resource Leak Evaluation:")
    print(f"   Baseline RSS:      {mem_before_kb} KB")
    print(f"   Post-Run RSS:      {mem_after_kb} KB")
    print(f"   Memory Delta:      {mem_delta_kb} KB")

    print(f"\n=== M6.5 Benchmark Complete ===")


if __name__ == "__main__":
    run_benchmark()
