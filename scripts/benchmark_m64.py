#!/usr/bin/env python3
"""High-volume performance and memory benchmark for Network & Socket State Telemetry (M6.4).

Benchmarks:
1. Procfs socket table parsing and hex decoding throughput.
2. Inode-to-process correlation resolver throughput.
3. Delta detection and CanonicalEvent generation.
4. Memory RSS delta and resource leak evaluation across N = 2,000 synthetic entries.
"""

import os
from pathlib import Path
import resource
import tempfile
import time
from typing import List

from logintel.network import (
    ProcNetReader,
    SocketProcessResolver,
    SocketProtocol,
    SocketStateCollector,
)


def generate_synthetic_tcp_table(count: int) -> str:
    """Generate synthetic /proc/net/tcp content with `count` lines."""
    lines = [
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    ]
    for i in range(count):
        # Local IP 10.0.X.Y
        b3 = (i // 256) % 256
        b4 = i % 256
        loc_hex = f"{b4:02X}{b3:02X}000A"
        loc_port = f"{1024 + (i % 60000):04X}"

        if i % 3 == 0:
            # Listening socket
            rem_hex = "00000000"
            rem_port = "0000"
            st_hex = "0A"
        else:
            # Established socket
            rem_hex = "22D85CE9"  # 233.92.216.34
            rem_port = "01BB"      # 443
            st_hex = "01"

        inode = 10000 + i
        uid = 1000
        line = f" {i:4d}: {loc_hex}:{loc_port} {rem_hex}:{rem_port} {st_hex} 00000000:00000000 00:00000000 00000000  {uid:4d}        0 {inode} 1 0000000000000000 100 0 0 10 0"
        lines.append(line)
    return "\n".join(lines) + "\n"


def run_benchmark():
    n_entries = 2000
    print(f"=== LogIntel M6.4 Network & Socket Performance Benchmark (N={n_entries}) ===")

    rusage_before = resource.getrusage(resource.RUSAGE_SELF)
    mem_before_kb = rusage_before.ru_maxrss

    with tempfile.TemporaryDirectory() as tmpdir:
        net_dir = Path(tmpdir) / "net"
        proc_dir = Path(tmpdir) / "proc"
        net_dir.mkdir(parents=True)
        proc_dir.mkdir(parents=True)

        tcp_content = generate_synthetic_tcp_table(n_entries)
        (net_dir / "tcp").write_text(tcp_content)

        # Create 20 mock processes with socket symlinks
        for pid in range(100, 120):
            p_dir = proc_dir / str(pid)
            fd_dir = p_dir / "fd"
            fd_dir.mkdir(parents=True)
            (p_dir / "comm").write_text(f"proc_{pid}\n")
            (p_dir / "cmdline").write_bytes(f"service_{pid}\x00--port\x0080\x00".encode("utf-8"))
            # Link 10 sockets per process
            for s_idx in range(10):
                target_inode = 10000 + (pid - 100) * 10 + s_idx
                os.symlink(f"socket:[{target_inode}]", fd_dir / str(s_idx + 3))

        # 1. Benchmark ProcNetReader parsing
        reader = ProcNetReader(base_path=str(net_dir))
        t0 = time.perf_counter()
        entries = reader.read_socket_table(SocketProtocol.TCP, max_entries=n_entries)
        t_read = time.perf_counter() - t0
        read_eps = len(entries) / t_read if t_read > 0 else 0

        print(f"1. Procfs Hex Decoding:")
        print(f"   Entries decoded:   {len(entries)}")
        print(f"   Duration:          {t_read*1000:.2f} ms")
        print(f"   Throughput:        {read_eps:,.2f} eps")
        print(f"   Avg per entry:     {(t_read / len(entries))*1000:.4f} ms")

        # 2. Benchmark SocketProcessResolver
        resolver = SocketProcessResolver(proc_path=str(proc_dir))
        t0 = time.perf_counter()
        resolved = resolver.resolve_entries(entries)
        t_resolve = time.perf_counter() - t0
        resolve_eps = len(resolved) / t_resolve if t_resolve > 0 else 0

        observed_count = sum(1 for e in resolved if e.epistemic_status == "OBSERVED")
        unknown_count = sum(1 for e in resolved if e.epistemic_status == "UNKNOWN")

        print(f"\n2. Inode-to-Process Resolution:")
        print(f"   Duration:          {t_resolve*1000:.2f} ms")
        print(f"   Throughput:        {resolve_eps:,.2f} eps")
        print(f"   Avg per entry:     {(t_resolve / len(resolved))*1000:.4f} ms")
        print(f"   Observed processes: {observed_count} (epistemic: OBSERVED)")
        print(f"   Unmapped sockets:   {unknown_count} (epistemic: UNKNOWN)")

        # 3. Benchmark Delta Collection and CanonicalEvent generation
        collector = SocketStateCollector(
            proc_net_path=str(net_dir),
            proc_path=str(proc_dir),
        )
        t0 = time.perf_counter()
        events_baseline = collector.collect_events()
        t_baseline = time.perf_counter() - t0

        t0 = time.perf_counter()
        events_poll2 = collector.collect_events()
        t_poll2 = time.perf_counter() - t0

        print(f"\n3. State Delta Detection & Event Generation:")
        print(f"   Baseline poll events: {len(events_baseline)}")
        print(f"   Baseline duration:    {t_baseline*1000:.2f} ms")
        print(f"   Second poll events:   {len(events_poll2)} (0 churn expected)")
        print(f"   Second poll duration: {t_poll2*1000:.2f} ms")

    rusage_after = resource.getrusage(resource.RUSAGE_SELF)
    mem_after_kb = rusage_after.ru_maxrss
    mem_delta_kb = max(0, mem_after_kb - mem_before_kb)

    print(f"\n4. Memory & Leak Evaluation:")
    print(f"   Baseline RSS:      {mem_before_kb} KB")
    print(f"   Post-Run RSS:      {mem_after_kb} KB")
    print(f"   Memory Delta:      {mem_delta_kb} KB")

    print(f"\n=== M6.4 Benchmark Complete ===")


if __name__ == "__main__":
    run_benchmark()
