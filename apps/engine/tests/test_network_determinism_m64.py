"""Determinism Certification Test Suite for Network & Socket Telemetry (Milestone M6.4).

Verifies that 10 consecutive evaluations of synthetic network procfs tables
and process socket mappings produce 100% bit-for-bit identical results.
"""

import hashlib
import json
import os
from pathlib import Path
import tempfile
import pytest

from logintel.network import (
    ProcNetReader,
    SocketProcessResolver,
    SocketProtocol,
    SocketStateCollector,
)

SAMPLE_TCP = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 1002 1 0000000000000000 100 0 0 10 0
   2: 6401A8C0:D431 22D85CE9:01BB 01 00000000:00000000 02:00000215 00000000  1000        0 1003 3 0000000000000000 21 4 21 10 90
"""

SAMPLE_TCP6 = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:0277 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2002 1 0000000000000000 100 0 0 10 0
"""


def test_network_decoding_and_event_determinism():
    """Verify bit-for-bit determinism of socket snapshot and events across 10 repetitions."""
    run_hashes = []

    with tempfile.TemporaryDirectory() as tmpdir:
        net_dir = Path(tmpdir) / "net"
        proc_dir = Path(tmpdir) / "proc"
        net_dir.mkdir(parents=True)
        proc_dir.mkdir(parents=True)

        (net_dir / "tcp").write_text(SAMPLE_TCP)
        (net_dir / "tcp6").write_text(SAMPLE_TCP6)

        # Create mock proc entry for inode 1002
        pid_dir = proc_dir / "5555"
        fd_dir = pid_dir / "fd"
        fd_dir.mkdir(parents=True)
        (pid_dir / "comm").write_text("gunicorn\n")
        (pid_dir / "cmdline").write_bytes(b"gunicorn\x00app:server\x00")
        os.symlink("socket:[1002]", fd_dir / "4")

        for iteration in range(10):
            collector = SocketStateCollector(
                proc_net_path=str(net_dir),
                proc_path=str(proc_dir),
            )
            snapshot = collector.take_snapshot()
            events = collector.collect_events()

            # Serialize snapshot data deterministically
            data_to_hash = {
                "total_count": snapshot.total_count,
                "entries": [
                    {
                        "proto": e.protocol.value,
                        "local": f"{e.local_address}:{e.local_port}",
                        "remote": f"{e.remote_address}:{e.remote_port}",
                        "state": e.state.value,
                        "inode": e.inode,
                        "pid": e.pid,
                        "comm": e.process_name,
                        "is_listening": e.is_listening,
                        "is_outbound": e.is_outbound,
                        "epistemic": e.epistemic_status,
                    }
                    for e in snapshot.entries
                ],
                "event_fps": [ev.event_fingerprint for ev in events],
            }

            serialized = json.dumps(data_to_hash, sort_keys=True)
            digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            run_hashes.append(digest)

    # Certification: All 10 runs produced the exact same hash
    assert len(set(run_hashes)) == 1, f"Determinism failure: observed multiple hashes: {set(run_hashes)}"
