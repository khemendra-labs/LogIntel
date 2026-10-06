"""Determinism Certification Test Suite for Filesystem & Persistence Telemetry (Milestone M6.5).

Verifies that 10 consecutive evaluations of scanning synthetic HVT directory trees
and state transition processing produce 100% bit-for-bit identical results.
"""

import hashlib
import json
from pathlib import Path
import tempfile
import pytest

from logintel.filesystem import (
    FilesystemPersistenceCollector,
    HVTTarget,
    TargetCategory,
)


def test_filesystem_scanning_and_event_determinism():
    """Verify bit-for-bit determinism of filesystem baseline and transitions across 10 repetitions."""
    run_hashes = []

    with tempfile.TemporaryDirectory() as tmpdir:
        cron_dir = Path(tmpdir) / "cron.d"
        cron_dir.mkdir(parents=True)
        (cron_dir / "job_a").write_text("* * * * * root /bin/sync\n")
        (cron_dir / "job_b").write_text("0 0 * * * root /bin/backup\n")

        sec_dir = Path(tmpdir) / "security"
        sec_dir.mkdir(parents=True)
        (sec_dir / "sudoers").write_text("root ALL=(ALL) ALL\n")

        targets = [
            HVTTarget(path=str(cron_dir), category=TargetCategory.PERSISTENCE_CRON, is_directory=True),
            HVTTarget(path=str(sec_dir / "sudoers"), category=TargetCategory.ACCOUNT_PRIVILEGE),
        ]

        for iteration in range(10):
            collector = FilesystemPersistenceCollector(targets=targets)
            events = collector.collect_events()
            tracked = collector.get_tracked_states()

            # Serialize tracked states deterministically
            data_to_hash = {
                "tracked": sorted(
                    [
                        {
                            "path": s.path,
                            "category": s.category.value,
                            "size": s.size_bytes,
                            "mode": s.mode_octal,
                            "sha256": s.sha256_hash,
                            "epistemic": s.epistemic_status,
                        }
                        for s in tracked.values()
                    ],
                    key=lambda x: x["path"],
                ),
                "event_fps": sorted([ev.event_fingerprint for ev in events]),
            }

            serialized = json.dumps(data_to_hash, sort_keys=True)
            digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            run_hashes.append(digest)

    # Certification: All 10 repetitions produced the exact same hash
    assert len(set(run_hashes)) == 1, f"Determinism failure: observed multiple hashes: {set(run_hashes)}"
