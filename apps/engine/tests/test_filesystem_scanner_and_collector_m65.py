"""Unit tests for FileIntegrityScanner and FilesystemPersistenceCollector (Milestone M6.5)."""

import os
from pathlib import Path
import tempfile
import pytest

from logintel.filesystem.collector import FilesystemPersistenceCollector
from logintel.filesystem.models import (
    FileTransitionType,
    HVTTarget,
    TargetCategory,
)
from logintel.filesystem.scanner import FileIntegrityScanner
from logintel.models import EventType, Severity


def test_scanner_single_file_and_hash():
    """Verify scanning single file correctly calculates size and SHA-256 hash."""
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = Path(tmpdir) / "test_file.conf"
        content = b"root:x:0:0:root:/root:/bin/bash\n"
        test_file.write_bytes(content)

        import hashlib
        expected_hash = hashlib.sha256(content).hexdigest()

        scanner = FileIntegrityScanner()
        state = scanner.scan_path(str(test_file), TargetCategory.ACCOUNT_PRIVILEGE)

        assert state is not None
        assert state.exists is True
        assert state.size_bytes == len(content)
        assert state.sha256_hash == expected_hash
        assert state.epistemic_status == "OBSERVED"


def test_scanner_directory_traversal():
    """Verify scanning directory discovers child files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        dir_path = Path(tmpdir) / "cron.d"
        dir_path.mkdir()
        (dir_path / "job1").write_text("* * * * * root /bin/sync\n")
        (dir_path / "job2").write_text("0 0 * * * root /bin/backup\n")

        target = HVTTarget(path=str(dir_path), category=TargetCategory.PERSISTENCE_CRON, is_directory=True)
        scanner = FileIntegrityScanner(targets=[target])
        results = scanner.scan_all()

        assert len(results) >= 2
        file_names = [Path(p).name for p in results.keys()]
        assert "job1" in file_names
        assert "job2" in file_names


def test_collector_baseline_and_delta_transitions():
    """Verify collector baseline poll and delta detection across file creation, modification, and deletion."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cron_dir = Path(tmpdir) / "cron.d"
        cron_dir.mkdir()
        initial_job = cron_dir / "job_orig"
        initial_job.write_text("initial cron script\n")

        target = HVTTarget(path=str(cron_dir), category=TargetCategory.PERSISTENCE_CRON, is_directory=True)
        collector = FilesystemPersistenceCollector(targets=[target])

        # 1. Baseline Poll
        base_events = collector.collect_events()
        assert len(base_events) >= 1
        assert all(ev.metadata["is_baseline"] is True for ev in base_events)

        # 2. Immediate Second Poll (no changes -> 0 events)
        second_events = collector.collect_events()
        assert len(second_events) == 0

        # 3. Create new persistence drop
        drop_job = cron_dir / "job_evil"
        drop_job.write_text("malicious payload\n")
        drop_events = collector.collect_events()
        assert len(drop_events) == 1
        ev_drop = drop_events[0]
        assert ev_drop.event_type == EventType.FILE_PERSISTENCE_DROP
        assert ev_drop.severity == Severity.ALERT
        assert "job_evil" in ev_drop.summary

        # 4. Modify original file
        initial_job.write_text("modified cron script with backdoors\n")
        mod_events = collector.collect_events()
        assert len(mod_events) == 1
        ev_mod = mod_events[0]
        assert ev_mod.event_type == EventType.FILE_INTEGRITY_MODIFY
        assert "modified" in ev_mod.summary.lower()

        # 5. Delete drop job
        drop_job.unlink()
        del_events = collector.collect_events()
        assert len(del_events) == 1
        ev_del = del_events[0]
        assert ev_del.event_type == EventType.FILE_PERSISTENCE_REMOVE
        assert "removed" in ev_del.summary.lower()


def test_collector_metadata_chmod_change():
    """Verify collector detects file permission changes without content changes."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sec_file = Path(tmpdir) / "sudoers"
        sec_file.write_text("root ALL=(ALL) ALL\n")
        os.chmod(sec_file, 0o440)

        target = HVTTarget(path=str(sec_file), category=TargetCategory.ACCOUNT_PRIVILEGE)
        collector = FilesystemPersistenceCollector(targets=[target])

        # Baseline
        _ = collector.collect_events()

        # Change permission to world-writable 0o666
        os.chmod(sec_file, 0o666)
        meta_events = collector.collect_events()
        assert len(meta_events) == 1
        ev = meta_events[0]
        assert ev.event_type == EventType.FILE_METADATA_MODIFY
        assert ev.severity == Severity.WARNING
        assert "0o666" in ev.summary or "permissions" in ev.summary.lower()
