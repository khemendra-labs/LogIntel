"""Unit tests for Filesystem & Persistence Telemetry Models (Milestone M6.5)."""

from datetime import datetime, timezone
import pytest

from logintel.filesystem.models import (
    DEFAULT_HVT_TARGETS,
    FileState,
    FileTransition,
    FileTransitionType,
    HVTTarget,
    TargetCategory,
)


def test_file_state_creation_and_properties():
    """Verify FileState model properties and epistemic status default."""
    state = FileState(
        path="/etc/crontab",
        category=TargetCategory.PERSISTENCE_CRON,
        exists=True,
        inode=12345,
        size_bytes=1024,
        mode_octal="0o644",
        uid=0,
        gid=0,
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        epistemic_status="OBSERVED",
    )

    assert state.exists
    assert state.is_hash_available
    assert not state.is_symlink
    assert not state.is_dir
    assert state.epistemic_status == "OBSERVED"


def test_file_state_unreadable_hash_none():
    """Verify FileState handles unreadable files with epistemic status."""
    state = FileState(
        path="/etc/shadow",
        category=TargetCategory.ACCOUNT_PRIVILEGE,
        exists=True,
        inode=67890,
        size_bytes=1500,
        mode_octal="0o640",
        uid=0,
        gid=42,
        sha256_hash=None,
        epistemic_status="PERMISSION_RESTRICTED",
    )

    assert not state.is_hash_available
    assert state.epistemic_status == "PERMISSION_RESTRICTED"


def test_file_transition_model():
    """Verify FileTransition model captures previous and current state."""
    s1 = FileState(
        path="/etc/cron.d/test_job",
        category=TargetCategory.PERSISTENCE_CRON,
        sha256_hash="hash_a",
    )
    s2 = FileState(
        path="/etc/cron.d/test_job",
        category=TargetCategory.PERSISTENCE_CRON,
        sha256_hash="hash_b",
    )

    trans = FileTransition(
        path="/etc/cron.d/test_job",
        category=TargetCategory.PERSISTENCE_CRON,
        transition_type=FileTransitionType.MODIFIED,
        previous_state=s1,
        current_state=s2,
        details="Hash mismatch detected",
    )

    assert trans.transition_type == FileTransitionType.MODIFIED
    assert trans.previous_state.sha256_hash == "hash_a"
    assert trans.current_state.sha256_hash == "hash_b"


def test_default_hvt_targets_coverage():
    """Verify that default HVT target list covers all required persistence and privilege vectors."""
    categories = {t.category for t in DEFAULT_HVT_TARGETS}
    assert TargetCategory.PERSISTENCE_CRON in categories
    assert TargetCategory.PERSISTENCE_SSH in categories
    assert TargetCategory.PERSISTENCE_SYSTEMD in categories
    assert TargetCategory.PERSISTENCE_SHELL in categories
    assert TargetCategory.ACCOUNT_PRIVILEGE in categories
    assert TargetCategory.DYNAMIC_LINKER in categories
    assert len(DEFAULT_HVT_TARGETS) >= 15
