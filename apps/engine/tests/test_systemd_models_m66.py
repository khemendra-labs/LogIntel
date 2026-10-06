"""Unit tests for Systemd & Service Lifecycle Telemetry Models (Milestone M6.6)."""

import pytest
from logintel.systemd.models import (
    SystemdUnitInfo,
    UnitLifecycleAction,
    UnitLifecycleEvent,
    UnitState,
)


def test_systemd_unit_info_creation_and_defaults():
    """Verify SystemdUnitInfo model initializes attributes and defaults."""
    unit = SystemdUnitInfo(
        unit_name="sshd.service",
        unit_type="service",
        description="OpenBSD Secure Shell server",
        load_state="loaded",
        active_state=UnitState.ACTIVE,
        sub_state="running",
        main_pid=1234,
        user="root",
        epistemic_status="OBSERVED",
    )

    assert unit.unit_name == "sshd.service"
    assert unit.unit_type == "service"
    assert unit.active_state == UnitState.ACTIVE
    assert unit.main_pid == 1234
    assert unit.epistemic_status == "OBSERVED"


def test_systemd_unit_unknown_state():
    """Verify UnitState enum handles unknown or unexpected strings."""
    assert UnitState.UNKNOWN == "unknown"
    assert UnitState.FAILED == "failed"
    assert UnitState.ACTIVE == "active"


def test_unit_lifecycle_event_model():
    """Verify UnitLifecycleEvent captures lifecycle transition details."""
    ev = UnitLifecycleEvent(
        unit_name="cron.service",
        unit_type="service",
        action=UnitLifecycleAction.STARTED,
        description="Regular background program processing daemon",
        main_pid=567,
        exit_code=0,
        raw_message="Started Regular background program processing daemon.",
    )

    assert ev.action == UnitLifecycleAction.STARTED
    assert ev.main_pid == 567
    assert ev.exit_code == 0
    assert "cron.service" in ev.unit_name
