"""Comprehensive test suite for LogIntel M2.5 Privilege & Process Detection Rules."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
import pytest

from logintel.models import Actor, CanonicalEvent, EventType, Network, Outcome, Process, Severity
from logintel.detection import (
    DetectionEngine,
    DetectionResult,
    EvidenceRole,
    RuleCategory,
    RuleRegistry,
    RuleType,
    load_default_rules,
)


def _make_priv_event(
    event_id: str,
    ts: datetime,
    event_type: EventType = EventType.SUDO_COMMAND,
    outcome: Outcome = Outcome.SUCCESS,
    host: str = "srv-01",
    username: Optional[str] = "alice",
    process_name: str = "sudo",
    command_line: Optional[str] = "/bin/bash",
    summary: str = "User executed command",
    parser: str = "sudo_privilege",
    metadata: Optional[dict] = None,
) -> CanonicalEvent:
    """Helper to construct realistic privilege and process CanonicalEvents."""
    actor = Actor(username=username, uid=1000 if username != "root" else 0) if username else None
    return CanonicalEvent(
        id=event_id,
        timestamp=ts,
        ingested_at=ts,
        host=host,
        source="/var/log/auth.log" if parser == "sudo_privilege" else "/var/log/kern.log",
        event_type=event_type,
        severity=Severity.ALERT if outcome == Outcome.FAILURE else Severity.NOTICE,
        actor=actor,
        process=Process(
            name=process_name,
            executable=f"/usr/bin/{process_name}",
            command_line=command_line,
        ),
        network=Network(),
        action="sudo_command" if parser == "sudo_privilege" else "kernel_alert",
        outcome=outcome,
        summary=summary,
        raw_message=summary,
        parser=parser,
        metadata=metadata or {},
    )


# ============================================================================
# 1. RULE LOADING & REGISTRY TESTS
# ============================================================================

def test_load_privilege_and_process_rules():
    """Verify that all default privilege and process rules load cleanly."""
    rules = load_default_rules()
    rule_map = {r.id: r for r in rules}

    expected_priv_ids = {
        "priv.sudo_failure",
        "priv.unauthorized_sudo",
        "priv.sudo_root_shell",
    }
    expected_proc_ids = {
        "proc.apparmor_denial",
        "proc.reconnaissance_tools",
        "proc.segfault_burst",
    }

    assert expected_priv_ids.issubset(set(rule_map.keys())), "Missing privilege rules"
    assert expected_proc_ids.issubset(set(rule_map.keys())), "Missing process rules"

    for r_id in expected_priv_ids:
        r = rule_map[r_id]
        assert r.category == RuleCategory.PRIVILEGE
        assert r.enabled is True

    for r_id in expected_proc_ids:
        r = rule_map[r_id]
        assert r.category == RuleCategory.PROCESS
        assert r.enabled is True

    assert rule_map["priv.sudo_failure"].rule_type == RuleType.THRESHOLD
    assert rule_map["priv.unauthorized_sudo"].rule_type == RuleType.ATOMIC
    assert rule_map["priv.sudo_root_shell"].rule_type == RuleType.ATOMIC
    assert rule_map["proc.apparmor_denial"].rule_type == RuleType.ATOMIC
    assert rule_map["proc.reconnaissance_tools"].rule_type == RuleType.ATOMIC
    assert rule_map["proc.segfault_burst"].rule_type == RuleType.THRESHOLD


def test_registry_category_filtering():
    """Verify registry can query rules specifically by PRIVILEGE and PROCESS categories."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())

    priv_rules = registry.get_rules_by_category(RuleCategory.PRIVILEGE)
    proc_rules = registry.get_rules_by_category(RuleCategory.PROCESS)

    assert len(priv_rules) == 3
    assert {r.id for r in priv_rules} == {
        "priv.sudo_failure",
        "priv.unauthorized_sudo",
        "priv.sudo_root_shell",
    }

    assert len(proc_rules) == 3
    assert {r.id for r in proc_rules} == {
        "proc.apparmor_denial",
        "proc.reconnaissance_tools",
        "proc.segfault_burst",
    }


# ============================================================================
# 2. PRIVILEGE ELEVATION RULES
# ============================================================================

def test_priv_sudo_failure_positive():
    """Positive test: 3 sudo failures for a user within 180s triggers threshold alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 11, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(3):
        event = _make_priv_event(
            event_id=f"sudo-fail-{i}",
            ts=base_time + timedelta(seconds=i * 30),
            event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
            outcome=Outcome.FAILURE,
            username="badactor",
            host="app-prod-01",
            summary="Sudo privilege elevation failure for user 'badactor': 3 incorrect password attempts",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "priv.sudo_failure"])

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "priv.sudo_failure"
    assert det.get_trigger_event_id() == "sudo-fail-2"
    assert len(det.evidence_event_ids) == 3
    roles = list(det.evidence_roles.values())
    assert roles.count(EvidenceRole.TRIGGER) == 1
    assert roles.count(EvidenceRole.AGGREGATE) == 2


def test_priv_sudo_failure_negative_sub_threshold():
    """Negative test: 2 sudo failures (threshold=3) produces 0 detections."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 11, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(2):
        event = _make_priv_event(
            event_id=f"sudo-fail-sub-{i}",
            ts=base_time + timedelta(seconds=i * 30),
            event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
            outcome=Outcome.FAILURE,
            username="badactor",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "priv.sudo_failure"])

    assert len(results) == 0


def test_priv_sudo_failure_negative_different_users():
    """Negative test: Failures targeting distinct users do not cross-accumulate."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 11, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(2):
        e1 = _make_priv_event(f"e-u1-{i}", base_time + timedelta(seconds=i * 20), event_type=EventType.PRIVILEGE_ELEVATION_FAILURE, outcome=Outcome.FAILURE, username="user1")
        e2 = _make_priv_event(f"e-u2-{i}", base_time + timedelta(seconds=i * 20), event_type=EventType.PRIVILEGE_ELEVATION_FAILURE, outcome=Outcome.FAILURE, username="user2")
        results.extend([r for r in engine.evaluate_event(e1) if r.rule_id == "priv.sudo_failure"])
        results.extend([r for r in engine.evaluate_event(e2) if r.rule_id == "priv.sudo_failure"])

    assert len(results) == 0


def test_priv_unauthorized_sudo_positive():
    """Positive test: User not in sudoers triggers immediate CRITICAL alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_priv_event(
        event_id="unauth-sudo-1",
        ts=datetime(2026, 9, 30, 11, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
        outcome=Outcome.FAILURE,
        username="guest",
        summary="Sudo privilege elevation failure for user 'guest': user NOT in sudoers",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "priv.unauthorized_sudo"]

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "priv.unauthorized_sudo"
    assert registry.get("priv.unauthorized_sudo").severity == Severity.CRITICAL
    assert det.get_trigger_event_id() == "unauth-sudo-1"
    assert det.evidence_roles["unauth-sudo-1"] == EvidenceRole.TRIGGER


def test_priv_unauthorized_sudo_negative():
    """Negative test: Normal sudo failure (incorrect password) does not match unauthorized_sudo rule."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_priv_event(
        event_id="pw-fail-1",
        ts=datetime(2026, 9, 30, 11, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.PRIVILEGE_ELEVATION_FAILURE,
        outcome=Outcome.FAILURE,
        username="alice",
        summary="Sudo privilege elevation failure for user 'alice': 1 incorrect password attempt",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "priv.unauthorized_sudo"]
    assert len(results) == 0


def test_priv_sudo_root_shell_positive():
    """Positive test: Interactive root shell spawned via sudo triggers WARNING alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    shells = ["/bin/bash", "/bin/sh", "su -", "/bin/zsh", "bash", "/usr/bin/su"]
    for idx, shell_cmd in enumerate(shells):
        event = _make_priv_event(
            event_id=f"shell-pos-{idx}",
            ts=datetime(2026, 9, 30, 11, idx, 0, tzinfo=timezone.utc),
            event_type=EventType.SUDO_COMMAND,
            outcome=Outcome.SUCCESS,
            username="bob",
            command_line=shell_cmd,
            summary=f"User 'bob' executed privileged command '{shell_cmd}' as 'root'",
        )
        results = [r for r in engine.evaluate_event(event) if r.rule_id == "priv.sudo_root_shell"]
        assert len(results) == 1, f"Failed to match shell: {shell_cmd}"
        assert results[0].rule_id == "priv.sudo_root_shell"
        assert results[0].get_trigger_event_id() == f"shell-pos-{idx}"


def test_priv_sudo_root_shell_negative():
    """Negative test: Benign non-shell commands do not match sudo_root_shell."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    commands = [
        "systemctl restart nginx",
        "cat /etc/hosts",
        "apt-get update",
        "tail -f /var/log/syslog",
    ]
    for idx, cmd in enumerate(commands):
        event = _make_priv_event(
            event_id=f"benign-cmd-{idx}",
            ts=datetime(2026, 9, 30, 11, idx, 0, tzinfo=timezone.utc),
            event_type=EventType.SUDO_COMMAND,
            outcome=Outcome.SUCCESS,
            username="bob",
            command_line=cmd,
        )
        results = [r for r in engine.evaluate_event(event) if r.rule_id == "priv.sudo_root_shell"]
        assert len(results) == 0, f"False positive for benign command: {cmd}"


# ============================================================================
# 3. PROCESS & SECURITY MONITORING RULES
# ============================================================================

def test_proc_apparmor_denial_positive():
    """Positive test: Kernel AppArmor denial event triggers immediate ALERT."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_priv_event(
        event_id="aa-denial-1",
        ts=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.SECURITY_ACCESS_DENIED,
        outcome=Outcome.FAILURE,
        process_name="nginx",
        parser="linux_kernel",
        summary="AppArmor security policy DENIED operation 'open' for profile '/usr/sbin/nginx' on target '/etc/shadow'",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "proc.apparmor_denial"]

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "proc.apparmor_denial"
    assert registry.get("proc.apparmor_denial").severity == Severity.ALERT
    assert det.get_trigger_event_id() == "aa-denial-1"


def test_proc_apparmor_denial_negative_different_parser():
    """Negative test: Non-kernel parser or outcome=SUCCESS does not trigger."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    event = _make_priv_event(
        event_id="aa-neg-1",
        ts=datetime(2026, 9, 30, 12, 0, 0, tzinfo=timezone.utc),
        event_type=EventType.SECURITY_ACCESS_DENIED,
        outcome=Outcome.FAILURE,
        parser="generic_syslog",
    )
    results = [r for r in engine.evaluate_event(event) if r.rule_id == "proc.apparmor_denial"]
    assert len(results) == 0


def test_proc_reconnaissance_tools_positive():
    """Positive test: Execution of reconnaissance tools via sudo triggers NOTICE alert."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    recon_commands = [
        "nmap -sS -p 1-1000 10.0.0.1",
        "/usr/bin/tcpdump -i eth0 -n",
        "wireshark",
        "tshark -i any",
        "masscan -p80 192.168.1.0/24",
    ]
    for idx, cmd in enumerate(recon_commands):
        event = _make_priv_event(
            event_id=f"recon-pos-{idx}",
            ts=datetime(2026, 9, 30, 12, idx, 0, tzinfo=timezone.utc),
            event_type=EventType.SUDO_COMMAND,
            outcome=Outcome.SUCCESS,
            command_line=cmd,
        )
        results = [r for r in engine.evaluate_event(event) if r.rule_id == "proc.reconnaissance_tools"]
        assert len(results) == 1, f"Failed to detect recon tool: {cmd}"
        assert results[0].rule_id == "proc.reconnaissance_tools"


def test_proc_reconnaissance_tools_negative():
    """Negative test: Benign tools or package installations do not match."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    benign_commands = [
        "apt-get install nmap",
        "systemctl status tcpdump",
        "ls -la /var/log",
    ]
    for idx, cmd in enumerate(benign_commands):
        event = _make_priv_event(
            event_id=f"recon-neg-{idx}",
            ts=datetime(2026, 9, 30, 12, idx, 0, tzinfo=timezone.utc),
            event_type=EventType.SUDO_COMMAND,
            outcome=Outcome.SUCCESS,
            command_line=cmd,
        )
        results = [r for r in engine.evaluate_event(event) if r.rule_id == "proc.reconnaissance_tools"]
        assert len(results) == 0, f"False positive for benign command: {cmd}"


def test_proc_segfault_burst_positive():
    """Positive test: 3 application crashes (segfaults) in 120s triggers ALERT."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 13, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(3):
        event = _make_priv_event(
            event_id=f"seg-pos-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            event_type=EventType.KERNEL_MESSAGE,
            outcome=Outcome.FAILURE,
            process_name="vulnerable_svc",
            host="srv-app-02",
            parser="linux_kernel",
            summary="Application crash: segfault in 'vulnerable_svc' (PID: 4321) at memory address 0xdeadbeef",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "proc.segfault_burst"])

    assert len(results) == 1
    det = results[0]
    assert det.rule_id == "proc.segfault_burst"
    assert det.get_trigger_event_id() == "seg-pos-2"
    assert len(det.evidence_event_ids) == 3


def test_proc_segfault_burst_negative_sub_threshold():
    """Negative test: 2 segfaults (threshold=3) produces 0 detections."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 13, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(2):
        event = _make_priv_event(
            event_id=f"seg-sub-{i}",
            ts=base_time + timedelta(seconds=i * 20),
            event_type=EventType.KERNEL_MESSAGE,
            outcome=Outcome.FAILURE,
            process_name="vulnerable_svc",
            summary="Application crash: segfault in 'vulnerable_svc' (PID: 4321)",
        )
        res = engine.evaluate_event(event)
        results.extend([r for r in res if r.rule_id == "proc.segfault_burst"])

    assert len(results) == 0


def test_proc_segfault_burst_negative_separated_processes():
    """Negative test: Crashes in distinct processes do not trigger threshold."""
    registry = RuleRegistry()
    registry.register_many(load_default_rules())
    engine = DetectionEngine(registry)

    base_time = datetime(2026, 9, 30, 13, 0, 0, tzinfo=timezone.utc)
    results: List[DetectionResult] = []

    for i in range(2):
        e1 = _make_priv_event(f"seg-p1-{i}", base_time + timedelta(seconds=i * 15), event_type=EventType.KERNEL_MESSAGE, outcome=Outcome.FAILURE, process_name="proc_alpha", summary="segfault in proc_alpha")
        e2 = _make_priv_event(f"seg-p2-{i}", base_time + timedelta(seconds=i * 15), event_type=EventType.KERNEL_MESSAGE, outcome=Outcome.FAILURE, process_name="proc_beta", summary="segfault in proc_beta")
        results.extend([r for r in engine.evaluate_event(e1) if r.rule_id == "proc.segfault_burst"])
        results.extend([r for r in engine.evaluate_event(e2) if r.rule_id == "proc.segfault_burst"])

    assert len(results) == 0
