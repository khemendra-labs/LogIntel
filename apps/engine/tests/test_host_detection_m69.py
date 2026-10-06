"""Test suite for declarative host detection rules (Milestone M6.9)."""

from datetime import datetime, timezone
import pytest

from logintel.detection.engine import DetectionEngine
from logintel.detection.loader import load_default_rules
from logintel.models import Actor, CanonicalEvent, EventType, Network, Outcome, Process, Severity


from logintel.detection.registry import RuleRegistry


@pytest.fixture
def detection_engine():
    registry = RuleRegistry()
    for rule in load_default_rules():
        registry.register(rule)
    engine = DetectionEngine(registry=registry)
    return engine



def _make_event(
    event_id: str,
    event_type: EventType,
    outcome: Outcome = Outcome.SUCCESS,
    process_name: str = "test",
    process_exe: str = "/bin/test",
    process_cmd: str = "test",
    dst_ip: str = "127.0.0.1",
    dst_port: int = 80,
    summary: str = "Test event",
    metadata: dict = None,
) -> CanonicalEvent:
    now = datetime.now(timezone.utc)
    return CanonicalEvent(
        id=event_id,
        timestamp=now,
        ingested_at=now,
        host="test-host",
        source="auditd",
        event_type=event_type,
        severity=Severity.NOTICE,
        actor=Actor(username="root", uid=0),
        process=Process(name=process_name, executable=process_exe, command_line=process_cmd),
        network=Network(dst_ip=dst_ip, dst_port=dst_port),
        action="EXEC",
        outcome=outcome,
        summary=summary,
        raw_message=summary,
        parser="audit",
        metadata=metadata or {},
    )


def test_sec_memory_execution_rule(detection_engine):
    """Verify sec.memory_execution triggers on /dev/shm execution."""
    ev_hit = _make_event(
        event_id="ev-shm-hit",
        event_type=EventType.PROCESS_EXECUTION,
        process_exe="/dev/shm/.miner",
        process_cmd="/dev/shm/.miner --algo rx/0",
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.memory_execution" in rule_ids

    ev_miss = _make_event(
        event_id="ev-shm-miss",
        event_type=EventType.PROCESS_EXECUTION,
        process_exe="/usr/bin/htop",
        process_cmd="htop",
    )
    results_miss = detection_engine.evaluate_event(ev_miss)
    rule_ids_miss = {r.rule_id for r in results_miss}
    assert "sec.memory_execution" not in rule_ids_miss


def test_sec_reverse_shell_socket_rule(detection_engine):
    """Verify sec.reverse_shell_socket triggers when bash opens outbound socket."""
    ev_hit = _make_event(
        event_id="ev-rev-hit",
        event_type=EventType.NETWORK_SOCKET_CONNECTION,
        process_name="bash",
        dst_ip="198.51.100.25",
        dst_port=4444,
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.reverse_shell_socket" in rule_ids

    ev_miss = _make_event(
        event_id="ev-rev-miss",
        event_type=EventType.NETWORK_SOCKET_CONNECTION,
        process_name="curl",
        dst_ip="198.51.100.25",
        dst_port=80,
    )
    results_miss = detection_engine.evaluate_event(ev_miss)
    rule_ids_miss = {r.rule_id for r in results_miss}
    assert "sec.reverse_shell_socket" not in rule_ids_miss


def test_sec_cron_persistence_tamper_rule(detection_engine):
    """Verify sec.cron_persistence_tamper detects cron modifications."""
    ev_hit = _make_event(
        event_id="ev-cron-hit",
        event_type=EventType.FILE_PERSISTENCE_DROP,
        summary="Crontab schedule dropped in /etc/cron.d/backdoor",
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.cron_persistence_tamper" in rule_ids


def test_sec_systemd_persistence_drop_rule(detection_engine):
    """Verify sec.systemd_persistence_drop detects service file drops."""
    ev_hit = _make_event(
        event_id="ev-sysd-hit",
        event_type=EventType.FILE_PERSISTENCE_DROP,
        summary="Systemd persistence unit written: /etc/systemd/system/malware.service",
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.systemd_persistence_drop" in rule_ids


def test_sec_ssh_authorized_keys_tamper_rule(detection_engine):
    """Verify sec.ssh_authorized_keys_tamper detects authorized_keys modifications."""
    ev_hit = _make_event(
        event_id="ev-ssh-hit",
        event_type=EventType.FILE_PERSISTENCE_DROP,
        summary="Modified authorized_keys file for persistence",
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.ssh_authorized_keys_tamper" in rule_ids


def test_sec_container_escape_attempt_rule(detection_engine):
    """Verify sec.container_escape_attempt triggers on escape attempts."""
    ev_hit = _make_event(
        event_id="ev-esc-hit",
        event_type=EventType.CONTAINER_SECURITY_ESCAPE_ATTEMPT,
        summary="Process attempted to join host namespace via nsenter",
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.container_escape_attempt" in rule_ids


def test_sec_suspicious_listening_socket_rule(detection_engine):
    """Verify sec.suspicious_listening_socket triggers on adversary ports."""
    ev_hit = _make_event(
        event_id="ev-listen-hit",
        event_type=EventType.NETWORK_SOCKET_LISTEN,
        dst_port=4444,
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.suspicious_listening_socket" in rule_ids

    ev_miss = _make_event(
        event_id="ev-listen-miss",
        event_type=EventType.NETWORK_SOCKET_LISTEN,
        dst_port=443,
    )
    results_miss = detection_engine.evaluate_event(ev_miss)
    rule_ids_miss = {r.rule_id for r in results_miss}
    assert "sec.suspicious_listening_socket" not in rule_ids_miss


def test_sec_kernel_module_tampering_rule(detection_engine):
    """Verify sec.kernel_module_tampering detects module loading."""
    ev_hit = _make_event(
        event_id="ev-kmod-hit",
        event_type=EventType.KERNEL_MODULE_LOAD,
        summary="Kernel module loaded: rootkit.ko",
    )
    results = detection_engine.evaluate_event(ev_hit)
    rule_ids = {r.rule_id for r in results}
    assert "sec.kernel_module_tampering" in rule_ids
