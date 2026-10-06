"""Tests for Milestone M6.2: Linux Process & Execution Telemetry via auditd."""

from datetime import datetime, timezone
import pytest
from logintel.collectors.audit import AuditLogCollector
from logintel.correlation.ancestry import (
    ProcessAncestryResolver,
    ProcessNode,
    build_process_identity,
)
from logintel.models import CanonicalEvent, EventType, Outcome, RawRecord, Severity
from logintel.normalization.sanitizer import mask_credentials
from logintel.parsers.audit import AuditParser, decode_audit_hex
from logintel.parsers.registry import parser_registry


def test_decode_audit_hex_standard_and_hex():
    """Verify decode_audit_hex handles plain, quoted, and hex-encoded audit strings."""
    assert decode_audit_hex("python3") == "python3"
    assert decode_audit_hex('"script.py"') == "script.py"
    assert decode_audit_hex("'--verbose'") == "--verbose"

    # Hex for "/usr/sbin/CRON\x00-f\x00-P"
    hex_cron = "2F7573722F7362696E2F43524F4E002D66002D50"
    decoded = decode_audit_hex(hex_cron)
    assert decoded == "/usr/sbin/CRON -f -P"

    # Odd length or non-hex string should not crash
    assert decode_audit_hex("abc") == "abc"
    assert decode_audit_hex("ZZZZ") == "ZZZZ"


def test_audit_parser_single_syscall_proctitle():
    """Verify AuditParser normalizes combined SYSCALL and PROCTITLE records."""
    raw = (
        'type=SYSCALL msg=audit(1791255901.300:699): arch=c000003e syscall=1 success=yes exit=1 '
        'items=0 ppid=1572 pid=75899 auid=0 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 '
        'tty=(none) ses=12 comm="cron" exe="/usr/sbin/cron" subj=unconfined key=(null)\n'
        'type=PROCTITLE msg=audit(1791255901.300:699): proctitle=2F7573722F7362696E2F43524F4E002D66002D50'
    )
    rec = RawRecord(source="audit.log", raw_content=raw, host="testhost")
    parser = AuditParser()
    assert parser.can_parse(rec) is True

    event = parser.parse(rec)
    assert event is not None
    assert event.event_type == EventType.PROCESS_EXECUTION
    assert event.process.name == "cron"
    assert event.process.pid == 75899
    assert event.process.ppid == 1572
    assert event.process.executable == "/usr/sbin/cron"
    assert event.process.command_line == "/usr/sbin/CRON -f -P"
    assert event.actor.uid == 0
    assert event.actor.session_id == "12"
    assert event.metadata["auid"] == "0"
    assert event.metadata["audit_sequence"] == "699"
    assert event.outcome == Outcome.SUCCESS


def test_audit_parser_execve_argument_reconstruction():
    """Verify AuditParser reconstructs command lines from EXECVE argc and a0, a1, a2."""
    raw = (
        'type=SYSCALL msg=audit(1620000000.123:1001): arch=c000003e syscall=59 success=yes exit=0 '
        'ppid=1000 pid=2048 auid=1000 uid=1000 gid=1000 euid=1000 ses=5 comm="python3" '
        'exe="/usr/bin/python3.12" tty=pts1\n'
        'type=EXECVE msg=audit(1620000000.123:1001): argc=3 a0="python3" a1="backup.py" a2="--dry-run"'
    )
    rec = RawRecord(source="audit.log", raw_content=raw, host="testhost")
    parser = AuditParser()
    event = parser.parse(rec)

    assert event is not None
    assert event.event_type == EventType.PROCESS_EXECUTION
    assert event.process.pid == 2048
    assert event.process.ppid == 1000
    assert event.process.command_line == "python3 backup.py --dry-run"
    assert event.actor.session_id == "5"
    assert event.metadata["cmdline_source"] == "EXECVE"


def test_audit_parser_user_start_end_pam_sessions():
    """Verify AuditParser normalizes USER_START and USER_END PAM session records."""
    raw_start = (
        'type=USER_START msg=audit(1791255901.302:700): pid=75899 uid=0 auid=0 ses=12 '
        'subj=unconfined msg=\'op=PAM:session_open grantors=pam_loginuid acct="root" '
        'exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success\' UID="root" AUID="root"'
    )
    rec_start = RawRecord(source="audit.log", raw_content=raw_start, host="testhost")
    parser = AuditParser()
    event_start = parser.parse(rec_start)

    assert event_start is not None
    assert event_start.event_type == EventType.AUDIT_SESSION_START
    assert event_start.actor.username == "root"
    assert event_start.actor.session_id == "12"
    assert event_start.outcome == Outcome.SUCCESS

    raw_end = (
        'type=USER_END msg=audit(1791255901.311:703): pid=75899 uid=0 auid=0 ses=12 '
        'subj=unconfined msg=\'op=PAM:session_close acct="root" exe="/usr/sbin/cron" '
        'terminal=cron res=success\' UID="root" AUID="root"'
    )
    rec_end = RawRecord(source="audit.log", raw_content=raw_end, host="testhost")
    event_end = parser.parse(rec_end)

    assert event_end is not None
    assert event_end.event_type == EventType.AUDIT_SESSION_END
    assert event_end.actor.username == "root"
    assert event_end.outcome == Outcome.SUCCESS


def test_credential_masking_in_audit_commands():
    """Verify mask_credentials masks secrets while keeping command structure intact."""
    raw = (
        'type=SYSCALL msg=audit(1620000000.456:1002): arch=c000003e syscall=59 success=yes exit=0 '
        'ppid=500 pid=3000 auid=1000 uid=1000 ses=2 comm="curl" exe="/usr/bin/curl"\n'
        'type=EXECVE msg=audit(1620000000.456:1002): argc=4 a0="curl" a1="-H" '
        'a2="Authorization: Bearer secret_token_xyz" a3="--password=mysecretpassword"'
    )
    rec = RawRecord(source="audit.log", raw_content=raw, host="testhost")
    parser = AuditParser()
    event = parser.parse(rec)

    assert event is not None
    # Canonical command line must be masked
    assert "secret_token_xyz" not in event.process.command_line
    assert "[MASKED]" in event.process.command_line
    assert "mysecretpassword" not in event.process.command_line
    assert "--password=[MASKED]" in event.process.command_line
    # Summary must also be masked
    assert "secret_token_xyz" not in event.summary
    assert "mysecretpassword" not in event.summary
    # Raw message MUST retain original evidence intact
    assert "Authorization: Bearer secret_token_xyz" in event.raw_message
    assert "--password=mysecretpassword" in event.raw_message


def test_process_ancestry_resolver_in_memory():
    """Verify ProcessAncestryResolver reconstructs multi-generation process tree."""
    t0 = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 6, 8, 0, 1, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 6, 8, 0, 2, tzinfo=timezone.utc)

    e_sshd = CanonicalEvent(
        timestamp=t0,
        host="host1",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        process={"name": "sshd", "pid": 100, "ppid": 1, "executable": "/usr/sbin/sshd"},
        actor={"username": "root"},
        summary="sshd",
        raw_message="sshd",
    )
    e_bash = CanonicalEvent(
        timestamp=t1,
        host="host1",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        process={"name": "bash", "pid": 200, "ppid": 100, "executable": "/bin/bash"},
        actor={"username": "user1"},
        summary="bash",
        raw_message="bash",
    )
    e_curl = CanonicalEvent(
        timestamp=t2,
        host="host1",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        process={"name": "curl", "pid": 300, "ppid": 200, "executable": "/usr/bin/curl", "command_line": "curl http://test"},
        actor={"username": "user1"},
        summary="curl",
        raw_message="curl",
    )

    all_events = [e_sshd, e_bash, e_curl]
    chain = ProcessAncestryResolver.resolve_ancestry_from_events(e_curl, all_events)

    assert chain.target_pid == 300
    assert len(chain.chain) == 3
    # Chain: leaf (curl) -> parent (bash) -> root (sshd)
    assert chain.chain[0].pid == 300
    assert chain.chain[0].name == "curl"
    assert chain.chain[1].pid == 200
    assert chain.chain[1].name == "bash"
    assert chain.chain[1].relationship_to_child == "SPAWNED"
    assert chain.chain[2].pid == 100
    assert chain.chain[2].name == "sshd"
    assert chain.chain[2].relationship_to_child == "SPAWNED"


def test_process_identity_prevents_pid_reuse_collision():
    """Verify build_process_identity differentiates identical PIDs across timestamps."""
    t1 = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 6, 9, 0, 0, tzinfo=timezone.utc)

    id1 = build_process_identity("host1", 1234, t1, exe="/bin/ls", audit_seq="100")
    id2 = build_process_identity("host1", 1234, t2, exe="/usr/bin/python", audit_seq="500")

    assert id1 != id2
    assert "1234" in id1 and "1234" in id2
    assert "ls" in id1
    assert "python" in id2


def test_parser_registry_integration():
    """Verify AuditParser is registered in parser_registry and executes automatically."""
    raw = 'type=PROCTITLE msg=audit(1791255901.300:700): proctitle=2F62696E2F74727565'
    rec = RawRecord(source="audit.log", raw_content=raw, host="testhost")

    event, is_specialized = parser_registry.parse_record(rec)
    assert is_specialized is True
    assert event.parser == "linux_audit"
    assert event.process.command_line == "/bin/true"


def test_detection_engine_process_execution_rule():
    """Verify detection engine matches atomic rule conditions on PROCESS_EXECUTION events."""
    from logintel.detection.models import DetectionRule, RuleCategory, RuleType, ConditionsBlock, Condition, Operator
    from logintel.detection.engine import DetectionEngine
    from logintel.detection.registry import RuleRegistry

    rule = DetectionRule(
        id="proc.test_unprivileged_recon",
        name="Test Unprivileged Reconnaissance",
        description="Detects execution of nmap via audit telemetry.",
        severity=Severity.WARNING,
        category=RuleCategory.PROCESS,
        rule_type=RuleType.ATOMIC,
        enabled=True,
        conditions=ConditionsBlock(
            all=[
                Condition(field="event_type", operator=Operator.EQUALS, value="PROCESS_EXECUTION"),
                Condition(field="outcome", operator=Operator.EQUALS, value="SUCCESS"),
                Condition(field="process_command_line", operator=Operator.REGEX, value=r"^(\S*/)?nmap(\s.*)?$"),
            ]
        ),
    )
    registry = RuleRegistry()
    registry.register(rule)
    engine = DetectionEngine(registry=registry)

    # Matching event
    event = CanonicalEvent(
        timestamp=datetime.now(timezone.utc),
        host="host1",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        outcome=Outcome.SUCCESS,
        process={"name": "nmap", "pid": 1234, "command_line": "nmap -sV 10.0.0.1"},
        summary="nmap scan",
        raw_message="nmap scan",
    )
    matches = engine.evaluate_event(event)
    assert len(matches) == 1
    assert matches[0].rule_id == "proc.test_unprivileged_recon"

