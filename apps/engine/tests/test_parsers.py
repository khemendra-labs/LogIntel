"""Deterministic unit tests for telemetry parsers and sanitization."""

from datetime import datetime
from logintel.models import EventType, Outcome, RawRecord, Severity
from logintel.normalization.sanitizer import extract_iocs, sanitize_message
from logintel.parsers.registry import parser_registry
from tests.fixtures.sample_logs import (
    FIXTURE_GENERIC_SYSLOG,
    FIXTURE_KERNEL_BOOT,
    FIXTURE_KERNEL_SEGFAULT,
    FIXTURE_KERNEL_UFW,
    FIXTURE_MALFORMED,
    FIXTURE_PAM_SESSION_CLOSE,
    FIXTURE_PAM_SESSION_OPEN,
    FIXTURE_SSH_FAILURE,
    FIXTURE_SSH_SUCCESS,
    FIXTURE_SUDO_COMMAND,
    FIXTURE_SUDO_FAILURE,
    FIXTURE_USERADD,
)


def test_ssh_failure_parser():
    record = RawRecord(source="auth.log", raw_content=FIXTURE_SSH_FAILURE)
    event, success = parser_registry.parse_record(record)
    assert success is True
    assert event.event_type == EventType.AUTH_LOGIN_FAILURE
    assert event.severity == Severity.ALERT
    assert event.actor.username == "admin"
    assert event.network.src_ip == "198.51.100.42"
    assert event.network.dst_port == 22
    assert event.outcome == Outcome.FAILURE
    assert "198.51.100.42" in event.iocs


def test_ssh_success_parser():
    record = RawRecord(source="auth.log", raw_content=FIXTURE_SSH_SUCCESS)
    event, success = parser_registry.parse_record(record)
    assert success is True
    assert event.event_type == EventType.AUTH_LOGIN_SUCCESS
    assert event.severity == Severity.NOTICE
    assert event.actor.username == "secops"
    assert event.network.src_ip == "203.0.113.15"
    assert event.outcome == Outcome.SUCCESS


def test_sudo_command_parser():
    record = RawRecord(source="auth.log", raw_content=FIXTURE_SUDO_COMMAND)
    event, success = parser_registry.parse_record(record)
    assert success is True
    assert event.event_type == EventType.SUDO_COMMAND
    assert event.actor.username == "analyst"
    assert event.process.command_line == "/usr/bin/cat /etc/shadow"
    assert event.outcome == Outcome.SUCCESS


def test_sudo_failure_parser():
    record = RawRecord(source="auth.log", raw_content=FIXTURE_SUDO_FAILURE)
    event, success = parser_registry.parse_record(record)
    assert success is True
    assert event.event_type == EventType.PRIVILEGE_ELEVATION_FAILURE
    assert event.severity == Severity.ALERT
    assert event.actor.username == "untrusted_user"
    assert event.outcome == Outcome.FAILURE


def test_pam_session_parser():
    open_rec = RawRecord(source="auth.log", raw_content=FIXTURE_PAM_SESSION_OPEN)
    open_evt, success = parser_registry.parse_record(open_rec)
    assert success is True
    assert open_evt.event_type == EventType.SESSION_OPEN
    assert open_evt.actor.username == "root"

    close_rec = RawRecord(source="auth.log", raw_content=FIXTURE_PAM_SESSION_CLOSE)
    close_evt, success = parser_registry.parse_record(close_rec)
    assert success is True
    assert close_evt.event_type == EventType.SESSION_CLOSE
    assert close_evt.actor.username == "root"


def test_useradd_parser():
    record = RawRecord(source="auth.log", raw_content=FIXTURE_USERADD)
    event, success = parser_registry.parse_record(record)
    assert success is True
    assert event.event_type == EventType.USER_CREATE
    assert event.actor.username == "backdoor"
    assert event.actor.uid == 1050


def test_kernel_parsers():
    boot_rec = RawRecord(source="kern.log", raw_content=FIXTURE_KERNEL_BOOT)
    boot_evt, success = parser_registry.parse_record(boot_rec)
    assert success is True
    assert boot_evt.event_type == EventType.SYSTEM_BOOT

    ufw_rec = RawRecord(source="kern.log", raw_content=FIXTURE_KERNEL_UFW)
    ufw_evt, success = parser_registry.parse_record(ufw_rec)
    assert success is True
    assert ufw_evt.network.src_ip == "198.51.100.99"
    assert ufw_evt.outcome == Outcome.FAILURE

    seg_rec = RawRecord(source="kern.log", raw_content=FIXTURE_KERNEL_SEGFAULT)
    seg_evt, success = parser_registry.parse_record(seg_rec)
    assert success is True
    assert seg_evt.severity == Severity.ALERT


def test_generic_fallback_parser():
    record = RawRecord(source="syslog", raw_content=FIXTURE_GENERIC_SYSLOG)
    event, success = parser_registry.parse_record(record)
    assert event.process.name == "systemd"
    assert event.event_type == EventType.SYSTEM_GENERIC


def test_malformed_event_resilience():
    # Ensure ANSI codes, null bytes are cleaned and parser does not crash
    record = RawRecord(source="syslog", raw_content=FIXTURE_MALFORMED)
    event, success = parser_registry.parse_record(record)
    assert "\x1b" not in event.raw_message
    assert "\x00" not in event.raw_message
    assert "CRITICAL" in event.raw_message


def test_sudo_with_spaces_in_pwd():
    """Verify that sudo parser handles directory paths containing spaces."""
    line = "Sep 29 10:15:00 sec-node sudo: analyst : TTY=pts/1 ; PWD=/home/analyst/my special projects/conf ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    record = RawRecord(source="auth.log", raw_content=line)
    event, success = parser_registry.parse_record(record)
    assert success is True
    assert event.event_type == EventType.SUDO_COMMAND
    assert event.actor.username == "analyst"
    assert event.process.command_line == "/usr/bin/cat /etc/shadow"
    assert event.outcome == Outcome.SUCCESS


def test_apparmor_denial_security_event():
    """Verify that apparmor='DENIED' events are explicitly mapped to SECURITY_ACCESS_DENIED with ALERT and FAILURE."""
    line = 'Sep 29 10:15:00 sec-node kernel: audit: type=1400 audit(1727600000.123:456): apparmor="DENIED" operation="open" class="file" profile="/usr/bin/evince" name="/etc/shadow" pid=12345 comm="evince" requested_mask="r" denied_mask="r"'
    record = RawRecord(source="kern.log", raw_content=line)
    event, success = parser_registry.parse_record(record)
    assert success is True
    assert event.event_type == EventType.SECURITY_ACCESS_DENIED
    assert event.severity == Severity.ALERT
    assert event.outcome == Outcome.FAILURE
    assert event.process.name == "evince"
    assert "AppArmor security policy DENIED" in event.summary
    assert "/etc/shadow" in event.summary


def test_ipv6_ioc_extraction():
    """Verify that both IPv4 and IPv6 indicators are correctly extracted."""
    line = "Sep 29 10:15:00 sec-node sshd[123]: Inbound scan from 127.0.0.1 and 192.168.1.20 and ::1 and fe80::1 and 2001:db8::10"
    record = RawRecord(source="auth.log", raw_content=line)
    event, success = parser_registry.parse_record(record)
    assert success is True
    for expected_ip in ["127.0.0.1", "192.168.1.20", "::1", "fe80::1", "2001:db8::10"]:
        assert expected_ip in event.iocs


def test_historical_timestamp_provenance():
    """Verify that historical syslog records preserve actual log event time rather than ingestion time."""
    line = "Sep 01 14:20:10 sec-node sshd[4321]: Accepted publickey for secops from 203.0.113.15 port 4222 ssh2"
    record = RawRecord(source="auth.log", raw_content=line, timestamp=None)
    event, success = parser_registry.parse_record(record)
    assert success is True
    # Event timestamp recovered from log header
    assert event.timestamp.month == 9
    assert event.timestamp.day == 1
    assert event.timestamp.hour == 14
    assert event.timestamp.minute == 20
    assert event.timestamp.second == 10
    # Ingested_at should be recent (now)
    assert event.timestamp != event.ingested_at
