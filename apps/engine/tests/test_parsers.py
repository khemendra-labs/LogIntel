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
