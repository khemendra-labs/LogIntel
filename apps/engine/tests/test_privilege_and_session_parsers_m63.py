"""Tests for M6.3 privilege transition and session continuity parsers."""

from datetime import datetime, timezone
import pytest
from logintel.models import EventType, Outcome, RawRecord, Severity
from logintel.parsers.audit import AuditParser
from logintel.parsers.pam import PAMSessionParser
from logintel.parsers.ssh import SSHAuthParser
from logintel.parsers.sudo import SudoParser


def test_audit_parser_elevated_session_detection():
    """Verify AuditParser identifies elevated PAM sessions (e.g. root session with human AUID)."""
    parser = AuditParser()
    raw = (
        "type=USER_START msg=audit(1700000000.123:45): pid=5120 uid=0 auid=1000 ses=12 "
        "msg='op=PAM:session_open grantors=pam_limits,pam_unix acct=\"root\" exe=\"/usr/bin/sudo\" "
        "hostname=? addr=? terminal=/dev/pts/0 res=success'"
    )
    record = RawRecord(
        source="audit.log",
        host="ubuntuhost",
        raw_content=raw,
        timestamp=datetime.now(timezone.utc),
    )
    event = parser.parse(record)
    assert event is not None
    assert event.event_type == EventType.AUDIT_SESSION_START
    assert event.actor.username == "root"
    assert event.actor.session_id == "12"
    assert event.metadata["auid"] == "1000"
    assert event.metadata["ses"] == "12"
    assert event.metadata["is_elevated_session"] is True
    assert event.metadata["transition_type"] == "PAM_ELEVATION"
    assert event.metadata["target_user"] == "root"


def test_audit_parser_elevated_execution_classification():
    """Verify AuditParser detects euid != uid and categorizes transition type."""
    parser = AuditParser()
    raw = (
        "type=SYSCALL msg=audit(1700000001.000:46): arch=c000003e syscall=59 success=yes exit=0 "
        "a0=7ffd123 a1=7ffd456 a2=7ffd789 a3=0 items=2 ppid=5000 pid=5121 auid=1000 uid=1000 "
        "gid=1000 euid=0 suid=0 fsuid=0 tty=pts0 ses=12 comm=\"sudo\" exe=\"/usr/bin/sudo\"\n"
        "type=EXECVE msg=audit(1700000001.000:46): argc=2 a0=\"sudo\" a1=\"su\""
    )
    record = RawRecord(
        source="audit.log",
        host="ubuntuhost",
        raw_content=raw,
        timestamp=datetime.now(timezone.utc),
    )
    event = parser.parse(record)
    assert event is not None
    assert event.event_type == EventType.PROCESS_EXECUTION
    assert event.metadata["is_elevated"] is True
    assert event.metadata["transition_type"] == "SUDO"
    assert event.metadata["target_user"] == "root"
    assert event.metadata["auid"] == "1000"
    assert event.metadata["euid"] == 0
    assert event.metadata["uid"] == 1000


def test_sudo_parser_credential_masking_and_transition_attributes():
    """Verify SudoParser masks passwords in command line and flags privilege transitions."""
    parser = SudoParser()
    raw = "Oct 06 10:15:00 srv sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/mysql -u root -p SecretPass123"
    record = RawRecord(
        source="auth.log",
        host="srv",
        raw_content=raw,
        timestamp=datetime.now(timezone.utc),
    )
    event = parser.parse(record)
    assert event is not None
    assert event.event_type == EventType.SUDO_COMMAND
    assert event.actor.username == "alice"
    assert event.actor.terminal == "pts/0"
    assert event.metadata["target_user"] == "root"
    assert event.metadata["source_user"] == "alice"
    assert event.metadata["transition_type"] == "SUDO"
    assert event.metadata["is_privilege_transition"] is True
    # Credentials must be masked in command_line and summary
    assert "SecretPass123" not in event.process.command_line
    assert "[MASKED]" in event.process.command_line
    assert "SecretPass123" not in event.summary
    assert "[MASKED]" in event.summary
    # But unaltered raw message must preserve raw evidence
    assert "SecretPass123" in event.raw_message


def test_pam_parser_switch_user_elevation():
    """Verify PAMSessionParser detects session open by different user (e.g. su to root)."""
    parser = PAMSessionParser()
    raw = "Oct 06 10:20:00 srv su: pam_unix(su:session): session opened for user root(uid=0) by bob(uid=1002)"
    record = RawRecord(
        source="auth.log",
        host="srv",
        raw_content=raw,
        timestamp=datetime.now(timezone.utc),
    )
    event = parser.parse(record)
    assert event is not None
    assert event.event_type == EventType.SESSION_OPEN
    assert event.actor.username == "root"
    assert event.actor.uid == 0
    assert event.metadata["by_user"] == "bob"
    assert event.metadata["by_uid"] == 1002
    assert event.metadata["is_privilege_transition"] is True
    assert event.metadata["transition_type"] == "SU"
    assert event.metadata["source_user"] == "bob"
    assert event.metadata["target_user"] == "root"


def test_ssh_parser_session_enrichment():
    """Verify SSHAuthParser enriches metadata with session continuity attributes."""
    parser = SSHAuthParser()
    raw = "Oct 06 10:22:00 srv sshd[12345]: Accepted publickey for alice from 192.168.1.50 port 54321 ssh2: RSA SHA256:abc..."
    record = RawRecord(
        source="auth.log",
        host="srv",
        raw_content=raw,
        timestamp=datetime.now(timezone.utc),
    )
    event = parser.parse(record)
    assert event is not None
    assert event.event_type == EventType.AUTH_LOGIN_SUCCESS
    assert event.actor.username == "alice"
    assert event.network.src_ip == "192.168.1.50"
    assert event.network.src_port == 54321
    assert event.metadata["service"] == "ssh"
    assert event.metadata["auth_method"] == "publickey"
    assert event.metadata["remote_ip"] == "192.168.1.50"
