"""Unit tests for M6.3 identity, session models, and SessionContinuityResolver."""

from datetime import datetime, timezone
import pytest
from logintel.identity import (
    AuditIdentity,
    IdentityContinuityChain,
    PrivilegeTransition,
    PrivilegeTransitionType,
    SessionContinuityResolver,
    SessionRecord,
    SessionState,
    UNSET_AUID_VALUES,
)
from logintel.models import CanonicalEvent, EventType, Outcome


def test_audit_identity_parsing_and_unset_auid():
    """Verify AuditIdentity correctly identifies unset AUIDs (system/daemon)."""
    # 1. Unset AUID (4294967295)
    kvs_daemon = {"auid": "4294967295", "uid": "0", "euid": "0"}
    id_daemon = AuditIdentity.from_audit_kvs(kvs_daemon, username="root")
    assert id_daemon.is_unset_auid is True
    assert id_daemon.auid is None
    assert id_daemon.uid == 0
    assert id_daemon.euid == 0
    assert id_daemon.is_elevated is False  # Already root uid, not an elevation

    # 2. Interactive user with sudo elevation
    kvs_elevated = {"auid": "1000", "uid": "1000", "euid": "0"}
    id_elevated = AuditIdentity.from_audit_kvs(kvs_elevated, username="user1")
    assert id_elevated.is_unset_auid is False
    assert id_elevated.auid == "1000"
    assert id_elevated.uid == 1000
    assert id_elevated.euid == 0
    assert id_elevated.is_elevated is True  # Effective UID 0 while real UID 1000


def test_session_continuity_registration_and_correlation():
    """Verify SessionContinuityResolver tracks session lifecycle and links process events."""
    resolver = SessionContinuityResolver()
    t0 = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 6, 10, 5, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 6, 10, 30, 0, tzinfo=timezone.utc)

    # 1. Session start event (login by alice)
    start_event = CanonicalEvent(
        timestamp=t0,
        host="srv01",
        source="audit.log",
        event_type=EventType.AUDIT_SESSION_START,
        actor={"username": "alice", "session_id": "42", "terminal": "pts/0"},
        network={"src_ip": "192.168.1.100"},
        metadata={"auid": "1001", "ses": "42", "service": "sshd"},
        summary="Session open for alice",
        raw_message="type=USER_START msg=audit(1700000000.0:1): pid=1000 uid=0 auid=1001 ses=42",
    )
    sess = resolver.register_session_start(start_event)
    assert sess is not None
    assert sess.session_id == "42"
    assert sess.login_user == "alice"
    assert sess.auid == "1001"
    assert sess.is_active is True

    # 2. Correlate process execution in session 42
    proc_event = CanonicalEvent(
        timestamp=t1,
        host="srv01",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        actor={"username": "alice", "session_id": "42"},
        process={"name": "ls", "pid": 5001, "command_line": "ls -la"},
        metadata={"auid": "1001", "ses": "42"},
        summary="ls execution",
        raw_message="type=SYSCALL pid=5001 ses=42 auid=1001",
    )
    matched_sess, epistemic = resolver.correlate_event_to_session(proc_event)
    assert matched_sess is not None
    assert matched_sess.session_id == "42"
    assert epistemic == "OBSERVED"
    assert 5001 in matched_sess.process_pids

    # 3. Session close event
    end_event = CanonicalEvent(
        timestamp=t2,
        host="srv01",
        source="audit.log",
        event_type=EventType.AUDIT_SESSION_END,
        actor={"username": "alice", "session_id": "42"},
        metadata={"ses": "42"},
        summary="Session close for alice",
        raw_message="type=USER_END msg=audit(1700001800.0:2): ses=42",
    )
    closed_sess = resolver.register_session_end(end_event)
    assert closed_sess is not None
    assert closed_sess.state == SessionState.CLOSED
    assert closed_sess.end_time == t2


def test_identity_continuity_chain_provenance():
    """Verify IdentityContinuityChain correctly attributes root command to original login user."""
    resolver = SessionContinuityResolver()
    t0 = datetime(2026, 10, 6, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 6, 10, 2, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 6, 10, 5, 0, tzinfo=timezone.utc)

    # Login by bob
    start_event = CanonicalEvent(
        timestamp=t0,
        host="srv01",
        source="audit.log",
        event_type=EventType.AUDIT_SESSION_START,
        actor={"username": "bob", "session_id": "105", "terminal": "pts/1"},
        network={"src_ip": "10.0.0.50"},
        metadata={"auid": "1002", "ses": "105"},
        summary="Session open for bob",
        raw_message="type=USER_START ses=105 auid=1002",
    )
    resolver.register_session_start(start_event)

    # Sudo transition event
    sudo_event = CanonicalEvent(
        timestamp=t1,
        host="srv01",
        source="auth.log",
        event_type=EventType.SUDO_COMMAND,
        actor={"username": "bob", "uid": 1002, "session_id": "105", "terminal": "pts/1"},
        process={"command_line": "sudo su -"},
        metadata={"target_user": "root", "ses": "105"},
        summary="bob executed sudo su -",
        raw_message="sudo: bob : TTY=pts/1 ; USER=root ; COMMAND=/bin/su -",
    )

    # Root command executed under sudo shell
    root_event = CanonicalEvent(
        timestamp=t2,
        host="srv01",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        actor={"username": "root", "uid": 0, "session_id": "105"},
        process={"name": "useradd", "pid": 9999, "command_line": "useradd attacker"},
        metadata={"auid": "1002", "ses": "105"},  # AUID preserves origin!
        summary="useradd execution",
        raw_message="type=SYSCALL pid=9999 uid=0 auid=1002 ses=105",
    )

    chain = resolver.resolve_identity_continuity(root_event, all_events=[sudo_event])
    assert chain.effective_user == "root"
    assert chain.effective_uid == 0
    assert chain.login_user == "bob"
    assert chain.login_auid == "1002"
    assert chain.session_id == "105"
    assert chain.epistemic_status == "OBSERVED"
    assert len(chain.privilege_transitions) == 1
    assert chain.privilege_transitions[0].transition_type == PrivilegeTransitionType.SUDO
    assert "bob" in chain.narrative
    assert "root" in chain.narrative
    assert "useradd" in chain.narrative


def test_daemon_execution_unset_auid_narrative():
    """Verify daemon execution with unset AUID is explicitly identified without false login attribution."""
    resolver = SessionContinuityResolver()
    t0 = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)

    daemon_event = CanonicalEvent(
        timestamp=t0,
        host="srv01",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        actor={"username": "root", "uid": 0},
        process={"name": "cron", "pid": 1200, "command_line": "/usr/sbin/cron -f"},
        metadata={"auid": "4294967295", "ses": "unset"},
        summary="cron execution",
        raw_message="type=SYSCALL pid=1200 uid=0 auid=4294967295 ses=unset",
    )

    chain = resolver.resolve_identity_continuity(daemon_event)
    assert chain.login_user is None
    assert chain.login_auid is None
    assert chain.epistemic_status == "UNKNOWN"
    assert "unauthenticated context" in chain.narrative
    assert "AUID UNSET" in chain.narrative
