"""Determinism certification test suite for Milestone M6.3: Advanced Identity & Session Continuity."""

from datetime import datetime, timezone
import hashlib
import json
import pytest

from logintel.identity.models import IdentityContinuityChain
from logintel.identity.resolver import SessionContinuityResolver
from logintel.models import CanonicalEvent, EventType, Severity


def test_identity_chain_determinism_10_runs():
    """Verify 10 repeated evaluations of multi-hop identity provenance yield identical SHA-256 hashes."""
    t0 = datetime(2026, 10, 6, 8, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 10, 6, 8, 5, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 6, 8, 10, 0, tzinfo=timezone.utc)

    # Inception SSH
    ev_ssh = CanonicalEvent(
        id="det-ssh-01",
        timestamp=t0,
        host="srv-determ",
        source="auth.log",
        event_type=EventType.AUTH_LOGIN_SUCCESS,
        actor={"username": "alice", "session_id": "42", "terminal": "pts/1"},
        network={"src_ip": "192.168.1.100", "src_port": 50123},
        metadata={"auid": "1001", "ses": "42", "service": "ssh"},
        summary="login",
        raw_message="Accepted publickey for alice",
    )

    # Elevation sudo
    ev_sudo = CanonicalEvent(
        id="det-sudo-02",
        timestamp=t1,
        host="srv-determ",
        source="auth.log",
        event_type=EventType.SUDO_COMMAND,
        actor={"username": "alice", "session_id": "42", "terminal": "pts/1"},
        process={"name": "sudo", "command_line": "sudo su -"},
        metadata={
            "source_user": "alice",
            "target_user": "root",
            "transition_type": "SUDO",
            "is_privilege_transition": True,
            "ses": "42",
            "auid": "1001",
        },
        summary="sudo su -",
        raw_message="sudo su -",
    )

    # Root execution
    ev_exec = CanonicalEvent(
        id="det-exec-03",
        timestamp=t2,
        host="srv-determ",
        source="audit.log",
        event_type=EventType.PROCESS_EXECUTION,
        actor={"username": "root", "uid": 0, "session_id": "42", "terminal": "pts/1"},
        process={"name": "tcpdump", "pid": 9999, "command_line": "tcpdump -i eth0"},
        metadata={"auid": "1001", "ses": "42", "uid": 0, "euid": 0, "is_elevated": True},
        summary="tcpdump",
        raw_message="SYSCALL tcpdump",
    )

    semantic_hashes = set()

    for _ in range(10):
        resolver = SessionContinuityResolver()
        resolver.register_session_start(ev_ssh)
        chain = resolver.resolve_identity_continuity(ev_exec, all_events=[ev_ssh, ev_sudo, ev_exec])

        payload = json.dumps(
            {
                "target_process_name": chain.target_process_name,
                "target_pid": chain.target_pid,
                "effective_user": chain.effective_user,
                "effective_uid": chain.effective_uid,
                "login_user": chain.login_user,
                "login_auid": chain.login_auid,
                "session_id": chain.session_id,
                "terminal": chain.terminal,
                "remote_ip": chain.remote_ip,
                "epistemic_status": chain.epistemic_status,
                "transitions_count": len(chain.privilege_transitions),
                "narrative": chain.narrative,
            },
            sort_keys=True,
        )
        h = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        semantic_hashes.add(h)

    assert len(semantic_hashes) == 1, "Identity continuity chain must be 100% bit-for-bit deterministic across 10 runs"
