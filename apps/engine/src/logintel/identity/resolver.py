"""Session continuity resolver and identity provenance engine for LogIntel (M6.3).

Correlates process executions and privilege transitions to interactive or service
sessions, preserving login accountability (AUID) across privilege elevations.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set, Tuple

from logintel.identity.models import (
    AuditIdentity,
    IdentityContinuityChain,
    PrivilegeTransition,
    PrivilegeTransitionType,
    SessionRecord,
    SessionState,
    UNSET_AUID_VALUES,
)
from logintel.logging import get_logger
from logintel.models import CanonicalEvent, EventType, Outcome

logger = get_logger("identity.resolver")

MAX_SESSIONS_PER_HOST = 5000
SESSION_EXPIRATION_HOURS = 48


class SessionContinuityResolver:
    """Manages session states and resolves identity continuity across privilege boundaries."""

    def __init__(self):
        # host -> session_id -> SessionRecord
        self._sessions_by_id: Dict[str, Dict[str, SessionRecord]] = {}
        # host -> auid -> List[SessionRecord] (sorted by start_time)
        self._sessions_by_auid: Dict[str, Dict[str, List[SessionRecord]]] = {}
        # host -> username -> List[SessionRecord]
        self._sessions_by_user: Dict[str, Dict[str, List[SessionRecord]]] = {}

    def register_session_start(self, event: CanonicalEvent) -> Optional[SessionRecord]:
        """Record inception of a new session from auditd, PAM, or SSH telemetry."""
        host = event.host
        session_id = event.actor.session_id or event.metadata.get("ses")
        if not session_id or session_id in UNSET_AUID_VALUES:
            return None

        # Clean session id string
        session_id = str(session_id)
        auid = event.metadata.get("auid")
        if auid and str(auid).lower() in UNSET_AUID_VALUES:
            auid = None

        login_user = event.actor.username or event.metadata.get("acct") or event.metadata.get("user")
        terminal = event.actor.terminal or event.metadata.get("terminal") or event.metadata.get("tty")
        remote_ip = event.network.src_ip or event.metadata.get("addr") or event.metadata.get("hostname")
        service = event.metadata.get("service") or event.metadata.get("grantors") or event.source

        session = SessionRecord(
            session_id=session_id,
            host=host,
            auid=str(auid) if auid else None,
            login_user=login_user,
            terminal=terminal,
            remote_ip=remote_ip,
            service=service,
            start_time=event.timestamp,
            state=SessionState.ACTIVE,
            start_event_id=event.id,
        )

        host_sessions = self._sessions_by_id.setdefault(host, {})
        # Resource clamping
        if len(host_sessions) >= MAX_SESSIONS_PER_HOST:
            self._prune_expired_sessions(host)

        host_sessions[session_id] = session

        if session.auid:
            self._sessions_by_auid.setdefault(host, {}).setdefault(session.auid, []).append(session)
        if session.login_user:
            self._sessions_by_user.setdefault(host, {}).setdefault(session.login_user, []).append(session)

        return session

    def register_session_end(self, event: CanonicalEvent) -> Optional[SessionRecord]:
        """Record termination of a session from auditd, PAM, or SSH telemetry."""
        host = event.host
        session_id = event.actor.session_id or event.metadata.get("ses")
        if not session_id:
            return None

        session_id = str(session_id)
        host_sessions = self._sessions_by_id.get(host, {})
        session = host_sessions.get(session_id)
        if session:
            session.end_time = event.timestamp
            session.state = SessionState.CLOSED
            session.end_event_id = event.id
            return session
        return None

    def get_session(self, host: str, session_id: str) -> Optional[SessionRecord]:
        """Retrieve tracked session by host and session ID."""
        return self._sessions_by_id.get(host, {}).get(session_id)

    def correlate_event_to_session(
        self, event: CanonicalEvent
    ) -> Tuple[Optional[SessionRecord], str]:
        """Associate an event with an active or historical session.

        Returns:
            (SessionRecord, epistemic_status) where epistemic_status is:
            - 'OBSERVED': Direct matching session_id or explicit auid linkage.
            - 'INFERRED': Matched via terminal/user temporal heuristic.
            - 'UNKNOWN': No corroborating session evidence found.
        """
        host = event.host
        host_sessions = self._sessions_by_id.get(host, {})

        # Strategy 1: Direct session_id match (OBSERVED)
        session_id = event.actor.session_id or event.metadata.get("ses")
        if session_id and str(session_id) not in UNSET_AUID_VALUES:
            sess = host_sessions.get(str(session_id))
            if sess:
                if event.process.pid:
                    sess.process_pids.add(event.process.pid)
                return sess, "OBSERVED"

        # Strategy 2: Direct auid match on same host (OBSERVED)
        auid = event.metadata.get("auid")
        if auid and str(auid).lower() not in UNSET_AUID_VALUES:
            auid_str = str(auid)
            candidates = self._sessions_by_auid.get(host, {}).get(auid_str, [])
            for sess in reversed(candidates):
                # Check if event timestamp falls within session lifetime (or active)
                if sess.start_time <= event.timestamp:
                    if sess.end_time is None or event.timestamp <= (sess.end_time + timedelta(seconds=5)):
                        if event.process.pid:
                            sess.process_pids.add(event.process.pid)
                        return sess, "OBSERVED"

        # Strategy 3: Terminal + User match (INFERRED)
        terminal = event.actor.terminal or event.metadata.get("tty")
        username = event.actor.username
        if terminal and username and terminal not in ("?", "(none)", "none"):
            user_candidates = self._sessions_by_user.get(host, {}).get(username, [])
            for sess in reversed(user_candidates):
                if sess.terminal == terminal and sess.start_time <= event.timestamp:
                    if sess.end_time is None or event.timestamp <= (sess.end_time + timedelta(minutes=5)):
                        if event.process.pid:
                            sess.process_pids.add(event.process.pid)
                        return sess, "INFERRED"

        return None, "UNKNOWN"

    def resolve_identity_continuity(
        self,
        target_event: CanonicalEvent,
        all_events: Optional[List[CanonicalEvent]] = None,
    ) -> IdentityContinuityChain:
        """Resolve full identity provenance for an execution or privilege event."""
        session, epistemic = self.correlate_event_to_session(target_event)

        auid_val = target_event.metadata.get("auid")
        is_unset_auid = (
            auid_val is None
            or str(auid_val).lower() in UNSET_AUID_VALUES
            or str(auid_val) == "4294967295"
        )

        effective_user = target_event.actor.username or "unknown"
        effective_uid = target_event.actor.uid if target_event.actor.uid is not None else 0

        chain = IdentityContinuityChain(
            target_process_name=target_event.process.name or target_event.process.executable,
            target_pid=target_event.process.pid,
            effective_user=effective_user,
            effective_uid=effective_uid,
            login_user=session.login_user if session else (None if is_unset_auid else target_event.actor.username),
            login_auid=None if is_unset_auid else (session.auid if session else str(auid_val)),
            session_id=session.session_id if session else target_event.actor.session_id,
            terminal=session.terminal if session else target_event.actor.terminal,
            remote_ip=session.remote_ip if session else target_event.network.src_ip,
            epistemic_status=epistemic if session else ("UNKNOWN" if is_unset_auid else "INFERRED"),
        )

        # Detect privilege transitions if related events provided
        if all_events and session:
            transitions = self._extract_privilege_transitions(session, all_events)
            chain.privilege_transitions = transitions

        # Build human-readable deterministic narrative
        proc_str = chain.target_process_name or "process"
        pid_str = f" (PID {chain.target_pid})" if chain.target_pid else ""

        if is_unset_auid and not session:
            chain.narrative = (
                f"Process '{proc_str}'{pid_str} executed under system daemon / unauthenticated context "
                f"(UID {effective_uid}, AUID UNSET). No interactive session observed."
            )
        elif chain.login_user and chain.login_user != effective_user:
            origin_str = f" from {chain.remote_ip}" if chain.remote_ip else ""
            chain.narrative = (
                f"Elevated process '{proc_str}'{pid_str} executed as {effective_user} (UID {effective_uid}), "
                f"initiated from session {chain.session_id or 'unknown'} logged in by '{chain.login_user}' "
                f"(AUID {chain.login_auid or 'unknown'}){origin_str}."
            )
        else:
            chain.narrative = (
                f"Process '{proc_str}'{pid_str} executed by {effective_user} (UID {effective_uid}, "
                f"AUID {chain.login_auid or 'unknown'}) in session {chain.session_id or 'none'}."
            )

        return chain

    def _extract_privilege_transitions(
        self, session: SessionRecord, events: List[CanonicalEvent]
    ) -> List[PrivilegeTransition]:
        """Identify sudo, su, or setuid transitions associated with this session."""
        transitions: List[PrivilegeTransition] = []
        for e in events:
            if e.host != session.host:
                continue

            # Check if event belongs to session
            e_ses = e.actor.session_id or e.metadata.get("ses")
            if e_ses and str(e_ses) != session.session_id:
                continue

            if e.event_type in (EventType.SUDO_COMMAND, EventType.PRIVILEGE_ELEVATION_SUCCESS, EventType.PRIVILEGE_ELEVATION_ATTEMPT):
                ttype = PrivilegeTransitionType.SUDO if "sudo" in e.source or e.event_type == EventType.SUDO_COMMAND else PrivilegeTransitionType.SETUID
                trans = PrivilegeTransition(
                    transition_type=ttype,
                    host=e.host,
                    source_user=e.actor.username or session.login_user,
                    target_user=e.metadata.get("target_user") or "root",
                    source_uid=e.actor.uid,
                    target_uid=0 if (e.metadata.get("target_user") == "root") else None,
                    auid=session.auid,
                    session_id=session.session_id,
                    terminal=e.actor.terminal or session.terminal,
                    command=e.process.command_line or e.summary,
                    timestamp=e.timestamp,
                    event_id=e.id,
                    outcome=e.outcome.value,
                    epistemic_status="OBSERVED" if e_ses else "INFERRED",
                )
                transitions.append(trans)
        return transitions

    def _prune_expired_sessions(self, host: str):
        """Remove sessions older than retention limit to bound memory consumption."""
        host_sessions = self._sessions_by_id.get(host, {})
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=SESSION_EXPIRATION_HOURS)

        to_remove = [
            sid for sid, sess in host_sessions.items()
            if sess.state == SessionState.CLOSED and sess.end_time and sess.end_time < cutoff
        ]
        for sid in to_remove:
            del host_sessions[sid]
