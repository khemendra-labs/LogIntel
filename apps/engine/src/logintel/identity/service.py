"""Identity and session continuity service for LogIntel (M6.3).

Provides end-to-end multi-source session correlation and identity provenance tracing
for forensic analysts.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from logintel.identity.models import (
    IdentityContinuityChain,
    PrivilegeTransition,
    SessionRecord,
    SessionState,
)
from logintel.identity.resolver import SessionContinuityResolver
from logintel.logging import get_logger
from logintel.models import CanonicalEvent, EventType
from logintel.storage.events_repo import EventsRepository, events_repo

logger = get_logger("identity.service")


class IdentityService:
    """Forensic identity and session continuity resolution service."""

    def __init__(self, repository: Optional[EventsRepository] = None):
        self.repo = repository or events_repo

    def get_identity_chain_for_event(self, event_id: str) -> Optional[IdentityContinuityChain]:
        """Resolve full identity provenance chain for a target canonical event."""
        target_event = self.repo.get_event_by_id(event_id)
        if not target_event:
            return None

        # Determine temporal correlation window (4 hours prior to 5 minutes after)
        start_time = target_event.timestamp - timedelta(hours=4)
        end_time = target_event.timestamp + timedelta(minutes=5)

        # Query candidate events on the same host in chronological order
        related_events, _ = self.repo.query_events(
            host=target_event.host,
            start_time=start_time,
            end_time=end_time,
            limit=500,
            sort_order="ASC",
        )

        resolver = SessionContinuityResolver()

        # Ingest session starts, logins, and ends chronologically
        for ev in related_events:
            if ev.event_type in (
                EventType.AUDIT_SESSION_START,
                EventType.SESSION_OPEN,
                EventType.AUTH_LOGIN_SUCCESS,
            ):
                resolver.register_session_start(ev)
            elif ev.event_type in (
                EventType.AUDIT_SESSION_END,
                EventType.SESSION_CLOSE,
                EventType.AUTH_LOGOUT,
            ):
                resolver.register_session_end(ev)

        return resolver.resolve_identity_continuity(target_event, all_events=related_events)

    def get_session_details(
        self, session_id: str, host: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Retrieve aggregated lifecycle and execution details for a given session ID."""
        events, total = self.repo.query_events(
            session_id=session_id,
            host=host,
            limit=200,
            sort_order="ASC",
        )
        if not events:
            return None

        first_ev = events[0]
        h = first_ev.host
        login_user = first_ev.actor.username
        auid = first_ev.metadata.get("auid")
        terminal = first_ev.actor.terminal
        remote_ip = first_ev.network.src_ip
        service = first_ev.metadata.get("service") or first_ev.source

        start_time = first_ev.timestamp
        end_time: Optional[datetime] = None
        is_active = True

        procs: List[Dict[str, Any]] = []
        transitions: List[Dict[str, Any]] = []

        for ev in events:
            if ev.event_type in (EventType.AUDIT_SESSION_END, EventType.SESSION_CLOSE, EventType.AUTH_LOGOUT):
                end_time = ev.timestamp
                is_active = False

            if ev.process.pid:
                procs.append({
                    "pid": ev.process.pid,
                    "ppid": ev.process.ppid,
                    "name": ev.process.name,
                    "executable": ev.process.executable,
                    "command_line": ev.process.command_line,
                    "timestamp": ev.timestamp.isoformat(),
                    "user": ev.actor.username,
                })

            if ev.metadata.get("is_privilege_transition") or ev.event_type in (
                EventType.SUDO_COMMAND,
                EventType.PRIVILEGE_ELEVATION_SUCCESS,
                EventType.PRIVILEGE_ELEVATION_ATTEMPT,
            ):
                transitions.append({
                    "event_id": ev.id,
                    "transition_type": ev.metadata.get("transition_type") or "UNKNOWN",
                    "source_user": ev.metadata.get("source_user") or ev.actor.username,
                    "target_user": ev.metadata.get("target_user") or "root",
                    "timestamp": ev.timestamp.isoformat(),
                    "command": ev.process.command_line or ev.summary,
                    "outcome": ev.outcome.value,
                })

        return {
            "session_id": session_id,
            "host": h,
            "login_user": login_user,
            "auid": auid,
            "terminal": terminal,
            "remote_ip": remote_ip,
            "service": service,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat() if end_time else None,
            "is_active": is_active,
            "events_count": total,
            "processes": procs,
            "privilege_transitions": transitions,
        }


identity_service = IdentityService()
