"""Process ancestry reconstruction and PID reuse resolution for LogIntel (M6.2).

Provides deterministic parent-child process tree traversal based on forensic
telemetry, enforcing strict epistemic boundaries:
- OBSERVED: Explicit audit/parent-child linkage with verifiable event evidence.
- INFERRED: Contextually reconstructed linkage.
- UNKNOWN: Missing or unprovable parent process.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from logintel.logging import get_logger
from logintel.models import CanonicalEvent
from logintel.storage.events_repo import EventsRepository

logger = get_logger("correlation.ancestry")

MAX_ANCESTRY_DEPTH = 32


class ProcessNode(BaseModel):
    """Represents a single process node within an execution ancestry tree."""
    pid: int
    ppid: Optional[int] = None
    name: Optional[str] = None
    executable: Optional[str] = None
    command_line: Optional[str] = None
    timestamp: datetime
    host: str
    username: Optional[str] = None
    auid: Optional[str] = None
    event_id: Optional[str] = None
    depth: int = 0
    relationship_to_child: str = "SPAWNED"
    confidence: str = "DIRECT"
    epistemic_status: str = "OBSERVED"


class ProcessAncestryChain(BaseModel):
    """Reconstructed execution ancestry chain starting from a target process."""
    target_pid: int
    target_host: str
    chain: List[ProcessNode] = Field(default_factory=list)
    max_depth: int = 0
    is_complete: bool = False

    @property
    def root(self) -> Optional[ProcessNode]:
        """Return the oldest ancestor in the chain."""
        return self.chain[-1] if self.chain else None

    @property
    def leaf(self) -> Optional[ProcessNode]:
        """Return the target process node."""
        return self.chain[0] if self.chain else None

    def format_tree(self) -> str:
        """Render a text representation of the process ancestry tree."""
        if not self.chain:
            return "No ancestry observed."
        # Reverse to show from root to leaf
        lines = []
        for i, node in enumerate(reversed(self.chain)):
            indent = "  " * i
            arrow = "└── " if i > 0 else ""
            cmd = node.command_line or node.name or "unknown"
            lines.append(f"{indent}{arrow}{node.name or 'unknown'} (PID: {node.pid}, PPID: {node.ppid or 'none'}) [User: {node.username or 'unset'}]: {cmd}")
        return "\n".join(lines)


def build_process_identity(
    host: str,
    pid: int,
    timestamp: datetime,
    exe: Optional[str] = None,
    audit_seq: Optional[str] = None,
) -> str:
    """Build a deterministic process identity string distinguishing PID reuse across time.

    Combines host, PID, ISO timestamp, executable basename, and optional audit sequence.
    """
    ts_iso = timestamp.isoformat()
    exe_name = exe or "unknown"
    seq_part = f":seq{audit_seq}" if audit_seq else ""
    return f"proc:{host}:{pid}:{ts_iso}:{exe_name}{seq_part}"


class ProcessAncestryResolver:
    """Resolves and reconstructs parent-child process ancestry chains."""

    @staticmethod
    def resolve_ancestry_from_events(
        target_event: CanonicalEvent,
        all_events: List[CanonicalEvent],
        max_depth: int = MAX_ANCESTRY_DEPTH,
    ) -> ProcessAncestryChain:
        """Reconstruct process ancestry chain from an in-memory collection of events."""
        target_pid = target_event.process.pid or 0
        target_host = target_event.host

        chain = ProcessAncestryChain(target_pid=target_pid, target_host=target_host)
        if target_pid <= 0:
            return chain

        # Filter events for this host that have valid process info
        proc_events = [
            e for e in all_events
            if e.host == target_host and e.process.pid is not None
        ]

        # Group by PID, sorted by timestamp descending
        events_by_pid: Dict[int, List[CanonicalEvent]] = {}
        for e in proc_events:
            events_by_pid.setdefault(e.process.pid, []).append(e)

        for pid_events in events_by_pid.values():
            pid_events.sort(key=lambda x: x.timestamp, reverse=True)

        # Build leaf node
        current_node = ProcessNode(
            pid=target_pid,
            ppid=target_event.process.ppid,
            name=target_event.process.name,
            executable=target_event.process.executable,
            command_line=target_event.process.command_line,
            timestamp=target_event.timestamp,
            host=target_host,
            username=target_event.actor.username,
            auid=target_event.metadata.get("auid"),
            event_id=target_event.id,
            depth=0,
            relationship_to_child="TARGET",
            confidence="DIRECT",
            epistemic_status="OBSERVED",
        )
        chain.chain.append(current_node)

        visited_pids: Set[int] = {target_pid}
        current_event = target_event
        depth = 0

        while depth < max_depth:
            ppid = current_event.process.ppid
            if not ppid or ppid <= 0 or ppid in visited_pids:
                chain.is_complete = (ppid is None or ppid <= 0)
                break

            visited_pids.add(ppid)

            # Find parent event where timestamp <= current_event.timestamp
            candidates = [
                e for e in events_by_pid.get(ppid, [])
                if e.timestamp <= current_event.timestamp
            ]

            if not candidates:
                # Parent process event is not observed in the telemetry batch
                chain.is_complete = False
                break

            parent_event = candidates[0]
            depth += 1

            parent_node = ProcessNode(
                pid=ppid,
                ppid=parent_event.process.ppid,
                name=parent_event.process.name,
                executable=parent_event.process.executable,
                command_line=parent_event.process.command_line,
                timestamp=parent_event.timestamp,
                host=target_host,
                username=parent_event.actor.username,
                auid=parent_event.metadata.get("auid"),
                event_id=parent_event.id,
                depth=depth,
                relationship_to_child="SPAWNED",
                confidence="DIRECT",
                epistemic_status="OBSERVED",
            )
            chain.chain.append(parent_node)
            current_event = parent_event

        chain.max_depth = depth
        return chain

    @staticmethod
    def resolve_ancestry_from_db(
        repo: EventsRepository,
        host: str,
        pid: int,
        timestamp: datetime,
        max_depth: int = MAX_ANCESTRY_DEPTH,
    ) -> ProcessAncestryChain:
        """Reconstruct process ancestry chain by querying the forensic database."""
        chain = ProcessAncestryChain(target_pid=pid, target_host=host)
        if pid <= 0:
            return chain

        with repo.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT * FROM events
                WHERE host = ? AND process_pid = ? AND timestamp <= ?
                ORDER BY timestamp DESC LIMIT 1
                """,
                (host, pid, timestamp.isoformat()),
            )
            row = cur.fetchone()
            if not row:
                return chain

            target_event = CanonicalEvent.from_db_row(dict(row))
            visited_pids: Set[int] = {pid}

            leaf_node = ProcessNode(
                pid=pid,
                ppid=target_event.process.ppid,
                name=target_event.process.name,
                executable=target_event.process.executable,
                command_line=target_event.process.command_line,
                timestamp=target_event.timestamp,
                host=host,
                username=target_event.actor.username,
                auid=target_event.metadata.get("auid"),
                event_id=target_event.id,
                depth=0,
                relationship_to_child="TARGET",
                confidence="DIRECT",
                epistemic_status="OBSERVED",
            )
            chain.chain.append(leaf_node)

            depth = 0
            current_event = target_event

            while depth < max_depth:
                ppid = current_event.process.ppid
                if not ppid or ppid <= 0 or ppid in visited_pids:
                    chain.is_complete = (ppid is None or ppid <= 0)
                    break

                visited_pids.add(ppid)

                cur.execute(
                    """
                    SELECT * FROM events
                    WHERE host = ? AND process_pid = ? AND timestamp <= ?
                    ORDER BY timestamp DESC LIMIT 1
                    """,
                    (host, ppid, current_event.timestamp.isoformat()),
                )
                p_row = cur.fetchone()
                if not p_row:
                    chain.is_complete = False
                    break

                parent_event = CanonicalEvent.from_db_row(dict(p_row))
                depth += 1

                parent_node = ProcessNode(
                    pid=ppid,
                    ppid=parent_event.process.ppid,
                    name=parent_event.process.name,
                    executable=parent_event.process.executable,
                    command_line=parent_event.process.command_line,
                    timestamp=parent_event.timestamp,
                    host=host,
                    username=parent_event.actor.username,
                    auid=parent_event.metadata.get("auid"),
                    event_id=parent_event.id,
                    depth=depth,
                    relationship_to_child="SPAWNED",
                    confidence="DIRECT",
                    epistemic_status="OBSERVED",
                )
                chain.chain.append(parent_node)
                current_event = parent_event

        chain.max_depth = depth
        return chain
