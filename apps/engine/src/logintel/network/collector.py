"""Socket state telemetry collector for Linux host networking (M6.4).

Polls kernel socket tables (/proc/net/{tcp,tcp6,udp,udp6}) and detects state transitions:
- Emits NETWORK_SOCKET_LISTEN for new listening ports.
- Emits NETWORK_SOCKET_CONNECTION for new inbound/outbound established sessions.
- Emits NETWORK_SOCKET_CLOSE when active connections terminate.
- Enriches events with resolved process context (PID, process name, executable) and M6.3 identity.
- Preserves raw socket telemetry in raw_message with deterministic SHA-256 fingerprints.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Dict, Generator, List, Optional, Set

from logintel.collectors.base import Collector
from logintel.models import (
    Actor,
    CanonicalEvent,
    EventType,
    Network,
    Outcome,
    Process,
    RawRecord,
    Severity,
)
from logintel.network.models import (
    SocketEntry,
    SocketProtocol,
    SocketSnapshot,
    SocketState,
)
from logintel.network.proc_reader import ProcNetReader
from logintel.network.resolver import SocketProcessResolver


class SocketStateCollector(Collector):
    """Monitors Linux network socket transitions via procfs polling."""

    def __init__(
        self,
        name: str = "socket_collector",
        source_type: str = "procfs_network",
        proc_net_path: str = "/proc/net",
        proc_path: str = "/proc",
        poll_interval_sec: float = 5.0,
        session_resolver: Optional[Any] = None,
    ) -> None:
        super().__init__(name=name, source_type=source_type)
        self.reader = ProcNetReader(base_path=proc_net_path)
        self.resolver = SocketProcessResolver(proc_path=proc_path)
        self.poll_interval_sec = poll_interval_sec
        self.session_resolver = session_resolver
        self.host = "localhost"

        # State tracking caches for delta detection
        # socket_key -> SocketEntry
        self._previous_listening: Dict[str, SocketEntry] = {}
        self._previous_established: Dict[str, SocketEntry] = {}
        self._is_initial_snapshot: bool = True

    def check_availability(self) -> tuple[bool, Optional[str]]:
        """Verify that /proc/net/tcp or other socket tables are readable."""
        if not self.reader.base_path.exists():
            return False, f"Directory does not exist: {self.reader.base_path}"
        try:
            test_file = self.reader.base_path / "tcp"
            if test_file.exists():
                with open(test_file, "r") as f:
                    f.readline()
            return True, None
        except Exception as e:
            return False, f"Permission or read error on {self.reader.base_path}: {e}"

    def collect_historical(self, limit: int = 2000) -> Generator[RawRecord, None, None]:
        """Collect initial baseline snapshot of listening sockets."""
        records = self.collect()
        for r in records[:limit]:
            yield r

    def collect_new(self) -> Generator[RawRecord, None, None]:
        """Collect incremental socket transition records."""
        records = self.collect()
        for r in records:
            yield r

    def take_snapshot(self) -> SocketSnapshot:
        """Capture and resolve the current socket state across all protocols."""
        raw_entries = self.reader.read_all_sockets()
        resolved_entries = self.resolver.resolve_entries(raw_entries)
        return SocketSnapshot(
            host=self.host,
            entries=resolved_entries,
        )

    def collect(self) -> List[RawRecord]:
        """Poll socket state and emit raw records for detected transitions."""
        events = self.collect_events()
        records: List[RawRecord] = []
        for ev in events:
            rec = RawRecord(
                source="procfs_network",
                raw_content=ev.raw_message,
                host=ev.host,
                timestamp=ev.timestamp,
                source_file="/proc/net/tcp",
                source_offset=str(ev.metadata.get("inode", 0)),
            )
            records.append(rec)
        return records

    def collect_events(self) -> List[CanonicalEvent]:
        """Poll socket state and produce canonical events for new connections or listeners."""
        snapshot = self.take_snapshot()
        current_listening: Dict[str, SocketEntry] = {}
        current_established: Dict[str, SocketEntry] = {}

        for entry in snapshot.entries:
            if entry.is_listening:
                current_listening[entry.socket_key] = entry
            elif entry.is_established:
                current_established[entry.socket_key] = entry

        events: List[CanonicalEvent] = []

        if self._is_initial_snapshot:
            # On first poll, record current listeners as baseline events
            for key, entry in current_listening.items():
                ev = self._create_listen_event(entry, is_baseline=True)
                events.append(ev)
            self._previous_listening = current_listening
            self._previous_established = current_established
            self._is_initial_snapshot = False
            return events

        # 1. Detect new listening sockets
        for key, entry in current_listening.items():
            if key not in self._previous_listening:
                ev = self._create_listen_event(entry, is_baseline=False)
                events.append(ev)

        # 2. Detect new established connections
        for key, entry in current_established.items():
            if key not in self._previous_established:
                ev = self._create_connection_event(entry)
                events.append(ev)

        # 3. Detect closed connections (optional transition tracking)
        for key, entry in self._previous_established.items():
            if key not in current_established:
                ev = self._create_close_event(entry)
                events.append(ev)

        self._previous_listening = current_listening
        self._previous_established = current_established
        return events

    def _create_listen_event(self, entry: SocketEntry, is_baseline: bool = False) -> CanonicalEvent:
        """Create a CanonicalEvent for a newly observed listening socket."""
        now = datetime.now(timezone.utc)
        if entry.pid and entry.process_name:
            proc_str = f"'{entry.process_name}' (PID: {entry.pid})"
        elif entry.process_name:
            proc_str = f"'{entry.process_name}'"
        elif entry.pid:
            proc_str = f"process PID {entry.pid}"
        else:
            proc_str = "unmapped process"
        status_note = "Baseline" if is_baseline else "New"
        summary = (
            f"{status_note} listening socket opened on {entry.local_address}:{entry.local_port} "
            f"({entry.protocol.value}) by {proc_str}"
        )

        raw_line = (
            f"proto={entry.protocol.value} local={entry.local_address}:{entry.local_port} "
            f"state=LISTEN inode={entry.inode} uid={entry.uid} pid={entry.pid or 'none'} "
            f"comm={entry.process_name or 'unknown'}"
        )

        fp = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
        event_id = f"sock-listen-{entry.inode}-{fp[:12]}"

        return CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="procfs_network",
            event_type=EventType.NETWORK_SOCKET_LISTEN,
            severity=Severity.INFORMATIONAL,
            actor=Actor(
                username=entry.process_user,
                uid=entry.uid,
            ),
            process=Process(
                name=entry.process_name,
                pid=entry.pid,
                executable=entry.process_executable,
                command_line=entry.process_cmdline,
            ),
            network=Network(
                src_ip=entry.local_address,
                src_port=entry.local_port,
                dst_ip="0.0.0.0" if ":" not in entry.local_address else "::",
                dst_port=0,
                protocol=entry.protocol.value,
            ),
            action="SOCKET_LISTEN",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_line,
            parser="procfs_socket",
            event_fingerprint=fp,
            metadata={
                "inode": entry.inode,
                "protocol": entry.protocol.value,
                "state": entry.state.value,
                "rx_queue": entry.rx_queue,
                "tx_queue": entry.tx_queue,
                "is_loopback": entry.is_loopback,
                "is_baseline": is_baseline,
                "epistemic_status": entry.epistemic_status,
            },
        )
        self._enrich_with_session(ev)
        return ev

    def _enrich_with_session(self, ev: CanonicalEvent) -> None:
        """Attach M6.3 session continuity provenance if available."""
        if self.session_resolver and ev.process.pid:
            sess, epistemic = self.session_resolver.correlate_event_to_session(ev)
            if sess:
                ev.actor.session_id = sess.session_id
                if sess.login_user:
                    ev.actor.username = sess.login_user
                ev.metadata["login_user"] = sess.login_user
                ev.metadata["auid"] = sess.auid
                ev.metadata["session_id"] = sess.session_id
                ev.metadata["identity_epistemic_status"] = epistemic

    def _create_connection_event(self, entry: SocketEntry) -> CanonicalEvent:
        """Create a CanonicalEvent for a newly established network connection."""
        now = datetime.now(timezone.utc)
        if entry.pid and entry.process_name:
            proc_str = f"'{entry.process_name}' (PID: {entry.pid})"
        elif entry.process_name:
            proc_str = f"'{entry.process_name}'"
        elif entry.pid:
            proc_str = f"process PID {entry.pid}"
        else:
            proc_str = "unmapped process"
        conn_dir = "Outbound" if entry.is_outbound else "Local/Inbound"
        summary = (
            f"{conn_dir} network connection established: {entry.local_address}:{entry.local_port} -> "
            f"{entry.remote_address}:{entry.remote_port} ({entry.protocol.value}) by {proc_str}"
        )

        raw_line = (
            f"proto={entry.protocol.value} local={entry.local_address}:{entry.local_port} "
            f"remote={entry.remote_address}:{entry.remote_port} state=ESTABLISHED inode={entry.inode} "
            f"uid={entry.uid} pid={entry.pid or 'none'} comm={entry.process_name or 'unknown'}"
        )

        fp = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
        event_id = f"sock-conn-{entry.inode}-{fp[:12]}"
        severity = Severity.NOTICE if entry.is_outbound else Severity.INFORMATIONAL

        ev = CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="procfs_network",
            event_type=EventType.NETWORK_SOCKET_CONNECTION,
            severity=severity,
            actor=Actor(
                username=entry.process_user,
                uid=entry.uid,
            ),
            process=Process(
                name=entry.process_name,
                pid=entry.pid,
                executable=entry.process_executable,
                command_line=entry.process_cmdline,
            ),
            network=Network(
                src_ip=entry.local_address,
                src_port=entry.local_port,
                dst_ip=entry.remote_address,
                dst_port=entry.remote_port,
                protocol=entry.protocol.value,
            ),
            action="SOCKET_CONNECT",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_line,
            parser="procfs_socket",
            event_fingerprint=fp,
            metadata={
                "inode": entry.inode,
                "protocol": entry.protocol.value,
                "state": entry.state.value,
                "is_outbound": entry.is_outbound,
                "is_loopback": entry.is_loopback,
                "rx_queue": entry.rx_queue,
                "tx_queue": entry.tx_queue,
                "epistemic_status": entry.epistemic_status,
            },
        )
        self._enrich_with_session(ev)
        return ev

    def _create_close_event(self, entry: SocketEntry) -> CanonicalEvent:
        """Create a CanonicalEvent when an active established connection terminates."""
        now = datetime.now(timezone.utc)
        summary = (
            f"Network connection closed: {entry.local_address}:{entry.local_port} -> "
            f"{entry.remote_address}:{entry.remote_port} ({entry.protocol.value})"
        )

        raw_line = (
            f"proto={entry.protocol.value} local={entry.local_address}:{entry.local_port} "
            f"remote={entry.remote_address}:{entry.remote_port} state=CLOSE inode={entry.inode} "
            f"uid={entry.uid} pid={entry.pid or 'none'}"
        )

        fp = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
        event_id = f"sock-close-{entry.inode}-{fp[:12]}"

        ev = CanonicalEvent(
            id=event_id,
            timestamp=now,
            ingested_at=now,
            host=self.host,
            source="procfs_network",
            event_type=EventType.NETWORK_SOCKET_CLOSE,
            severity=Severity.DEBUG,
            actor=Actor(
                username=entry.process_user,
                uid=entry.uid,
            ),
            process=Process(
                name=entry.process_name,
                pid=entry.pid,
                executable=entry.process_executable,
                command_line=entry.process_cmdline,
            ),
            network=Network(
                src_ip=entry.local_address,
                src_port=entry.local_port,
                dst_ip=entry.remote_address,
                dst_port=entry.remote_port,
                protocol=entry.protocol.value,
            ),
            action="SOCKET_CLOSE",
            outcome=Outcome.SUCCESS,
            summary=summary,
            raw_message=raw_line,
            parser="procfs_socket",
            event_fingerprint=fp,
            metadata={
                "inode": entry.inode,
                "protocol": entry.protocol.value,
                "state": "CLOSED",
                "epistemic_status": entry.epistemic_status,
            },
        )
        self._enrich_with_session(ev)
        return ev
