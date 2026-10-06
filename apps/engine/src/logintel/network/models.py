"""Data models for Linux network and socket state telemetry (M6.4).

Provides forensic representations for:
- Socket protocol (TCP, UDP, TCP6, UDP6).
- Kernel socket state (LISTEN, ESTABLISHED, TIME_WAIT, etc.).
- Socket endpoints (local IP/port and remote IP/port).
- Socket inode and associated host process (PID, name, exe, cmdline).
- Epistemic certainty tracking (OBSERVED, INFERRED, UNKNOWN).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SocketProtocol(str, Enum):
    """Network transport protocol."""
    TCP = "tcp"
    UDP = "udp"
    TCP6 = "tcp6"
    UDP6 = "udp6"


class SocketState(str, Enum):
    """Linux kernel socket states as reported by /proc/net/tcp."""
    ESTABLISHED = "ESTABLISHED"
    SYN_SENT = "SYN_SENT"
    SYN_RECV = "SYN_RECV"
    FIN_WAIT1 = "FIN_WAIT1"
    FIN_WAIT2 = "FIN_WAIT2"
    TIME_WAIT = "TIME_WAIT"
    CLOSE = "CLOSE"
    CLOSE_WAIT = "CLOSE_WAIT"
    LAST_ACK = "LAST_ACK"
    LISTEN = "LISTEN"
    CLOSING = "CLOSING"
    UNKNOWN = "UNKNOWN"


# Mapping from Linux /proc/net/tcp hex state codes to SocketState
TCP_HEX_STATES: Dict[str, SocketState] = {
    "01": SocketState.ESTABLISHED,
    "02": SocketState.SYN_SENT,
    "03": SocketState.SYN_RECV,
    "04": SocketState.FIN_WAIT1,
    "05": SocketState.FIN_WAIT2,
    "06": SocketState.TIME_WAIT,
    "07": SocketState.CLOSE,
    "08": SocketState.CLOSE_WAIT,
    "09": SocketState.LAST_ACK,
    "0A": SocketState.LISTEN,
    "0B": SocketState.CLOSING,
}


class SocketEntry(BaseModel):
    """Individual socket state record decoded from Linux kernel procfs."""
    protocol: SocketProtocol
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: SocketState
    inode: int
    uid: int
    tx_queue: int = 0
    rx_queue: int = 0

    # Process attribution (resolved via /proc/<pid>/fd/ scanning)
    pid: Optional[int] = None
    process_name: Optional[str] = None
    process_executable: Optional[str] = None
    process_cmdline: Optional[str] = None
    process_user: Optional[str] = None

    # Epistemic certainty of process association:
    # - OBSERVED: Direct match from /proc/<pid>/fd/ socket symlink
    # - INFERRED: Heuristic or parent binding
    # - UNKNOWN: Inode unmapped or process inaccessible due to permissions
    epistemic_status: str = "OBSERVED"
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def socket_key(self) -> str:
        """Deterministic unique key for tracking connection lifecycles across polls."""
        return f"{self.protocol.value}:{self.local_address}:{self.local_port}->{self.remote_address}:{self.remote_port}:{self.inode}"

    @property
    def is_listening(self) -> bool:
        """True if the socket is actively listening for incoming connections."""
        return self.state == SocketState.LISTEN

    @property
    def is_established(self) -> bool:
        """True if the socket is in an active two-way connection."""
        return self.state == SocketState.ESTABLISHED

    @property
    def is_loopback(self) -> bool:
        """True if both local and remote addresses reside on the local loopback interface."""
        return self.local_address in ("127.0.0.1", "::1") and (
            self.remote_address in ("0.0.0.0", "::", "127.0.0.1", "::1") or self.remote_port == 0
        )

    @property
    def is_outbound(self) -> bool:
        """True if the connection connects to an external non-loopback remote endpoint."""
        return (
            self.state == SocketState.ESTABLISHED
            and self.remote_port > 0
            and self.remote_address not in ("0.0.0.0", "::", "127.0.0.1", "::1")
        )


class SocketSnapshot(BaseModel):
    """Snapshot of active and listening sockets across the host at an instant in time."""
    host: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    entries: List[SocketEntry] = Field(default_factory=list)

    @property
    def total_count(self) -> int:
        return len(self.entries)

    @property
    def listening_entries(self) -> List[SocketEntry]:
        return [e for e in self.entries if e.is_listening]

    @property
    def established_entries(self) -> List[SocketEntry]:
        return [e for e in self.entries if e.is_established]

    @property
    def outbound_entries(self) -> List[SocketEntry]:
        return [e for e in self.entries if e.is_outbound]
