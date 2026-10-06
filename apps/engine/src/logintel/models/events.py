"""Canonical Security Event Model for LogIntel.

This module defines the typed canonical representation of security telemetry events.
All raw events are parsed and normalized into this structure while preserving
original raw messages, parsing provenance, and source offsets.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    DEBUG = "DEBUG"
    INFORMATIONAL = "INFORMATIONAL"
    NOTICE = "NOTICE"
    WARNING = "WARNING"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"


class Outcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    ATTEMPT = "ATTEMPT"
    UNKNOWN = "UNKNOWN"


class EventType(str, Enum):
    # Authentication & Session
    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_LOGOUT = "AUTH_LOGOUT"
    SESSION_OPEN = "SESSION_OPEN"
    SESSION_CLOSE = "SESSION_CLOSE"
    
    # Privilege & Access
    PRIVILEGE_ELEVATION_ATTEMPT = "PRIVILEGE_ELEVATION_ATTEMPT"
    PRIVILEGE_ELEVATION_SUCCESS = "PRIVILEGE_ELEVATION_SUCCESS"
    PRIVILEGE_ELEVATION_FAILURE = "PRIVILEGE_ELEVATION_FAILURE"
    SUDO_COMMAND = "SUDO_COMMAND"
    
    # Account & Identity
    USER_CREATE = "USER_CREATE"
    USER_DELETE = "USER_DELETE"
    USER_MODIFY = "USER_MODIFY"
    GROUP_MODIFY = "GROUP_MODIFY"
    
    # System & Kernel
    SYSTEM_BOOT = "SYSTEM_BOOT"
    SYSTEM_SHUTDOWN = "SYSTEM_SHUTDOWN"
    KERNEL_MESSAGE = "KERNEL_MESSAGE"
    KERNEL_DEVICE_CHANGE = "KERNEL_DEVICE_CHANGE"
    SYSTEM_SERVICE_STATE = "SYSTEM_SERVICE_STATE"
    
    # Security & Access Control
    SECURITY_ACCESS_DENIED = "SECURITY_ACCESS_DENIED"
    
    # Process & Execution (M6.2)
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    AUDIT_SESSION_START = "AUDIT_SESSION_START"
    AUDIT_SESSION_END = "AUDIT_SESSION_END"

    # General & Unclassified
    SYSTEM_GENERIC = "SYSTEM_GENERIC"
    UNKNOWN = "UNKNOWN"


class Actor(BaseModel):
    username: Optional[str] = None
    uid: Optional[int] = None
    session_id: Optional[str] = None
    terminal: Optional[str] = None


class Process(BaseModel):
    name: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    executable: Optional[str] = None
    command_line: Optional[str] = None


class Network(BaseModel):
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None


class CanonicalEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    host: str
    source: str
    event_type: EventType = EventType.SYSTEM_GENERIC
    severity: Severity = Severity.INFORMATIONAL
    
    actor: Actor = Field(default_factory=Actor)
    process: Process = Field(default_factory=Process)
    network: Network = Field(default_factory=Network)
    
    action: Optional[str] = None
    outcome: Outcome = Outcome.UNKNOWN
    
    summary: str
    raw_message: str
    
    iocs: List[str] = Field(default_factory=list)
    parser: str = "generic"
    source_file: Optional[str] = None
    source_offset: Optional[str] = None
    event_fingerprint: Optional[str] = None
    
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def compute_fingerprint(self) -> str:
        """Derive a stable, deterministic ingestion fingerprint from source provenance and content."""
        import hashlib
        seed = f"{self.source}:{self.source_file or ''}:{self.source_offset or ''}:{self.raw_message}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

    def to_db_row(self) -> Dict[str, Any]:
        """Convert canonical event to flat dictionary suitable for SQLite insertion."""
        import json
        fp = self.event_fingerprint or self.compute_fingerprint()
        return {
            "id": self.id,
            "event_fingerprint": fp,
            "timestamp": self.timestamp.isoformat(),
            "ingested_at": self.ingested_at.isoformat(),
            "host": self.host,
            "source": self.source,
            "event_type": self.event_type.value,
            "severity": self.severity.value,
            "username": self.actor.username,
            "uid": self.actor.uid,
            "session_id": self.actor.session_id,
            "terminal": self.actor.terminal,
            "process_name": self.process.name,
            "process_pid": self.process.pid,
            "process_ppid": self.process.ppid,
            "process_executable": self.process.executable,
            "process_command_line": self.process.command_line,
            "src_ip": self.network.src_ip,
            "src_port": self.network.src_port,
            "dst_ip": self.network.dst_ip,
            "dst_port": self.network.dst_port,
            "protocol": self.network.protocol,
            "action": self.action,
            "outcome": self.outcome.value,
            "summary": self.summary,
            "raw_message": self.raw_message,
            "iocs_json": json.dumps(self.iocs),
            "parser": self.parser,
            "source_file": self.source_file,
            "source_offset": str(self.source_offset) if self.source_offset is not None else None,
            "metadata_json": json.dumps(self.metadata),
        }

    @classmethod
    def from_db_row(cls, row: Dict[str, Any]) -> "CanonicalEvent":
        """Reconstruct canonical event from a SQLite dictionary row."""
        import json
        
        iocs = json.loads(row.get("iocs_json") or "[]")
        metadata = json.loads(row.get("metadata_json") or "{}")
        
        return cls(
            id=row["id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            ingested_at=datetime.fromisoformat(row["ingested_at"]),
            host=row["host"],
            source=row["source"],
            event_type=EventType(row["event_type"]) if row.get("event_type") in EventType._value2member_map_ else EventType.UNKNOWN,
            severity=Severity(row["severity"]) if row.get("severity") in Severity._value2member_map_ else Severity.INFORMATIONAL,
            actor=Actor(
                username=row.get("username"),
                uid=row.get("uid"),
                session_id=row.get("session_id"),
                terminal=row.get("terminal"),
            ),
            process=Process(
                name=row.get("process_name"),
                pid=row.get("process_pid"),
                ppid=row.get("process_ppid"),
                executable=row.get("process_executable"),
                command_line=row.get("process_command_line"),
            ),
            network=Network(
                src_ip=row.get("src_ip"),
                src_port=row.get("src_port"),
                dst_ip=row.get("dst_ip"),
                dst_port=row.get("dst_port"),
                protocol=row.get("protocol"),
            ),
            action=row.get("action"),
            outcome=Outcome(row["outcome"]) if row.get("outcome") in Outcome._value2member_map_ else Outcome.UNKNOWN,
            summary=row.get("summary") or "",
            raw_message=row.get("raw_message") or "",
            iocs=iocs,
            parser=row.get("parser") or "unknown",
            source_file=row.get("source_file"),
            source_offset=row.get("source_offset"),
            event_fingerprint=row.get("event_fingerprint"),
            metadata=metadata,
        )
