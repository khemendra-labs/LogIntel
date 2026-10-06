"""Data models for Systemd & Service Lifecycle Telemetry (M6.6).

Forensic representations for:
- Systemd unit state (unit_name, unit_type, load_state, active_state, sub_state, main_pid, user).
- Unit lifecycle actions (STARTING, STARTED, STOPPING, STOPPED, FAILED, RELOADED).
- Epistemic certainty modeling (OBSERVED, INFERRED, UNKNOWN).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class UnitState(str, Enum):
    """Systemd operational active states."""
    ACTIVE = "active"
    RELOADING = "reloading"
    INACTIVE = "inactive"
    FAILED = "failed"
    ACTIVATING = "activating"
    DEACTIVATING = "deactivating"
    UNKNOWN = "unknown"


class UnitLifecycleAction(str, Enum):
    """Lifecycle transitions observed from systemd."""
    STARTING = "STARTING"
    STARTED = "STARTED"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"
    RELOADED = "RELOADED"
    STATUS = "STATUS"


class SystemdUnitInfo(BaseModel):
    """Forensic inspection of a tracked systemd unit."""
    unit_name: str
    unit_type: str = "service"
    description: Optional[str] = None
    load_state: str = "loaded"
    active_state: UnitState = UnitState.ACTIVE
    sub_state: str = "running"
    main_pid: Optional[int] = None
    exit_code: Optional[int] = None
    user: Optional[str] = None
    epistemic_status: str = "OBSERVED"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UnitLifecycleEvent(BaseModel):
    """Normalized unit lifecycle transition."""
    unit_name: str
    unit_type: str
    action: UnitLifecycleAction
    description: Optional[str] = None
    main_pid: Optional[int] = None
    exit_code: Optional[int] = None
    raw_message: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
