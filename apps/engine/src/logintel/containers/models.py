"""Data models for Container and Namespace Telemetry (M6.7).

Forensic representations for:
- Container runtimes (Docker, containerd, Podman, CRI-O, systemd-nspawn, host-native).
- Container operational states (running, paused, exited, dead, created).
- Linux kernel namespace isolation (mnt, net, pid, ipc, uts, user, cgroup, time).
- Process namespace profiling (mapping host PIDs to container contexts).
- Epistemic certainty modeling (OBSERVED, INFERRED, UNKNOWN).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ContainerRuntime(str, Enum):
    """Container runtime environment."""
    DOCKER = "docker"
    CONTAINERD = "containerd"
    PODMAN = "podman"
    CRIO = "crio"
    SYSTEMD_NSPAWN = "systemd_nspawn"
    HOST_NATIVE = "host_native"
    UNKNOWN = "unknown"


class ContainerState(str, Enum):
    """Container operational lifecycle state."""
    RUNNING = "running"
    PAUSED = "paused"
    RESTARTING = "restarting"
    EXITED = "exited"
    DEAD = "dead"
    CREATED = "created"
    UNKNOWN = "unknown"


class NamespaceType(str, Enum):
    """Linux kernel namespace categories."""
    MNT = "mnt"
    NET = "net"
    PID = "pid"
    IPC = "ipc"
    UTS = "uts"
    USER = "user"
    CGROUP = "cgroup"
    TIME = "time"


class NamespaceInfo(BaseModel):
    """Single kernel namespace descriptor."""
    ns_type: NamespaceType
    ns_id: int
    is_host_ns: bool = True


class ProcessNamespaceProfile(BaseModel):
    """Namespace isolation profile and container binding for a Linux process."""
    pid: int
    is_isolated: bool = False
    isolated_namespaces: List[NamespaceType] = Field(default_factory=list)
    container_id: Optional[str] = None
    container_runtime: ContainerRuntime = ContainerRuntime.HOST_NATIVE
    cgroup_path: str = ""
    epistemic_status: str = "OBSERVED"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ContainerInfo(BaseModel):
    """Forensic descriptor for a detected container instance."""
    container_id: str
    container_name: Optional[str] = None
    image: str = "unknown"
    runtime: ContainerRuntime = ContainerRuntime.DOCKER
    state: ContainerState = ContainerState.RUNNING
    created_at: Optional[datetime] = None
    pids: List[int] = Field(default_factory=list)
    ip_address: Optional[str] = None
    privileged: Optional[bool] = None
    epistemic_status: str = "OBSERVED"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ContainerLifecycleEvent(BaseModel):
    """Normalized container lifecycle transition or security event."""
    container_id: str
    container_name: Optional[str] = None
    action: str
    image: str = "unknown"
    runtime: ContainerRuntime = ContainerRuntime.DOCKER
    privileged: Optional[bool] = None
    raw_message: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
