"""Data models for Linux Filesystem & Persistence Telemetry (M6.5).

Forensic representations for:
- High-Value Target (HVT) persistence directories and sensitive configuration files.
- File state (inode, size, permissions, ownership, SHA-256 hash, symlink targets).
- File state transitions (CREATED, MODIFIED, DELETED, METADATA_CHANGED).
- Epistemic certainty modeling (OBSERVED, PERMISSION_RESTRICTED, UNKNOWN).
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetCategory(str, Enum):
    """Categorization of high-value filesystem targets and persistence vectors."""
    PERSISTENCE_CRON = "PERSISTENCE_CRON"
    PERSISTENCE_SSH = "PERSISTENCE_SSH"
    PERSISTENCE_SYSTEMD = "PERSISTENCE_SYSTEMD"
    PERSISTENCE_SHELL = "PERSISTENCE_SHELL"
    ACCOUNT_PRIVILEGE = "ACCOUNT_PRIVILEGE"
    DYNAMIC_LINKER = "DYNAMIC_LINKER"
    CUSTOM = "CUSTOM"


class FileTransitionType(str, Enum):
    """Types of observed file lifecycle transitions."""
    CREATED = "CREATED"
    MODIFIED = "MODIFIED"
    DELETED = "DELETED"
    METADATA_CHANGED = "METADATA_CHANGED"


class FileState(BaseModel):
    """Point-in-time forensic metadata and integrity state for a tracked file."""
    path: str
    category: TargetCategory
    exists: bool = True
    inode: Optional[int] = None
    size_bytes: Optional[int] = None
    mode_octal: Optional[str] = None
    uid: Optional[int] = None
    gid: Optional[int] = None
    mtime: Optional[float] = None
    ctime: Optional[float] = None
    sha256_hash: Optional[str] = None
    is_dir: bool = False
    is_symlink: bool = False
    symlink_target: Optional[str] = None

    # Epistemic certainty of file state:
    # - OBSERVED: File exists, stat and SHA-256 successfully computed
    # - PERMISSION_RESTRICTED: Stat retrieved but content unreadable (e.g. /etc/shadow)
    # - UNKNOWN: Inaccessible or transiently removed
    epistemic_status: str = "OBSERVED"
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def is_hash_available(self) -> bool:
        return self.sha256_hash is not None


class FileTransition(BaseModel):
    """Represents a detected state transition between scanning cycles."""
    path: str
    category: TargetCategory
    transition_type: FileTransitionType
    previous_state: Optional[FileState] = None
    current_state: Optional[FileState] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: str = ""


class HVTTarget(BaseModel):
    """Configuration target for high-value monitoring."""
    path: str
    category: TargetCategory
    is_directory: bool = False
    recursive: bool = False
    file_pattern: Optional[str] = None


# Authoritative default list of Linux High-Value Targets (HVTs)
DEFAULT_HVT_TARGETS: List[HVTTarget] = [
    # 1. Cron Persistence
    HVTTarget(path="/etc/crontab", category=TargetCategory.PERSISTENCE_CRON),
    HVTTarget(path="/etc/cron.d", category=TargetCategory.PERSISTENCE_CRON, is_directory=True),
    HVTTarget(path="/etc/cron.daily", category=TargetCategory.PERSISTENCE_CRON, is_directory=True),
    HVTTarget(path="/etc/cron.hourly", category=TargetCategory.PERSISTENCE_CRON, is_directory=True),
    HVTTarget(path="/etc/cron.weekly", category=TargetCategory.PERSISTENCE_CRON, is_directory=True),
    HVTTarget(path="/etc/cron.monthly", category=TargetCategory.PERSISTENCE_CRON, is_directory=True),
    HVTTarget(path="/var/spool/cron/crontabs", category=TargetCategory.PERSISTENCE_CRON, is_directory=True),

    # 2. Systemd Service Drops
    HVTTarget(path="/etc/systemd/system", category=TargetCategory.PERSISTENCE_SYSTEMD, is_directory=True),

    # 3. SSH User Persistence
    HVTTarget(path=str(Path.home() / ".ssh" / "authorized_keys"), category=TargetCategory.PERSISTENCE_SSH),

    # 4. Shell & Profile Persistence
    HVTTarget(path=str(Path.home() / ".bashrc"), category=TargetCategory.PERSISTENCE_SHELL),
    HVTTarget(path=str(Path.home() / ".profile"), category=TargetCategory.PERSISTENCE_SHELL),
    HVTTarget(path="/etc/profile", category=TargetCategory.PERSISTENCE_SHELL),
    HVTTarget(path="/etc/profile.d", category=TargetCategory.PERSISTENCE_SHELL, is_directory=True),
    HVTTarget(path="/etc/environment", category=TargetCategory.PERSISTENCE_SHELL),

    # 5. Accounts & Privilege Control
    HVTTarget(path="/etc/passwd", category=TargetCategory.ACCOUNT_PRIVILEGE),
    HVTTarget(path="/etc/shadow", category=TargetCategory.ACCOUNT_PRIVILEGE),
    HVTTarget(path="/etc/sudoers", category=TargetCategory.ACCOUNT_PRIVILEGE),
    HVTTarget(path="/etc/sudoers.d", category=TargetCategory.ACCOUNT_PRIVILEGE, is_directory=True),
    HVTTarget(path="/etc/group", category=TargetCategory.ACCOUNT_PRIVILEGE),

    # 6. Dynamic Linker Hijacking
    HVTTarget(path="/etc/ld.so.preload", category=TargetCategory.DYNAMIC_LINKER),
    HVTTarget(path="/etc/ld.so.conf", category=TargetCategory.DYNAMIC_LINKER),
    HVTTarget(path="/etc/ld.so.conf.d", category=TargetCategory.DYNAMIC_LINKER, is_directory=True),
]
