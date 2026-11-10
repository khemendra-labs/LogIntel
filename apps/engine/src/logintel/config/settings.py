"""Centralized configuration management for LogIntel."""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Optional
from pydantic import BaseModel, Field


def get_default_data_dir() -> Path:
    """Return standard user data directory for LogIntel according to XDG base directory spec."""
    xdg_data = os.environ.get("XDG_DATA_HOME")
    if xdg_data:
        base = Path(xdg_data)
    else:
        base = Path.home() / ".local" / "share"
    logintel_dir = base / "logintel"
    logintel_dir.mkdir(parents=True, exist_ok=True)
    try:
        if (logintel_dir.stat().st_mode & 0o777) != 0o700:
            logintel_dir.chmod(0o700)
    except OSError:
        pass
    return logintel_dir


def get_default_log_dir() -> Path:
    """Return standard user log directory for LogIntel."""
    xdg_state = os.environ.get("XDG_STATE_HOME")
    if xdg_state:
        base = Path(xdg_state)
    else:
        base = Path.home() / ".local" / "state"
    log_dir = base / "logintel"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


class CollectorSettings(BaseModel):
    journald_enabled: bool = True
    journald_max_historical_records: int = 5000
    
    auth_log_enabled: bool = True
    auth_log_path: str = "/var/log/auth.log"
    
    syslog_enabled: bool = True
    syslog_path: str = "/var/log/syslog"
    
    kern_log_enabled: bool = True
    kern_log_path: str = "/var/log/kern.log"

    audit_log_enabled: bool = True
    audit_log_path: str = "/var/log/audit/audit.log"

    socket_collector_enabled: bool = True
    proc_net_path: str = "/proc/net"
    proc_path: str = "/proc"

    filesystem_collector_enabled: bool = True
    
    # The main loop remains responsive for append-only logs.  Expensive sources
    # are scheduled independently below rather than being re-scanned each loop.
    poll_interval_seconds: float = 1.0
    journald_poll_interval_seconds: float = 5.0
    journald_max_records_per_cycle: int = 1000
    socket_poll_interval_seconds: float = 5.0
    filesystem_poll_interval_seconds: float = 60.0
    batch_size: int = 100


class RemoteIngestSettings(BaseModel):
    """Opt-in boundary for future remote Linux collectors.

    The API remains loopback-only by default. Operators enabling a reverse
    proxy or a private listener must set a high-entropy shared token outside
    the repository; unauthenticated fleet intake is never permitted.
    """
    enabled: bool = False
    agent_token: Optional[str] = Field(default_factory=lambda: os.environ.get("LOGINTEL_AGENT_TOKEN"))
    max_batch_records: int = 500
    max_record_bytes: int = 32 * 1024


class RetentionSettings(BaseModel):
    """Conservative local database retention policy.

    Evidence referenced by detections is never removed automatically. The
    policy is disabled by default and execution requires an explicit API call.
    """
    enabled: bool = False
    event_retention_days: int = Field(default=90, ge=1, le=3650)
    max_delete_batch: int = Field(default=5000, ge=1, le=50000)


class Settings(BaseModel):
    app_name: str = "LogIntel"
    version: str = "0.1.0"
    
    host_name: str = Field(default_factory=socket.gethostname)
    
    data_dir: Path = Field(default_factory=get_default_data_dir)
    log_dir: Path = Field(default_factory=get_default_log_dir)
    
    db_filename: str = "logintel.db"
    
    api_host: str = "127.0.0.1"
    api_port: int = 41721
    
    log_level: str = "INFO"
    collectors: CollectorSettings = Field(default_factory=CollectorSettings)
    remote_ingest: RemoteIngestSettings = Field(default_factory=RemoteIngestSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)

    @property
    def db_path(self) -> Path:
        return self.data_dir / self.db_filename

    @property
    def log_file(self) -> Path:
        return self.log_dir / "engine.log"

    @property
    def token_path(self) -> Path:
        return self.data_dir / ".engine_token"

    @property
    def rules_dir(self) -> Path:
        env_rules = os.environ.get("LOGINTEL_RULES_DIR")
        if env_rules:
            return Path(env_rules)
        # Search candidate parents for repo root rules directory
        for parent in Path(__file__).resolve().parents:
            candidate = parent / "rules"
            if candidate.is_dir() and (candidate / "authentication").is_dir():
                return candidate
        pkg_rules = Path("/usr/share/logintel/rules")
        if pkg_rules.exists() and pkg_rules.is_dir():
            return pkg_rules
        return self.data_dir / "rules"


# Global singleton settings instance
settings = Settings()
