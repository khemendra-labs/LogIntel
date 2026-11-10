"""Secure, file-based configuration for a LogIntel Linux collector agent."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


def default_config_path() -> Path:
    return Path(os.environ.get("LOGINTEL_AGENT_CONFIG", "/etc/logintel-agent/config.json"))


class AgentConfig(BaseModel):
    endpoint: str
    token: str = Field(min_length=32)
    host: str = Field(default_factory=socket.gethostname, min_length=1, max_length=255)
    spool_dir: Path = Path("/var/lib/logintel-agent/spool")
    ca_file: Optional[Path] = None
    client_cert_file: Optional[Path] = None
    client_key_file: Optional[Path] = None
    batch_size: int = Field(default=250, ge=1, le=500)
    max_spool_bytes: int = Field(default=64 * 1024 * 1024, ge=1024 * 1024, le=1024 * 1024 * 1024)
    timeout_seconds: float = Field(default=10.0, ge=1.0, le=60.0)
    poll_interval_seconds: float = Field(default=5.0, ge=1.0, le=300.0)
    journald_enabled: bool = True
    journal_max_records: int = Field(default=250, ge=1, le=500)
    max_record_bytes: int = Field(default=32 * 1024, ge=1024, le=1024 * 1024)
    log_paths: dict[str, Path] = Field(default_factory=lambda: {
        "auth.log": Path("/var/log/auth.log"),
        "syslog": Path("/var/log/syslog"),
        "kern.log": Path("/var/log/kern.log"),
        "audit.log": Path("/var/log/audit/audit.log"),
    })

    @field_validator("endpoint")
    @classmethod
    def validate_endpoint(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise ValueError("endpoint must be an absolute HTTP(S) URL")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("non-local collector endpoints must use HTTPS")
        return value.rstrip("/")

    def write(self, path: Optional[Path] = None) -> Path:
        target = path or default_config_path()
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(".tmp")
        temporary.write_text(self.model_dump_json(indent=2), encoding="utf-8")
        temporary.chmod(0o600)
        temporary.replace(target)
        return target

    @classmethod
    def load(cls, path: Optional[Path] = None) -> "AgentConfig":
        target = path or default_config_path()
        if not target.exists():
            raise FileNotFoundError(f"Agent configuration does not exist: {target}")
        mode = target.stat().st_mode & 0o777
        if mode & 0o077:
            raise PermissionError(f"Agent configuration must be owner-only (0600), found {oct(mode)}")
        return cls.model_validate_json(target.read_text(encoding="utf-8"))
