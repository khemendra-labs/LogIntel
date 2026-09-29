"""Telemetry health diagnostics and verification service."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from logintel.collectors import (
    AuthLogCollector,
    Collector,
    JournalCollector,
    KernLogCollector,
    SyslogCollector,
)
from logintel.config import settings
from logintel.logging import get_logger
from logintel.storage.events_repo import EventsRepository, events_repo

logger = get_logger("health.checker")


class SourceHealth(BaseModel):
    name: str
    source_type: str
    available: bool
    error_reason: Optional[str] = None
    total_records: int = 0
    last_collected_at: Optional[str] = None
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_permissions: Optional[str] = None
    action_hint: Optional[str] = None


class TelemetryHealthReport(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    overall_status: str  # "HEALTHY", "DEGRADED", "OFFLINE"
    sources: List[SourceHealth]
    total_events_in_db: int
    database_size_bytes: int
    active_sources_count: int
    total_sources_count: int


class HealthService:
    """Monitors telemetry collectors, files, and database status."""

    def __init__(self, repo: Optional[EventsRepository] = None):
        self.repo = repo or events_repo

    def inspect_file(self, path_str: str) -> Dict[str, Any]:
        p = Path(path_str)
        if not p.exists():
            return {
                "available": False,
                "error_reason": f"Path '{path_str}' does not exist on host.",
                "action_hint": "Verify system syslog daemon (rsyslog or systemd-journald) is configured to write log files.",
            }
        if not os.access(p, os.R_OK):
            return {
                "available": False,
                "error_reason": f"Permission denied reading '{path_str}'.",
                "action_hint": "Add current user to 'adm' group: sudo usermod -aG adm $USER",
            }
        try:
            stat = p.stat()
            mode_oct = oct(stat.st_mode)[-3:]
            return {
                "available": True,
                "file_size_bytes": stat.st_size,
                "file_permissions": mode_oct,
                "error_reason": None,
                "action_hint": None,
            }
        except Exception as exc:
            return {
                "available": False,
                "error_reason": f"Error accessing file metadata: {exc}",
                "action_hint": None,
            }

    def get_full_health(
        self, collectors: Optional[Dict[str, Collector]] = None
    ) -> TelemetryHealthReport:
        sources_health: List[SourceHealth] = []
        ingestion_states = {s["source_name"]: s for s in self.repo.get_all_ingestion_states()}

        # 1. Inspect journald
        journal_collector = (
            collectors.get("journald") if collectors else JournalCollector()
        )
        j_avail, j_reason = journal_collector.check_availability()
        j_state = ingestion_states.get("journald", {})
        sources_health.append(
            SourceHealth(
                name="journald",
                source_type="journal",
                available=j_avail,
                error_reason=j_reason,
                total_records=j_state.get("total_records_ingested", 0),
                last_collected_at=j_state.get("last_run_at"),
                action_hint="Ensure user is in 'systemd-journal' or 'adm' group." if not j_avail else None,
            )
        )

        # 2. Inspect file-based collectors
        file_specs = [
            ("auth.log", settings.collectors.auth_log_path),
            ("syslog", settings.collectors.syslog_path),
            ("kern.log", settings.collectors.kern_log_path),
        ]

        for name, path_str in file_specs:
            file_meta = self.inspect_file(path_str)
            state = ingestion_states.get(name, {})
            sources_health.append(
                SourceHealth(
                    name=name,
                    source_type="file",
                    file_path=path_str,
                    available=file_meta.get("available", False),
                    error_reason=file_meta.get("error_reason"),
                    file_size_bytes=file_meta.get("file_size_bytes"),
                    file_permissions=file_meta.get("file_permissions"),
                    action_hint=file_meta.get("action_hint"),
                    total_records=state.get("total_records_ingested", 0),
                    last_collected_at=state.get("last_run_at"),
                )
            )

        # Calculate database stats
        try:
            db_size = settings.db_path.stat().st_size if settings.db_path.exists() else 0
        except Exception:
            db_size = 0

        _, total_events = self.repo.query_events(limit=1, offset=0)
        active_sources = sum(1 for s in sources_health if s.available)
        total_sources = len(sources_health)

        if active_sources == total_sources:
            overall = "HEALTHY"
        elif active_sources > 0:
            overall = "DEGRADED"
        else:
            overall = "OFFLINE"

        return TelemetryHealthReport(
            overall_status=overall,
            sources=sources_health,
            total_events_in_db=total_events,
            database_size_bytes=db_size,
            active_sources_count=active_sources,
            total_sources_count=total_sources,
        )


health_service = HealthService()
