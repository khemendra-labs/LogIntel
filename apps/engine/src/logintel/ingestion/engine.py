"""Telemetry ingestion pipeline orchestrating collectors, parsers, and persistence."""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional
from logintel.collectors import (
    AuthLogCollector,
    Collector,
    JournalCollector,
    KernLogCollector,
    SyslogCollector,
)
from logintel.config import settings
from logintel.logging import get_logger
from logintel.models import CanonicalEvent, RawRecord
from logintel.parsers.registry import ParserRegistry, parser_registry
from logintel.storage.events_repo import EventsRepository, events_repo

logger = get_logger("ingestion.engine")


class IngestionEngine:
    """Coordinates telemetry collectors, parsing, normalization, and persistence."""

    def __init__(
        self,
        repo: Optional[EventsRepository] = None,
        registry: Optional[ParserRegistry] = None,
    ):
        self.repo = repo or events_repo
        self.registry = registry or parser_registry
        self.collectors: Dict[str, Collector] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        
        self.metrics = {
            "total_ingested": 0,
            "total_errors": 0,
            "last_cycle_timestamp": None,
        }

        self._setup_collectors()

    def _setup_collectors(self) -> None:
        """Initialize enabled collectors based on settings and persisted state."""
        import platform
        from logintel.storage.db import db
        db.initialize()

        # Populate host metadata
        self.repo.upsert_host(
            hostname=settings.host_name,
            os_name=platform.system(),
            os_version=platform.release(),
        )

        states = {s["source_name"]: s for s in self.repo.get_all_ingestion_states()}

        if settings.collectors.journald_enabled:
            j_state = states.get("journald")
            cursor = j_state.get("cursor") if j_state else None
            self.collectors["journald"] = JournalCollector(cursor=cursor)
            self.repo.upsert_source(name="journald", source_type="journal", enabled=True)

        if settings.collectors.auth_log_enabled:
            a_state = states.get("auth.log")
            offset = int(a_state.get("byte_offset", 0)) if a_state else 0
            inode = a_state.get("inode") if a_state else None
            self.collectors["auth.log"] = AuthLogCollector(
                current_offset=offset,
                current_inode=inode,
            )
            self.repo.upsert_source(name="auth.log", source_type="file", path=settings.collectors.auth_log_path, enabled=True)

        if settings.collectors.syslog_enabled:
            s_state = states.get("syslog")
            offset = int(s_state.get("byte_offset", 0)) if s_state else 0
            inode = s_state.get("inode") if s_state else None
            self.collectors["syslog"] = SyslogCollector(
                current_offset=offset,
                current_inode=inode,
            )
            self.repo.upsert_source(name="syslog", source_type="file", path=settings.collectors.syslog_path, enabled=True)

        if settings.collectors.kern_log_enabled:
            k_state = states.get("kern.log")
            offset = int(k_state.get("byte_offset", 0)) if k_state else 0
            inode = k_state.get("inode") if k_state else None
            self.collectors["kern.log"] = KernLogCollector(
                current_offset=offset,
                current_inode=inode,
            )
            self.repo.upsert_source(name="kern.log", source_type="file", path=settings.collectors.kern_log_path, enabled=True)

    def ingest_records(self, records: List[RawRecord]) -> int:
        """Process, normalize, and persist a batch of raw records."""
        if not records:
            return 0

        events: List[CanonicalEvent] = []
        for record in records:
            try:
                event, _ = self.registry.parse_record(record)
                events.append(event)
            except Exception as exc:
                self.metrics["total_errors"] += 1
                logger.error("Error parsing record from %s: %s", record.source, exc)

        inserted_count = self.repo.insert_events(events)
        self.metrics["total_ingested"] += inserted_count
        return inserted_count

    def run_cycle(self, historical: bool = False, limit_per_source: int = 500) -> int:
        """Execute one ingestion pass across all active collectors."""
        total_cycle_ingested = 0

        for name, collector in self.collectors.items():
            avail, reason = collector.check_availability()
            if not avail:
                logger.debug("Skipping collector %s: %s", name, reason)
                continue

            try:
                if historical:
                    generator = collector.collect_historical(limit=limit_per_source)
                else:
                    generator = collector.collect_new()

                batch: List[RawRecord] = []
                last_offset: Optional[str] = None
                cycle_records = 0

                for rec in generator:
                    batch.append(rec)
                    cycle_records += 1
                    if rec.source_offset:
                        last_offset = str(rec.source_offset)

                    if len(batch) >= settings.collectors.batch_size:
                        count = self.ingest_records(batch)
                        total_cycle_ingested += count
                        batch.clear()

                if batch:
                    count = self.ingest_records(batch)
                    total_cycle_ingested += count

                # Update ingestion state with cursor, offset, and inode
                tailer = getattr(collector, "tailer", None)
                self.repo.update_ingestion_state(
                    source_name=name,
                    cursor=getattr(collector, "cursor", None),
                    byte_offset=getattr(tailer, "current_offset", 0) if tailer else 0,
                    inode=getattr(tailer, "current_inode", None) if tailer else None,
                    records_delta=cycle_records,
                )

            except Exception as exc:
                self.metrics["total_errors"] += 1
                logger.error("Collector %s encountered an error during collection cycle: %s", name, exc)
                self.repo.update_ingestion_state(
                    source_name=name,
                    error_count_delta=1,
                    last_error=str(exc),
                )

        self.metrics["last_cycle_timestamp"] = time.time()
        return total_cycle_ingested

    def _loop(self) -> None:
        """Continuous background collection thread."""
        logger.info("Ingestion worker thread started.")
        # Only run historical catchup if no prior ingestion state exists (fresh startup)
        existing_states = self.repo.get_all_ingestion_states()
        has_prior_history = any(s.get("cursor") or (s.get("byte_offset", 0) > 0) for s in existing_states)

        if not has_prior_history:
            try:
                initial_count = self.run_cycle(historical=True, limit_per_source=1000)
                logger.info("Initial historical ingestion completed: %d records processed.", initial_count)
            except Exception as exc:
                logger.error("Error during initial historical ingestion: %s", exc)
        else:
            logger.info("Persisted ingestion state detected across restarts; resuming incremental ingestion.")

        while self._running:
            try:
                self.run_cycle(historical=False)
            except Exception as exc:
                logger.error("Error in ingestion cycle: %s", exc)

            # Sleep between cycles
            time.sleep(settings.collectors.poll_interval_seconds)

        logger.info("Ingestion worker thread exiting.")

    def start(self) -> None:
        """Start the live ingestion thread."""
        with self._lock:
            if not self._running:
                self._running = True
                self._thread = threading.Thread(target=self._loop, daemon=True, name="LogIntelIngestion")
                self._thread.start()
                logger.info("Telemetry ingestion engine started.")

    def stop(self) -> None:
        """Signal ingestion thread to stop and wait for join."""
        with self._lock:
            if self._running:
                self._running = False
                if self._thread:
                    self._thread.join(timeout=3.0)
                    self._thread = None
                logger.info("Telemetry ingestion engine stopped.")


ingestion_engine = IngestionEngine()
