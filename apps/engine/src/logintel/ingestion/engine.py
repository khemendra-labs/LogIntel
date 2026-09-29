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
        """Initialize enabled collectors based on settings."""
        if settings.collectors.journald_enabled:
            self.collectors["journald"] = JournalCollector()
        if settings.collectors.auth_log_enabled:
            self.collectors["auth.log"] = AuthLogCollector()
        if settings.collectors.syslog_enabled:
            self.collectors["syslog"] = SyslogCollector()
        if settings.collectors.kern_log_enabled:
            self.collectors["kern.log"] = KernLogCollector()

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

                for rec in generator:
                    batch.append(rec)
                    if rec.source_offset:
                        last_offset = str(rec.source_offset)

                    if len(batch) >= settings.collectors.batch_size:
                        count = self.ingest_records(batch)
                        total_cycle_ingested += count
                        batch.clear()

                if batch:
                    count = self.ingest_records(batch)
                    total_cycle_ingested += count

                # Update ingestion state
                self.repo.update_ingestion_state(
                    source_name=name,
                    cursor=getattr(collector, "cursor", None),
                    byte_offset=getattr(getattr(collector, "tailer", None), "current_offset", 0),
                    records_delta=collector.total_records,
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
        # First perform historical catchup
        try:
            initial_count = self.run_cycle(historical=True, limit_per_source=1000)
            logger.info("Initial historical ingestion completed: %d records processed.", initial_count)
        except Exception as exc:
            logger.error("Error during initial historical ingestion: %s", exc)

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
