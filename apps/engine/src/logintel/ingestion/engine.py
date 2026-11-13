"""Telemetry ingestion pipeline orchestrating collectors, parsers, and persistence."""

from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional
from logintel.collectors import (
    AuditLogCollector,
    AuthLogCollector,
    Collector,
    JournalCollector,
    KernLogCollector,
    SyslogCollector,
)
from logintel.network import SocketStateCollector
from logintel.filesystem import FilesystemPersistenceCollector
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
        detection_engine=None,
        alerts_repository=None,
    ):
        self.repo = repo or events_repo
        self.registry = registry or parser_registry
        if detection_engine is None:
            from logintel.detection.engine import DetectionEngine
            from logintel.detection.registry import get_rule_registry
            detection_engine = DetectionEngine(registry=get_rule_registry())
        if alerts_repository is None:
            from logintel.storage.alerts_repo import AlertsRepository
            alerts_repository = AlertsRepository(self.repo.db)
        self.detection_engine = detection_engine
        self.alerts_repository = alerts_repository
        self.collectors: Dict[str, Collector] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        # Monotonic timestamps are deliberately in-memory: they only govern
        # polling cadence, while collectors' durable cursor/offset state still
        # guarantees correct resume behavior after a restart.
        self._last_live_poll: Dict[str, float] = {}
        
        self.metrics = {
            "total_ingested": 0,
            "total_detections": 0,
            "total_alerts_recorded": 0,
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

        if settings.collectors.audit_log_enabled:
            aud_state = states.get("audit.log")
            offset = int(aud_state.get("byte_offset", 0)) if aud_state else 0
            inode = aud_state.get("inode") if aud_state else None
            self.collectors["audit.log"] = AuditLogCollector(
                current_offset=offset,
                current_inode=inode,
            )
            self.repo.upsert_source(name="audit.log", source_type="file", path=settings.collectors.audit_log_path, enabled=True)

        if settings.collectors.socket_collector_enabled:
            self.collectors["sockets"] = SocketStateCollector(
                proc_net_path=settings.collectors.proc_net_path,
                proc_path=settings.collectors.proc_path,
            )
            self.repo.upsert_source(name="sockets", source_type="procfs", path="/proc/net/tcp", enabled=True)

        if settings.collectors.filesystem_collector_enabled:
            self.collectors["filesystem_hvt"] = FilesystemPersistenceCollector()
            self.repo.upsert_source(name="filesystem_hvt", source_type="filesystem", path="/etc", enabled=True)

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

        inserted_ids = set(self.repo.insert_events_with_ids(events))
        inserted_events = [event for event in events if event.id in inserted_ids]
        inserted_count = len(inserted_events)
        if inserted_events:
            try:
                detections = self.detection_engine.evaluate_batch(inserted_events)
                for detection in detections:
                    rule = self.detection_engine.registry.get(detection.rule_id)
                    if rule is None:
                        logger.warning("Skipping detection for unavailable rule %s", detection.rule_id)
                        continue
                    alert = self.alerts_repository.record_detection(detection, rule)
                    self.metrics["total_alerts_recorded"] += 1
                    from logintel.notifications import notification_service

                    # Locate the trigger/evidence event to include granular forensic telemetry
                    trigger_ev = None
                    trigger_id = detection.get_trigger_event_id()
                    for ev in inserted_events:
                        if ev.id == trigger_id or (not trigger_ev and ev.id in detection.evidence_event_ids):
                            trigger_ev = ev
                            if ev.id == trigger_id:
                                break

                    payload = {
                        "alert_id": alert.id,
                        "rule_id": rule.id,
                        "rule_name": rule.name,
                        "rule_description": rule.description,
                        "rule_category": rule.category.value if hasattr(rule.category, "value") else str(rule.category),
                        "severity": alert.severity.value,
                        "host": alert.host,
                        "status": alert.status.value,
                        "occurrence_count": alert.occurrence_count,
                        "first_seen": alert.first_seen.isoformat() if hasattr(alert.first_seen, "isoformat") else str(alert.first_seen),
                        "last_seen": alert.last_seen.isoformat() if hasattr(alert.last_seen, "isoformat") else str(alert.last_seen),
                        "summary": detection.summary or alert.description or rule.name,
                        "evidence_count": len(detection.evidence_event_ids),
                    }
                    if trigger_ev:
                        payload["trigger_event"] = {
                            "event_id": trigger_ev.id,
                            "timestamp": trigger_ev.timestamp.isoformat() if hasattr(trigger_ev.timestamp, "isoformat") else str(trigger_ev.timestamp),
                            "event_type": trigger_ev.event_type,
                            "source": trigger_ev.source,
                            "severity": trigger_ev.severity.value if hasattr(trigger_ev.severity, "value") else str(trigger_ev.severity),
                            "action": trigger_ev.action,
                            "outcome": trigger_ev.outcome.value if hasattr(trigger_ev.outcome, "value") else str(trigger_ev.outcome),
                            "summary": trigger_ev.summary,
                            "raw_message": trigger_ev.raw_message,
                            "user": trigger_ev.actor.username if trigger_ev.actor else None,
                            "uid": trigger_ev.actor.uid if trigger_ev.actor else None,
                            "terminal": trigger_ev.actor.terminal if trigger_ev.actor else None,
                            "process_name": trigger_ev.process.name if trigger_ev.process else None,
                            "process_pid": trigger_ev.process.pid if trigger_ev.process else None,
                            "process_ppid": trigger_ev.process.ppid if trigger_ev.process else None,
                            "executable": trigger_ev.process.executable if trigger_ev.process else None,
                            "command_line": trigger_ev.process.command_line if trigger_ev.process else None,
                            "src_ip": trigger_ev.network.src_ip if trigger_ev.network else None,
                            "src_port": trigger_ev.network.src_port if trigger_ev.network else None,
                            "dst_ip": trigger_ev.network.dst_ip if trigger_ev.network else None,
                            "dst_port": trigger_ev.network.dst_port if trigger_ev.network else None,
                            "protocol": trigger_ev.network.protocol if trigger_ev.network else None,
                        }

                    notification_service.publish(
                        event_type="alert.detected",
                        resource_type="alert",
                        resource_id=str(alert.id),
                        payload=payload,
                    )
                self.metrics["total_detections"] += len(detections)
            except Exception as exc:
                # Event durability takes precedence over a non-fatal matcher
                # failure so a bad rule cannot stop telemetry ingestion.
                self.metrics["total_errors"] += 1
                logger.exception("Live detection failed for %d inserted events: %s", inserted_count, exc)
        self.metrics["total_ingested"] += inserted_count
        return inserted_count

    def _poll_interval_for(self, collector_name: str) -> float:
        """Return the live collection cadence for a source.

        File tailers are cheap metadata reads and keep the one-second cadence.
        Process-table and integrity scans are intentionally slower because they
        can touch thousands of procfs entries or hash files.
        """
        if collector_name == "journald":
            return settings.collectors.journald_poll_interval_seconds
        if collector_name == "sockets":
            return settings.collectors.socket_poll_interval_seconds
        if collector_name == "filesystem_hvt":
            return settings.collectors.filesystem_poll_interval_seconds
        return settings.collectors.poll_interval_seconds

    def run_cycle(
        self,
        historical: bool = False,
        limit_per_source: int = 500,
        respect_schedule: bool = False,
    ) -> int:
        """Execute one ingestion pass across all active collectors."""
        acquired = self._lock.acquire(timeout=2.0)
        if not acquired:
            logger.info("Ingestion cycle already in progress; skipping overlapping run.")
            return 0

        try:
            total_cycle_ingested = 0

            for name, collector in self.collectors.items():
                if respect_schedule and not historical:
                    now = time.monotonic()
                    previous_poll = self._last_live_poll.get(name)
                    if previous_poll is not None and now - previous_poll < self._poll_interval_for(name):
                        continue
                    # Record the attempted poll too, so an unavailable source does
                    # not cause repeated costly availability checks every second.
                    self._last_live_poll[name] = now

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
        finally:
            self._lock.release()

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
                self.run_cycle(historical=False, respect_schedule=True)
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
