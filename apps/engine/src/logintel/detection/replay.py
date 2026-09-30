"""Historical replay harness for deterministic detection rule evaluation."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union

from pydantic import BaseModel, Field

from logintel.detection.engine import DetectionEngine
from logintel.detection.loader import load_default_rules
from logintel.detection.models import DetectionRule, RuleCategory
from logintel.detection.registry import RuleRegistry
from logintel.detection.results import DetectionResult
from logintel.logging import get_logger
from logintel.models.events import CanonicalEvent, Severity
from logintel.storage.db import Database, db
from logintel.storage.events_repo import EventsRepository

logger = get_logger("detection.replay")


class ReplayConfig(BaseModel):
    """Configuration options for a historical replay execution."""
    rule_ids: Optional[List[str]] = None
    category: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    host: Optional[str] = None
    dry_run: bool = True
    batch_size: int = 1000
    max_events: Optional[int] = None


class SimulatedAlert(BaseModel):
    """In-memory alert consolidated during a dry-run replay."""
    rule_id: str
    dedup_key: str
    title: str
    severity: str
    host: str
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = 1
    evidence_event_ids: List[str] = Field(default_factory=list)


class ReplayReport(BaseModel):
    """Deterministic summary report produced by historical replay."""
    start_wall_time: datetime
    end_wall_time: datetime
    duration_seconds: float
    total_events_evaluated: int
    total_detections_count: int
    detections_by_rule: Dict[str, int] = Field(default_factory=dict)
    detections_by_severity: Dict[str, int] = Field(default_factory=dict)
    simulated_alerts_count: int
    simulated_alerts: List[SimulatedAlert] = Field(default_factory=list)
    events_per_second: float = 0.0
    rules_evaluated_count: int = 0
    dry_run: bool = True


class HistoricalReplayHarness:
    """Deterministic replay harness for evaluating historical telemetry streams.
    
    Guarantees:
    - Strict chronological event ordering (`timestamp ASC, id ASC`).
    - Deterministic evaluation: identical input sequence produces identical outputs.
    - Zero database pollution in dry-run mode (isolated in-memory evaluation).
    - Batch streaming: handles large historical collections without memory exhaustion.
    - Comprehensive detection and alert consolidation reporting.
    """

    def __init__(
        self,
        registry: Optional[RuleRegistry] = None,
        database: Optional[Database] = None,
    ):
        self.db = database or db
        self.registry = registry or RuleRegistry()
        if not self.registry.list_rules():
            for rule in load_default_rules():
                self.registry.register(rule)

    def _filter_rules(self, config: ReplayConfig) -> List[DetectionRule]:
        """Determine which rules to activate for this replay run."""
        rules = self.registry.get_enabled_rules()

        if config.rule_ids:
            target_ids = set(config.rule_ids)
            rules = [r for r in rules if r.id in target_ids]

        if config.category:
            cat_upper = config.category.upper()
            rules = [r for r in rules if r.category.value == cat_upper]

        return rules

    def stream_events_from_db(self, config: ReplayConfig) -> Iterator[CanonicalEvent]:
        """Stream canonical events from SQLite strictly in event timestamp order."""
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []

        if config.start_time:
            query += " AND timestamp >= ?"
            params.append(config.start_time.isoformat())
        if config.end_time:
            query += " AND timestamp <= ?"
            params.append(config.end_time.isoformat())
        if config.host:
            query += " AND host = ?"
            params.append(config.host)

        # Enforce strict event-time sorting for sliding window evaluation
        query += " ORDER BY timestamp ASC, id ASC"

        if config.max_events:
            query += f" LIMIT {int(config.max_events)}"

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            while True:
                rows = cur.fetchmany(config.batch_size)
                if not rows:
                    break
                for row in rows:
                    yield CanonicalEvent.from_db_row(dict(row))

    def replay_events(
        self,
        events: Union[Sequence[CanonicalEvent], Iterator[CanonicalEvent]],
        config: Optional[ReplayConfig] = None,
    ) -> ReplayReport:
        """Execute deterministic replay against an event sequence or generator."""
        cfg = config or ReplayConfig()
        active_rules = self._filter_rules(cfg)

        # Build isolated registry and engine for this replay run
        isolated_registry = RuleRegistry()
        for r in active_rules:
            isolated_registry.register(r)

        engine = DetectionEngine(registry=isolated_registry)
        engine.reset()

        start_time_wall = datetime.now(timezone.utc)
        t0 = time.perf_counter()

        total_evaluated = 0
        all_detections: List[DetectionResult] = []
        detections_by_rule: Dict[str, int] = {}
        detections_by_sev: Dict[str, int] = {}

        # In-memory alert consolidation state: dedup_key -> SimulatedAlert
        simulated_alerts: Dict[str, SimulatedAlert] = {}
        rule_map = {r.id: r for r in active_rules}

        # Track last alert emission time for cooldown simulation
        alert_cooldowns: Dict[str, datetime] = {}

        # Replay event stream
        for event in events:
            total_evaluated += 1
            if cfg.max_events and total_evaluated > cfg.max_events:
                break

            det_results = engine.evaluate_event(event)
            for det in det_results:
                all_detections.append(det)
                rule = rule_map.get(det.rule_id)
                if not rule:
                    continue

                rule_id = det.rule_id
                detections_by_rule[rule_id] = detections_by_rule.get(rule_id, 0) + 1
                sev = rule.severity.value
                detections_by_sev[sev] = detections_by_sev.get(sev, 0) + 1

                # Compute deterministic deduplication key
                dedup_key = self._compute_dedup_key(det, rule)

                # Check cooldown suppression
                last_fired = alert_cooldowns.get(dedup_key)
                if last_fired is not None and rule.cooldown_seconds > 0:
                    delta = (det.timestamp - last_fired).total_seconds()
                    if delta < rule.cooldown_seconds:
                        # Cooldown active: update existing alert last_seen without creating duplicate
                        if dedup_key in simulated_alerts:
                            alt = simulated_alerts[dedup_key]
                            alt.last_seen = det.timestamp
                            alt.occurrence_count += 1
                            alt.evidence_event_ids.extend(det.evidence_event_ids)
                        continue

                # Emit or consolidate simulated alert
                alert_cooldowns[dedup_key] = det.timestamp
                if dedup_key in simulated_alerts:
                    alt = simulated_alerts[dedup_key]
                    alt.last_seen = det.timestamp
                    alt.occurrence_count += 1
                    alt.evidence_event_ids.extend(det.evidence_event_ids)
                else:
                    simulated_alerts[dedup_key] = SimulatedAlert(
                        rule_id=rule.id,
                        dedup_key=dedup_key,
                        title=rule.name,
                        severity=rule.severity.value,
                        host=det.host,
                        first_seen=det.timestamp,
                        last_seen=det.timestamp,
                        occurrence_count=1,
                        evidence_event_ids=list(det.evidence_event_ids),
                    )

        elapsed = time.perf_counter() - t0
        end_time_wall = datetime.now(timezone.utc)
        eps = total_evaluated / elapsed if elapsed > 0 else float(total_evaluated)

        return ReplayReport(
            start_wall_time=start_time_wall,
            end_wall_time=end_time_wall,
            duration_seconds=round(elapsed, 4),
            total_events_evaluated=total_evaluated,
            total_detections_count=len(all_detections),
            detections_by_rule=detections_by_rule,
            detections_by_severity=detections_by_sev,
            simulated_alerts_count=len(simulated_alerts),
            simulated_alerts=list(simulated_alerts.values()),
            events_per_second=round(eps, 2),
            rules_evaluated_count=len(active_rules),
            dry_run=cfg.dry_run,
        )

    def replay_from_database(self, config: Optional[ReplayConfig] = None) -> ReplayReport:
        """Run replay over historical events stored in the database."""
        cfg = config or ReplayConfig()
        event_stream = self.stream_events_from_db(cfg)
        return self.replay_events(event_stream, config=cfg)

    def _compute_dedup_key(self, result: DetectionResult, rule: DetectionRule) -> str:
        """Compute deterministic deduplication key."""
        if rule.group_by:
            # Group key from details or fallback
            gk = result.details.get("group_key") if result.details else None
            if gk:
                return f"{rule.id}:{gk}"
            return f"{rule.id}:{result.host}"
        
        # Atomic rule dedup key
        username = result.details.get("username") if result.details else None
        if username:
            return f"{rule.id}:{result.host}:{username}"
        return f"{rule.id}:{result.host}"
