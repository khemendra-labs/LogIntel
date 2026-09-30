"""Deterministic in-memory detection evaluation engine for LogIntel."""

import bisect
import threading
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Deque, Dict, List, Optional, Tuple

from logintel.logging import get_logger
from logintel.models import CanonicalEvent
from logintel.detection.matcher import evaluate_conditions_block, extract_field_value
from logintel.detection.models import DetectionRule, RuleType
from logintel.detection.registry import RuleRegistry
from logintel.detection.results import DetectionResult, EvidenceRole

logger = get_logger("detection.engine")

# Maximum number of event items retained in memory per (rule, group_key) window
MAX_EVENTS_PER_WINDOW = 1000


class DetectionEngine:
    """Evaluates CanonicalEvents against registered rules deterministically in memory.
    
    Guarantees:
    - Zero SQL queries during live event matching.
    - Strict event-time sliding windows (event.timestamp, not wall-clock).
    - Cross-batch out-of-order tolerance: late events within active window cutoff are
      incorporated into sorted timestamp order; late events outside cutoff are excluded.
    - Deterministic grouping keys with missing-value exclusion.
    - Bounded in-memory state with maxlen bounds per window.
    - Thread-safe window updates and evaluation.
    - Rule-level error isolation.
    """

    def __init__(self, registry: Optional[RuleRegistry] = None):
        self.registry = registry or RuleRegistry()
        # Window state: (rule_id, group_key) -> list of (timestamp, event_id) sorted by timestamp
        self._windows: Dict[Tuple[str, str], List[Tuple[datetime, str]]] = {}
        # Maximum timestamp observed per (rule_id, group_key) stream
        self._max_timestamps: Dict[Tuple[str, str], datetime] = {}
        self._lock = threading.RLock()

    def reset(self) -> None:
        """Reset all in-memory window states. Used for clean test isolation."""
        with self._lock:
            self._windows.clear()
            self._max_timestamps.clear()

    def get_window_count(self) -> int:
        """Return total active window queues in memory."""
        with self._lock:
            return len(self._windows)

    def build_group_key(self, rule: DetectionRule, event: CanonicalEvent) -> Optional[str]:
        """Generate a deterministic grouping key from event fields.
        
        Policy for missing fields:
        If any field specified in group_by evaluates to None, empty string, or empty collection,
        the event is excluded from threshold aggregation (returns None) to prevent erroneous
        global catch-all groupings.
        """
        if not rule.group_by:
            return None

        parts: List[str] = []
        for field in sorted(rule.group_by):
            val = extract_field_value(event, field)
            if val is None or val == "" or val == [] or val == {}:
                return None
            parts.append(f"{field}={str(val)}")

        return "|".join(parts)

    def evaluate_event(self, event: CanonicalEvent) -> List[DetectionResult]:
        """Evaluate a single canonical event against all enabled rules."""
        results: List[DetectionResult] = []
        enabled_rules = self.registry.get_enabled_rules()

        for rule in enabled_rules:
            try:
                if rule.rule_type == RuleType.ATOMIC:
                    result = self._evaluate_atomic_rule(rule, event)
                    if result:
                        results.append(result)
                elif rule.rule_type == RuleType.THRESHOLD:
                    result = self._evaluate_threshold_rule(rule, event)
                    if result:
                        results.append(result)
            except Exception as e:
                # Rule-level error isolation: log warning and continue without failing engine
                logger.warning(
                    "Error evaluating rule '%s' against event '%s': %s",
                    rule.id,
                    event.id,
                    e,
                    exc_info=False,
                )

        return results

    def evaluate_batch(self, events: List[CanonicalEvent]) -> List[DetectionResult]:
        """Evaluate a batch of canonical events in deterministic temporal order."""
        if not events:
            return []

        # Deterministic ordering: sort primarily by event timestamp, secondarily by event ID
        sorted_events = sorted(events, key=lambda e: (e.timestamp, e.id))
        all_results: List[DetectionResult] = []

        for event in sorted_events:
            results = self.evaluate_event(event)
            if results:
                all_results.extend(results)

        return all_results

    def _evaluate_atomic_rule(self, rule: DetectionRule, event: CanonicalEvent) -> Optional[DetectionResult]:
        """Evaluate an ATOMIC rule against an individual event."""
        if not evaluate_conditions_block(rule.conditions, event):
            return None

        # Condition satisfied: construct atomic DetectionResult
        return DetectionResult(
            rule_id=rule.id,
            timestamp=event.timestamp,
            host=event.host,
            summary=f"Rule '{rule.name}' matched on host {event.host}",
            evidence_event_ids=[event.id],
            evidence_roles={event.id: EvidenceRole.TRIGGER},
            details={
                "rule_type": RuleType.ATOMIC.value,
                "severity": rule.severity.value,
                "category": rule.category.value,
                "matched_fields": {
                    cond.field: str(extract_field_value(event, cond.field))
                    for cond in (rule.conditions.all or []) + (rule.conditions.any or [])
                },
            },
        )

    def _evaluate_threshold_rule(self, rule: DetectionRule, event: CanonicalEvent) -> Optional[DetectionResult]:
        """Evaluate a THRESHOLD rule using bounded in-memory sliding windows with cross-batch out-of-order tolerance."""
        if not evaluate_conditions_block(rule.conditions, event):
            return None

        if not rule.threshold or not rule.group_by:
            return None

        group_key = self.build_group_key(rule, event)
        if group_key is None:
            # Event does not have all required grouping fields
            return None

        window_key = (rule.id, group_key)
        window_seconds = rule.threshold.window_seconds

        with self._lock:
            # Retrieve or initialize window and stream max_timestamp
            window = self._windows.get(window_key)
            if window is None:
                window = []
                self._windows[window_key] = window

            max_ts = self._max_timestamps.get(window_key)
            if max_ts is None or event.timestamp > max_ts:
                max_ts = event.timestamp
                self._max_timestamps[window_key] = max_ts

            cutoff_time = max_ts - timedelta(seconds=window_seconds)

            # Policy: Late events arriving older than active window cutoff are excluded from threshold state
            if event.timestamp < cutoff_time:
                return None

            # Incorporate out-of-order event in exact sorted timestamp position
            bisect.insort(window, (event.timestamp, event.id))

            # Prune events older than active window cutoff
            while window and window[0][0] < cutoff_time:
                window.pop(0)

            # Hard memory bound per window
            if len(window) > MAX_EVENTS_PER_WINDOW:
                del window[:-MAX_EVENTS_PER_WINDOW]

            # Check if threshold count is reached
            if len(window) >= rule.threshold.count:
                # Capture snapshot of evidence events in window in temporal order
                evidence_ids = [ev_id for _, ev_id in window]
                evidence_roles: Dict[str, EvidenceRole] = {
                    ev_id: EvidenceRole.AGGREGATE for ev_id in evidence_ids
                }
                # Mark the current arriving event as the TRIGGER
                evidence_roles[event.id] = EvidenceRole.TRIGGER

                return DetectionResult(
                    rule_id=rule.id,
                    timestamp=event.timestamp,
                    host=event.host,
                    summary=(
                        f"Threshold rule '{rule.name}' fired for group [{group_key}] "
                        f"({len(window)} events in {rule.threshold.window_seconds}s)"
                    ),
                    evidence_event_ids=evidence_ids,
                    evidence_roles=evidence_roles,
                    details={
                        "rule_type": RuleType.THRESHOLD.value,
                        "severity": rule.severity.value,
                        "category": rule.category.value,
                        "group_key": group_key,
                        "match_count": len(window),
                        "threshold_count": rule.threshold.count,
                        "window_seconds": rule.threshold.window_seconds,
                    },
                )

        return None
