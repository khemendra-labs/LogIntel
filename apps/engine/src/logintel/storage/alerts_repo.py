"""Repository and lifecycle manager for security alerts, detections, and evidence."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from logintel.detection.models import DetectionRule
from logintel.detection.results import DetectionResult, EvidenceRole
from logintel.logging import get_logger
from logintel.models.alerts import (
    ALLOWED_STATUS_TRANSITIONS,
    Alert,
    AlertStatus,
    DetectionEvidenceRecord,
    DetectionRecord,
    InvalidStatusTransitionError,
)
from logintel.models.events import Severity
from logintel.storage.db import Database, db

logger = get_logger("storage.alerts_repo")


class AlertsRepository:
    """Thread-safe and transaction-safe repository for alert lifecycle, deduplication, and evidence."""

    def __init__(self, database: Optional[Database] = None) -> None:
        self.db = database or db
        self._lock = threading.RLock()

    def sync_rules(self, rules: Iterable[DetectionRule]) -> int:
        """Upsert detection rules into the detection_rules catalog table.
        
        Guarantees that foreign key references from alerts and detections succeed.
        """
        rules_list = list(rules)
        if not rules_list:
            return 0

        with self.db.connection() as conn:
            cur = conn.cursor()
            for rule in rules_list:
                yaml_str = rule.to_yaml() if hasattr(rule, "to_yaml") else ""
                cur.execute(
                    """
                    INSERT INTO detection_rules (
                        id, name, description, severity, category, rule_type, definition_yaml, enabled, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', 'utc'))
                    ON CONFLICT(id) DO UPDATE SET
                        name = excluded.name,
                        description = excluded.description,
                        severity = excluded.severity,
                        category = excluded.category,
                        rule_type = excluded.rule_type,
                        definition_yaml = excluded.definition_yaml,
                        enabled = excluded.enabled,
                        updated_at = datetime('now', 'utc')
                    """,
                    (
                        rule.id,
                        rule.name,
                        rule.description,
                        rule.severity.value,
                        rule.category.value,
                        rule.rule_type.value,
                        yaml_str,
                        1 if rule.enabled else 0,
                    ),
                )
            conn.commit()
            return len(rules_list)

    def compute_dedup_key(self, result: DetectionResult, rule: DetectionRule) -> str:
        """Deterministically calculate a unique deduplication key for an alert.
        
        - For threshold rules: incorporates rule ID and group_by key.
        - For atomic rules: incorporates rule ID and target host (or target user if available).
        """
        group_key = result.details.get("group_key")
        if group_key:
            return f"{rule.id}:{group_key}"

        # Atomic rule deduplication
        matched_fields = result.details.get("matched_fields", {})
        target_user = matched_fields.get("username") or matched_fields.get("user")
        if target_user:
            return f"{rule.id}:{result.host}:{target_user}"
        return f"{rule.id}:{result.host}"

    def record_detection(self, result: DetectionResult, rule: DetectionRule) -> Alert:
        """Atomically record a DetectionResult, performing deduplication and cooldown logic.
        
        - If an active alert exists within cooldown, aggregates into the existing alert.
        - If previous alert was resolved/dismissed, archives its key and creates a fresh alert.
        - Persists detection instance and links evidence items into detection_evidence.
        """
        dedup_key = self.compute_dedup_key(result, rule)
        cooldown_sec = rule.cooldown_seconds or 3600
        now_utc = datetime.now(timezone.utc)
        result_ts_str = result.timestamp.isoformat()

        with self._lock:
            with self.db.connection() as conn:
                old_isolation = conn.isolation_level
                conn.isolation_level = None
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    cur = conn.cursor()

                    # Check for existing alert with this dedup_key
                    cur.execute(
                        """
                        SELECT id, rule_id, dedup_key, title, description, severity, status,
                               host, first_seen, last_seen, occurrence_count, acknowledged_at,
                               resolved_at, resolution_note
                        FROM alerts
                        WHERE dedup_key = ?
                        """,
                        (dedup_key,),
                    )
                    row = cur.fetchone()

                    alert_id: int
                    if row:
                        old_id = row["id"]
                        old_status = AlertStatus(row["status"])
                        last_seen_dt = datetime.fromisoformat(row["last_seen"])
                        if last_seen_dt.tzinfo is None:
                            last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)

                        elapsed = (result.timestamp - last_seen_dt).total_seconds()

                        # Case A: Alert was resolved or dismissed -> Archive old key and create new alert
                        if old_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
                            archived_key = f"{dedup_key}:archived:{old_id}"
                            cur.execute(
                                "UPDATE alerts SET dedup_key = ? WHERE id = ?",
                                (archived_key, old_id),
                            )
                            # Create new alert
                            cur.execute(
                                """
                                INSERT INTO alerts (
                                    rule_id, dedup_key, title, description, severity,
                                    status, host, first_seen, last_seen, occurrence_count
                                ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, 1)
                                """,
                                (
                                    rule.id,
                                    dedup_key,
                                    rule.name,
                                    rule.description,
                                    rule.severity.value,
                                    result.host,
                                    result_ts_str,
                                    result_ts_str,
                                ),
                            )
                            alert_id = cur.lastrowid
                        else:
                            # Case B: Alert is OPEN or ACKNOWLEDGED -> Deduplicate and update
                            alert_id = old_id
                            new_last_seen = max(last_seen_dt, result.timestamp).isoformat()
                            cur.execute(
                                """
                                UPDATE alerts
                                SET last_seen = ?, occurrence_count = occurrence_count + 1
                                WHERE id = ?
                                """,
                                (new_last_seen, alert_id),
                            )
                    else:
                        # Case C: First occurrence of this alert
                        cur.execute(
                            """
                            INSERT INTO alerts (
                                rule_id, dedup_key, title, description, severity,
                                status, host, first_seen, last_seen, occurrence_count
                            ) VALUES (?, ?, ?, ?, ?, 'OPEN', ?, ?, ?, 1)
                            """,
                            (
                                rule.id,
                                dedup_key,
                                rule.name,
                                rule.description,
                                rule.severity.value,
                                result.host,
                                result_ts_str,
                                result_ts_str,
                            ),
                        )
                        alert_id = cur.lastrowid

                    # Insert detection instance
                    details_json = json.dumps(result.details)
                    evidence_count = len(result.evidence_event_ids)
                    cur.execute(
                        """
                        INSERT INTO detections (
                            alert_id, rule_id, timestamp, host, summary, evidence_count, details_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            alert_id,
                            rule.id,
                            result_ts_str,
                            result.host,
                            result.summary,
                            evidence_count,
                            details_json,
                        ),
                    )
                    detection_id = cur.lastrowid

                    # Insert evidence links
                    matched_at_str = now_utc.isoformat()
                    for ev_id in result.evidence_event_ids:
                        role_enum = result.evidence_roles.get(ev_id, EvidenceRole.TRIGGER)
                        role_str = role_enum.value if hasattr(role_enum, "value") else str(role_enum)
                        cur.execute(
                            """
                            INSERT INTO detection_evidence (
                                detection_id, event_id, role, matched_at
                            ) VALUES (?, ?, ?, ?)
                            """,
                            (detection_id, ev_id, role_str, matched_at_str),
                        )

                    conn.execute("COMMIT;")
                except Exception:
                    conn.execute("ROLLBACK;")
                    raise
                finally:
                    conn.isolation_level = old_isolation

            return self.get_alert(alert_id)  # type: ignore

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Fetch an alert by its ID."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, rule_id, dedup_key, title, description, severity, status,
                       host, first_seen, last_seen, occurrence_count, acknowledged_at,
                       resolved_at, resolution_note
                FROM alerts
                WHERE id = ?
                """,
                (alert_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_alert(row)

    def get_alert_details(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Fetch complete alert details, including linked detections and evidence items."""
        alert = self.get_alert(alert_id)
        if not alert:
            return None

        with self.db.connection() as conn:
            cur = conn.cursor()
            # Fetch detections
            cur.execute(
                """
                SELECT id, alert_id, rule_id, timestamp, host, summary, evidence_count, details_json
                FROM detections
                WHERE alert_id = ?
                ORDER BY timestamp DESC
                """,
                (alert_id,),
            )
            det_rows = cur.fetchall()

            detections: List[Dict[str, Any]] = []
            for d in det_rows:
                det_id = d["id"]
                # Fetch evidence for detection
                cur.execute(
                    """
                    SELECT de.id, de.detection_id, de.event_id, de.role, de.matched_at,
                           e.summary AS event_summary, e.event_type, e.source
                    FROM detection_evidence de
                    LEFT JOIN events e ON de.event_id = e.id
                    WHERE de.detection_id = ?
                    ORDER BY de.id ASC
                    """,
                    (det_id,),
                )
                ev_rows = cur.fetchall()
                evidence_list = [
                    {
                        "id": er["id"],
                        "detection_id": er["detection_id"],
                        "event_id": er["event_id"],
                        "role": er["role"],
                        "matched_at": er["matched_at"],
                        "event_summary": er["event_summary"],
                        "event_type": er["event_type"],
                        "source": er["source"],
                    }
                    for er in ev_rows
                ]

                details_dict = {}
                try:
                    details_dict = json.loads(d["details_json"])
                except Exception:
                    pass

                detections.append(
                    {
                        "id": det_id,
                        "alert_id": d["alert_id"],
                        "rule_id": d["rule_id"],
                        "timestamp": d["timestamp"],
                        "host": d["host"],
                        "summary": d["summary"],
                        "evidence_count": d["evidence_count"],
                        "details": details_dict,
                        "evidence": evidence_list,
                    }
                )

            return {
                "alert": alert.model_dump(),
                "detections": detections,
            }

    def list_alerts(
        self,
        status: Optional[AlertStatus] = None,
        severity: Optional[Severity] = None,
        host: Optional[str] = None,
        rule_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Alert]:
        """Query alerts with filtering and pagination, ordered by last_seen DESC."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status.value)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if host:
            query += " AND host = ?"
            params.append(host)
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)

        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([max(1, limit), max(0, offset)])

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return [self._row_to_alert(row) for row in cur.fetchall()]

    def count_alerts(
        self,
        status: Optional[AlertStatus] = None,
        severity: Optional[Severity] = None,
        host: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> int:
        """Count total matching alerts."""
        query = "SELECT COUNT(*) FROM alerts WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status.value)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if host:
            query += " AND host = ?"
            params.append(host)
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return cur.fetchone()[0]

    def update_alert_status(
        self,
        alert_id: int,
        new_status: AlertStatus,
        resolution_note: Optional[str] = None,
    ) -> Alert:
        """Perform a validated status transition on an alert."""
        with self._lock:
            with self.db.connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT status FROM alerts WHERE id = ?",
                    (alert_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"Alert with ID {alert_id} not found")

                current_status = AlertStatus(row["status"])
                if current_status == new_status:
                    return self.get_alert(alert_id)  # type: ignore

                allowed = ALLOWED_STATUS_TRANSITIONS.get(current_status, set())
                if new_status not in allowed:
                    raise InvalidStatusTransitionError(current_status, new_status)

                now_iso = datetime.now(timezone.utc).isoformat()
                if new_status == AlertStatus.ACKNOWLEDGED:
                    cur.execute(
                        """
                        UPDATE alerts
                        SET status = ?, acknowledged_at = ?
                        WHERE id = ?
                        """,
                        (new_status.value, now_iso, alert_id),
                    )
                elif new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
                    cur.execute(
                        """
                        UPDATE alerts
                        SET status = ?, resolved_at = ?, resolution_note = ?
                        WHERE id = ?
                        """,
                        (new_status.value, now_iso, resolution_note, alert_id),
                    )
                elif new_status == AlertStatus.OPEN:
                    # Reopening
                    cur.execute(
                        """
                        UPDATE alerts
                        SET status = ?, resolved_at = NULL, resolution_note = NULL
                        WHERE id = ?
                        """,
                        (new_status.value, alert_id),
                    )

                conn.commit()

            return self.get_alert(alert_id)  # type: ignore

    @staticmethod
    def _row_to_alert(row: sqlite3.Row) -> Alert:
        """Convert a SQLite row into an Alert domain model."""
        def parse_dt(val: Optional[str]) -> Optional[datetime]:
            if not val:
                return None
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt

        return Alert(
            id=row["id"],
            rule_id=row["rule_id"],
            dedup_key=row["dedup_key"],
            title=row["title"],
            description=row["description"],
            severity=Severity(row["severity"]),
            status=AlertStatus(row["status"]),
            host=row["host"],
            first_seen=parse_dt(row["first_seen"]),  # type: ignore
            last_seen=parse_dt(row["last_seen"]),    # type: ignore
            occurrence_count=row["occurrence_count"],
            acknowledged_at=parse_dt(row["acknowledged_at"]),
            resolved_at=parse_dt(row["resolved_at"]),
            resolution_note=row["resolution_note"],
        )


# Global singleton alerts repository
alerts_repo = AlertsRepository()
