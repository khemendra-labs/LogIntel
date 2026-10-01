"""Repository and lifecycle manager for security incidents, alert aggregation, and attack graphs."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from logintel.logging import get_logger
from logintel.models.alerts import Alert
from logintel.models.events import Severity
from logintel.models.incidents import (
    ALLOWED_INCIDENT_STATUS_TRANSITIONS,
    ConfidenceLevel,
    EntityType,
    Incident,
    IncidentEntity,
    IncidentRelationship,
    IncidentStatus,
    InvalidIncidentStatusTransitionError,
    TimelineItem,
    TimelineItemType,
)
from logintel.storage.alerts_repo import AlertsRepository, alerts_repo
from logintel.storage.db import Database, db

logger = get_logger("storage.incidents_repo")


class IncidentsRepository:
    """Thread-safe and transaction-safe repository for incident correlation, attack graphs, and timelines."""

    def __init__(
        self,
        database: Optional[Database] = None,
        alerts_repository: Optional[AlertsRepository] = None,
    ) -> None:
        self.db = database or db
        self.alerts_repo = alerts_repository or alerts_repo
        self._lock = threading.RLock()
        self._merged_into: Dict[int, int] = {}

    # =========================================================================
    # Incident CRUD & Lifecycle
    # =========================================================================

    def create_incident(
        self,
        incident: Incident,
        alert_ids: Optional[List[int]] = None,
        entities: Optional[List[IncidentEntity]] = None,
        relationships: Optional[List[IncidentRelationship]] = None,
    ) -> Incident:
        """Create a new incident with optional linked alerts, entities, and relationships atomically."""
        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()
        first_seen_iso = incident.first_seen.isoformat() if incident.first_seen else now_iso
        last_seen_iso = incident.last_seen.isoformat() if incident.last_seen else now_iso

        with self._lock:
            with self.db.connection() as conn:
                old_isolation = conn.isolation_level
                conn.isolation_level = None
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    cur = conn.cursor()

                    # 1. Insert incident record
                    cur.execute(
                        """
                        INSERT INTO incidents (
                            incident_key, title, summary, severity, status,
                            primary_host, primary_user, first_seen, last_seen,
                            alert_count, event_count, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            incident.incident_key,
                            incident.title,
                            incident.summary,
                            incident.severity.value,
                            incident.status.value,
                            incident.primary_host,
                            incident.primary_user,
                            first_seen_iso,
                            last_seen_iso,
                            incident.alert_count,
                            incident.event_count,
                            now_iso,
                            now_iso,
                        ),
                    )
                    incident_id = cur.lastrowid

                    # 2. Link alerts if provided
                    if alert_ids:
                        for a_id in alert_ids:
                            cur.execute(
                                """
                                INSERT INTO incident_alerts (incident_id, alert_id, added_at)
                                VALUES (?, ?, ?)
                                ON CONFLICT(incident_id, alert_id) DO NOTHING
                                """,
                                (incident_id, a_id, now_iso),
                            )

                    # 3. Add entities if provided
                    if entities:
                        for ent in entities:
                            meta = getattr(ent, "metadata", None) or getattr(ent, "metadata_json", {})
                            meta_json = json.dumps(meta) if meta else "{}"
                            cur.execute(
                                """
                                INSERT INTO incident_entities (
                                    incident_id, entity_key, entity_type, display_name, metadata_json
                                ) VALUES (?, ?, ?, ?, ?)
                                ON CONFLICT(incident_id, entity_key) DO UPDATE SET
                                    display_name = excluded.display_name,
                                    metadata_json = excluded.metadata_json
                                """,
                                (
                                    incident_id,
                                    ent.entity_key,
                                    ent.entity_type.value,
                                    ent.display_name,
                                    meta_json,
                                ),
                            )

                    # 4. Add relationships if provided (idempotent, deduplicated, endpoint-validated)
                    if relationships:
                        for rel in relationships:
                            self._insert_or_consolidate_relationship(
                                cur, incident_id, rel, now_iso
                            )

                    # 5. Recompute aggregated counts and timestamps if alerts were linked
                    if alert_ids:
                        self._sync_incident_metrics(cur, incident_id)

                    conn.execute("COMMIT;")
                except Exception:
                    conn.execute("ROLLBACK;")
                    raise
                finally:
                    conn.isolation_level = old_isolation

            return self.get_incident(incident_id)  # type: ignore

    def get_incident(self, incident_id: int) -> Optional[Incident]:
        """Fetch an incident by its primary key ID."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, incident_key, title, summary, severity, status,
                       primary_host, primary_user, first_seen, last_seen,
                       alert_count, event_count, created_at, updated_at,
                       resolved_at, resolution_note
                FROM incidents
                WHERE id = ?
                """,
                (incident_id,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_incident(row)

    def get_incident_by_key(self, incident_key: str) -> Optional[Incident]:
        """Fetch an incident by its deterministic key."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, incident_key, title, summary, severity, status,
                       primary_host, primary_user, first_seen, last_seen,
                       alert_count, event_count, created_at, updated_at,
                       resolved_at, resolution_note
                FROM incidents
                WHERE incident_key = ?
                """,
                (incident_key,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return self._row_to_incident(row)

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[Severity] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Incident]:
        """List incidents with filtering and pagination ordered by last_seen DESC."""
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status.value)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if host:
            query += " AND primary_host = ?"
            params.append(host)
        if user:
            query += " AND primary_user = ?"
            params.append(user)

        query += " ORDER BY last_seen DESC LIMIT ? OFFSET ?"
        params.extend([max(1, limit), max(0, offset)])

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return [self._row_to_incident(row) for row in cur.fetchall()]

    def count_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        severity: Optional[Severity] = None,
        host: Optional[str] = None,
        user: Optional[str] = None,
    ) -> int:
        """Count total matching incidents."""
        query = "SELECT COUNT(*) FROM incidents WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status.value)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        if host:
            query += " AND primary_host = ?"
            params.append(host)
        if user:
            query += " AND primary_user = ?"
            params.append(user)

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return cur.fetchone()[0]

    def update_incident_status(
        self,
        incident_id: int,
        new_status: IncidentStatus,
        resolution_note: Optional[str] = None,
    ) -> Incident:
        """Perform a validated status transition on an incident."""
        with self._lock:
            with self.db.connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT status FROM incidents WHERE id = ?",
                    (incident_id,),
                )
                row = cur.fetchone()
                if not row:
                    raise ValueError(f"Incident with ID {incident_id} not found")

                current_status = IncidentStatus(row["status"])
                if current_status == new_status:
                    return self.get_incident(incident_id)  # type: ignore

                allowed = ALLOWED_INCIDENT_STATUS_TRANSITIONS.get(current_status, set())
                if new_status not in allowed:
                    raise InvalidIncidentStatusTransitionError(current_status, new_status)

                now_iso = datetime.now(timezone.utc).isoformat()
                if new_status in (
                    IncidentStatus.RESOLVED,
                    IncidentStatus.FALSE_POSITIVE,
                    IncidentStatus.CLOSED,
                ):
                    cur.execute(
                        """
                        UPDATE incidents
                        SET status = ?, resolved_at = ?, resolution_note = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (new_status.value, now_iso, resolution_note, now_iso, incident_id),
                    )
                elif new_status == IncidentStatus.OPEN:
                    # Reopening
                    cur.execute(
                        """
                        UPDATE incidents
                        SET status = ?, resolved_at = NULL, resolution_note = NULL, updated_at = ?
                        WHERE id = ?
                        """,
                        (new_status.value, now_iso, incident_id),
                    )
                else:
                    cur.execute(
                        """
                        UPDATE incidents
                        SET status = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (new_status.value, now_iso, incident_id),
                    )

                conn.commit()

            return self.get_incident(incident_id)  # type: ignore

    def delete_incident(self, incident_id: int) -> bool:
        """Delete an incident, cascading to incident_alerts, entities, and relationships."""
        with self._lock:
            with self.db.connection() as conn:
                cur = conn.cursor()
                cur.execute("DELETE FROM incidents WHERE id = ?", (incident_id,))
                conn.commit()
                return cur.rowcount > 0

    # =========================================================================
    # Alert Aggregation & Association
    # =========================================================================

    def add_alerts_to_incident(
        self,
        incident_id: int,
        alert_ids: List[int],
    ) -> Incident:
        """Link operational alerts to an incident and atomically refresh aggregated metrics."""
        if not alert_ids:
            return self.get_incident(incident_id)  # type: ignore

        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self.db.connection() as conn:
                old_isolation = conn.isolation_level
                conn.isolation_level = None
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    cur = conn.cursor()

                    # Verify incident exists
                    cur.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,))
                    if not cur.fetchone():
                        raise ValueError(f"Incident with ID {incident_id} not found")

                    for a_id in alert_ids:
                        cur.execute(
                            """
                            INSERT INTO incident_alerts (incident_id, alert_id, added_at)
                            VALUES (?, ?, ?)
                            ON CONFLICT(incident_id, alert_id) DO NOTHING
                            """,
                            (incident_id, a_id, now_iso),
                        )

                    self._sync_incident_metrics(cur, incident_id)
                    conn.execute("COMMIT;")
                except Exception:
                    conn.execute("ROLLBACK;")
                    raise
                finally:
                    conn.isolation_level = old_isolation

            return self.get_incident(incident_id)  # type: ignore

    def remove_alert_from_incident(
        self,
        incident_id: int,
        alert_id: int,
    ) -> Incident:
        """Unlink an alert from an incident and refresh aggregated metrics."""
        with self._lock:
            with self.db.connection() as conn:
                old_isolation = conn.isolation_level
                conn.isolation_level = None
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    cur = conn.cursor()

                    cur.execute(
                        "DELETE FROM incident_alerts WHERE incident_id = ? AND alert_id = ?",
                        (incident_id, alert_id),
                    )

                    self._sync_incident_metrics(cur, incident_id)
                    conn.execute("COMMIT;")
                except Exception:
                    conn.execute("ROLLBACK;")
                    raise
                finally:
                    conn.isolation_level = old_isolation

            return self.get_incident(incident_id)  # type: ignore

    def get_incident_alerts(self, incident_id: int) -> List[Alert]:
        """Fetch all operational Alert records linked to an incident, ordered by last_seen DESC."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT a.*
                FROM alerts a
                INNER JOIN incident_alerts ia ON a.id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY a.last_seen DESC
                """,
                (incident_id,),
            )
            return [AlertsRepository._row_to_alert(row) for row in cur.fetchall()]

    def get_incident_alert_ids(self, incident_id: int) -> List[int]:
        """Fetch list of alert IDs linked to an incident."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT alert_id FROM incident_alerts WHERE incident_id = ? ORDER BY added_at ASC",
                (incident_id,),
            )
            return [row[0] for row in cur.fetchall()]

    # =========================================================================
    # Attack Graph Entities & Relationships
    # =========================================================================

    def add_entities(
        self,
        incident_id: int,
        entities: List[IncidentEntity],
    ) -> List[IncidentEntity]:
        """Upsert entities associated with an incident."""
        if not entities:
            return []

        with self._lock:
            with self.db.connection() as conn:
                cur = conn.cursor()
                for ent in entities:
                    meta = getattr(ent, "metadata", None) or getattr(ent, "metadata_json", {})
                    meta_json = json.dumps(meta) if meta else "{}"
                    cur.execute(
                        """
                        INSERT INTO incident_entities (
                            incident_id, entity_key, entity_type, display_name, metadata_json
                        ) VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(incident_id, entity_key) DO UPDATE SET
                            display_name = excluded.display_name,
                            metadata_json = excluded.metadata_json
                        """,
                        (
                            incident_id,
                            ent.entity_key,
                            ent.entity_type.value,
                            ent.display_name,
                            meta_json,
                        ),
                    )
                conn.commit()

        return self.get_incident_entities(incident_id)

    def get_incident_entities(
        self,
        incident_id: int,
        entity_type: Optional[EntityType] = None,
    ) -> List[IncidentEntity]:
        """Fetch entities for an incident, optionally filtered by EntityType."""
        query = "SELECT * FROM incident_entities WHERE incident_id = ?"
        params: List[Any] = [incident_id]

        if entity_type:
            query += " AND entity_type = ?"
            params.append(entity_type.value)

        query += " ORDER BY id ASC"

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return [self._row_to_entity(row) for row in cur.fetchall()]

    def add_relationships(
        self,
        incident_id: int,
        relationships: List[IncidentRelationship],
    ) -> List[IncidentRelationship]:
        """Insert directed relationships between entities in an incident idempotently."""
        if not relationships:
            return []

        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self.db.connection() as conn:
                old_isolation = conn.isolation_level
                conn.isolation_level = None
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    cur = conn.cursor()
                    for rel in relationships:
                        self._insert_or_consolidate_relationship(
                            cur, incident_id, rel, now_iso
                        )
                    conn.execute("COMMIT;")
                except Exception:
                    conn.execute("ROLLBACK;")
                    raise
                finally:
                    conn.isolation_level = old_isolation

        return self.get_incident_relationships(incident_id)

    def merge_incidents(
        self,
        source_incident_id: int,
        target_incident_id: int,
    ) -> Incident:
        """Merge source incident into target incident atomically, preserving all evidence and entities.
        
        Guarantees:
        - Idempotent: merging an incident into itself is a no-op.
        - Atomic: executed within a single BEGIN IMMEDIATE transaction with rollback.
        - Preserves all linked alerts without duplicates.
        - Preserves all entities and metadata.
        - Preserves all relationships, consolidating evidence event IDs on duplicate edges.
        - Recomputes first_seen (minimum), last_seen (maximum), severity (highest), and event counts.
        """
        if source_incident_id == target_incident_id:
            inc = self.get_incident(target_incident_id)
            if not inc:
                raise ValueError(f"Incident {target_incident_id} not found")
            return inc

        with self._lock:
            # Idempotent check: if source was already merged into target
            if self._merged_into.get(source_incident_id) == target_incident_id:
                inc = self.get_incident(target_incident_id)
                if inc:
                    return inc

            # Idempotent check: if target was already merged into source (inverse call)
            if self._merged_into.get(target_incident_id) == source_incident_id:
                inc = self.get_incident(source_incident_id)
                if inc:
                    return inc

        now_iso = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self.db.connection() as conn:
                old_isolation = conn.isolation_level
                conn.isolation_level = None
                try:
                    conn.execute("BEGIN IMMEDIATE;")
                    cur = conn.cursor()

                    # 1. Verify both source and target exist
                    cur.execute("SELECT * FROM incidents WHERE id = ?", (source_incident_id,))
                    source_row = cur.fetchone()
                    if not source_row:
                        raise ValueError(f"Source incident {source_incident_id} does not exist")

                    cur.execute("SELECT * FROM incidents WHERE id = ?", (target_incident_id,))
                    target_row = cur.fetchone()
                    if not target_row:
                        raise ValueError(f"Target incident {target_incident_id} does not exist")

                    # 2. Reassign alerts from source to target
                    cur.execute(
                        """
                        INSERT INTO incident_alerts (incident_id, alert_id, added_at)
                        SELECT ?, alert_id, added_at
                        FROM incident_alerts
                        WHERE incident_id = ?
                        ON CONFLICT(incident_id, alert_id) DO NOTHING
                        """,
                        (target_incident_id, source_incident_id),
                    )
                    cur.execute("DELETE FROM incident_alerts WHERE incident_id = ?", (source_incident_id,))

                    # 3. Reassign entities from source to target
                    cur.execute(
                        """
                        INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json)
                        SELECT ?, entity_key, entity_type, display_name, metadata_json
                        FROM incident_entities
                        WHERE incident_id = ?
                        ON CONFLICT(incident_id, entity_key) DO UPDATE SET
                            metadata_json = excluded.metadata_json
                        """,
                        (target_incident_id, source_incident_id),
                    )
                    cur.execute("DELETE FROM incident_entities WHERE incident_id = ?", (source_incident_id,))

                    # 4. Reassign and consolidate relationships
                    cur.execute(
                        "SELECT * FROM incident_relationships WHERE incident_id = ?",
                        (source_incident_id,),
                    )
                    source_rels = cur.fetchall()
                    for s_rel in source_rels:
                        rel_obj = self._row_to_relationship(s_rel)
                        self._insert_or_consolidate_relationship(
                            cur, target_incident_id, rel_obj, now_iso
                        )
                    cur.execute("DELETE FROM incident_relationships WHERE incident_id = ?", (source_incident_id,))

                    # 5. Recompute timestamps and severity
                    s_first = source_row["first_seen"]
                    t_first = target_row["first_seen"]
                    combined_first = min(filter(None, [s_first, t_first]))

                    s_last = source_row["last_seen"]
                    t_last = target_row["last_seen"]
                    combined_last = max(filter(None, [s_last, t_last]))

                    severity_order = {
                        "CRITICAL": 5, "ALERT": 4, "WARNING": 3,
                        "NOTICE": 2, "INFORMATIONAL": 1, "DEBUG": 0,
                    }
                    s_sev = source_row["severity"]
                    t_sev = target_row["severity"]
                    combined_sev = s_sev if severity_order.get(s_sev, 0) > severity_order.get(t_sev, 0) else t_sev

                    cur.execute(
                        """
                        UPDATE incidents
                        SET first_seen = ?, last_seen = ?, severity = ?, updated_at = ?
                        WHERE id = ?
                        """,
                        (combined_first, combined_last, combined_sev, now_iso, target_incident_id),
                    )

                    # 6. Recompute aggregated counts (alert_count, event_count)
                    self._sync_incident_metrics(cur, target_incident_id)

                    # 7. Delete source incident
                    cur.execute("DELETE FROM incidents WHERE id = ?", (source_incident_id,))

                    conn.execute("COMMIT;")
                    self._merged_into[source_incident_id] = target_incident_id
                    logger.info("Successfully merged incident %d into incident %d", source_incident_id, target_incident_id)
                except Exception:
                    conn.execute("ROLLBACK;")
                    raise
                finally:
                    conn.isolation_level = old_isolation

        return self.get_incident(target_incident_id)  # type: ignore

    def get_incident_relationships(
        self,
        incident_id: int,
        relationship_type: Optional[str] = None,
    ) -> List[IncidentRelationship]:
        """Fetch relationships for an incident, optionally filtered by relationship_type."""
        query = "SELECT * FROM incident_relationships WHERE incident_id = ?"
        params: List[Any] = [incident_id]

        if relationship_type:
            query += " AND relationship_type = ?"
            params.append(relationship_type)

        query += " ORDER BY id ASC"

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return [self._row_to_relationship(row) for row in cur.fetchall()]

    def get_attack_graph(self, incident_id: int) -> Dict[str, Any]:
        """Build structured attack graph nodes and edges for visualization and traversal."""
        entities = self.get_incident_entities(incident_id)
        relationships = self.get_incident_relationships(incident_id)

        nodes = [
            {
                "id": ent.entity_key,
                "entity_type": ent.entity_type.value,
                "label": ent.display_name,
                "metadata": ent.metadata,
            }
            for ent in entities
        ]

        edges = [
            {
                "id": str(rel.id) if rel.id is not None else f"{rel.source_entity_key}->{rel.target_entity_key}",
                "source": rel.source_entity_key,
                "target": rel.target_entity_key,
                "relationship_type": rel.relationship_type,
                "confidence": rel.confidence.value,
                "evidence_event_ids": rel.evidence_event_ids,
                "matched_at": rel.matched_at.isoformat() if rel.matched_at else None,
            }
            for rel in relationships
        ]

        return {
            "incident_id": incident_id,
            "nodes": nodes,
            "edges": edges,
        }

    # =========================================================================
    # Investigation Timeline
    # =========================================================================

    def get_incident_timeline(self, incident_id: int) -> List[TimelineItem]:
        """Generate a complete, chronologically sorted investigation timeline for an incident."""
        timeline: List[TimelineItem] = []

        with self.db.connection() as conn:
            cur = conn.cursor()

            # 1. Linked Alerts
            cur.execute(
                """
                SELECT a.id, a.title, a.description, a.severity, a.first_seen, a.host, a.occurrence_count
                FROM alerts a
                INNER JOIN incident_alerts ia ON a.id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY a.first_seen ASC
                """,
                (incident_id,),
            )
            for r in cur.fetchall():
                alert_dt = self._parse_dt(r["first_seen"])
                if alert_dt:
                    timeline.append(
                        TimelineItem(
                            id=f"alert-{r['id']}",
                            timestamp=alert_dt,
                            item_type=TimelineItemType.ALERT,
                            title=f"Alert: {r['title']}",
                            summary=r["description"],
                            severity=Severity(r["severity"]),
                            ref_id=str(r["id"]),
                            details={"occurrence_count": r["occurrence_count"], "host": r["host"]},
                        )
                    )

            # 2. Underlying Evidence Events from Detections linked to Alerts
            cur.execute(
                """
                SELECT DISTINCT e.id, e.timestamp, e.host, e.username, e.event_type,
                                e.severity, e.outcome, e.summary, e.source, e.process_name, e.src_ip
                FROM events e
                INNER JOIN detection_evidence de ON e.id = de.event_id
                INNER JOIN detections d ON de.detection_id = d.id
                INNER JOIN incident_alerts ia ON d.alert_id = ia.alert_id
                WHERE ia.incident_id = ?
                ORDER BY e.timestamp ASC
                """,
                (incident_id,),
            )
            for r in cur.fetchall():
                ev_dt = self._parse_dt(r["timestamp"])
                if ev_dt:
                    timeline.append(
                        TimelineItem(
                            id=f"event-{r['id']}",
                            timestamp=ev_dt,
                            item_type=TimelineItemType.EVENT,
                            title=f"{r['event_type']} ({r['outcome']})",
                            summary=r["summary"],
                            severity=Severity(r["severity"]),
                            ref_id=r["id"],
                            details={
                                "host": r["host"],
                                "user": r["username"],
                                "source": r["source"],
                                "process_name": r["process_name"],
                                "src_ip": r["src_ip"],
                            },
                        )
                    )

            # 3. Discovered Relationships as Milestones
            cur.execute(
                """
                SELECT id, source_entity_key, target_entity_key, relationship_type, confidence, matched_at
                FROM incident_relationships
                WHERE incident_id = ?
                ORDER BY matched_at ASC
                """,
                (incident_id,),
            )
            for r in cur.fetchall():
                rel_dt = self._parse_dt(r["matched_at"])
                if rel_dt:
                    timeline.append(
                        TimelineItem(
                            id=f"rel-{r['id']}",
                            timestamp=rel_dt,
                            item_type=TimelineItemType.MILESTONE,
                            title=f"Discovered: {r['source_entity_key']} -> {r['target_entity_key']}",
                            summary=f"{r['relationship_type']} (Confidence: {r['confidence']})",
                            severity=Severity.INFORMATIONAL,
                            ref_id=str(r["id"]),
                            details={
                                "source": r["source_entity_key"],
                                "target": r["target_entity_key"],
                                "type": r["relationship_type"],
                                "confidence": r["confidence"],
                            },
                        )
                    )

        # Sort chronologically using deterministic sort_key
        timeline.sort(key=lambda item: item.sort_key())
        return timeline

    # =========================================================================
    # Full Incident Details (Investigation Workspace)
    # =========================================================================

    def get_incident_details(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """Fetch complete incident details including linked alerts, attack graph, and timeline."""
        incident = self.get_incident(incident_id)
        if not incident:
            return None

        alerts = self.get_incident_alerts(incident_id)
        graph = self.get_attack_graph(incident_id)
        timeline = self.get_incident_timeline(incident_id)

        return {
            "incident": incident.model_dump(),
            "alerts": [a.model_dump() for a in alerts],
            "graph": graph,
            "timeline": [t.model_dump() for t in timeline],
        }

    # =========================================================================
    # Helper & Serialization Methods
    # =========================================================================

    def _sync_incident_metrics(self, cur: sqlite3.Cursor, incident_id: int) -> None:
        """Internal helper to recompute alert_count, event_count, first_seen, last_seen from alerts."""
        cur.execute(
            """
            SELECT COUNT(a.id), MIN(a.first_seen), MAX(a.last_seen)
            FROM alerts a
            INNER JOIN incident_alerts ia ON a.id = ia.alert_id
            WHERE ia.incident_id = ?
            """,
            (incident_id,),
        )
        agg_row = cur.fetchone()
        count = agg_row[0] or 0
        min_first = agg_row[1]
        max_last = agg_row[2]

        # Calculate distinct evidence event count
        cur.execute(
            """
            SELECT COUNT(DISTINCT de.event_id)
            FROM detection_evidence de
            INNER JOIN detections d ON de.detection_id = d.id
            INNER JOIN incident_alerts ia ON d.alert_id = ia.alert_id
            WHERE ia.incident_id = ?
            """,
            (incident_id,),
        )
        event_count = cur.fetchone()[0] or 0

        now_iso = datetime.now(timezone.utc).isoformat()
        if count > 0 and min_first and max_last:
            cur.execute(
                """
                UPDATE incidents
                SET alert_count = ?, event_count = ?, first_seen = ?, last_seen = ?, updated_at = ?
                WHERE id = ?
                """,
                (count, event_count, min_first, max_last, now_iso, incident_id),
            )
        else:
            cur.execute(
                """
                UPDATE incidents
                SET alert_count = ?, event_count = ?, updated_at = ?
                WHERE id = ?
                """,
                (count, event_count, now_iso, incident_id),
            )

    @staticmethod
    def _parse_dt(val: Optional[str]) -> Optional[datetime]:
        """Convert ISO timestamp string to timezone-aware UTC datetime."""
        if not val:
            return None
        dt = datetime.fromisoformat(val)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt

    @classmethod
    def _row_to_incident(cls, row: sqlite3.Row) -> Incident:
        """Convert a SQLite row into an Incident domain model."""
        return Incident(
            id=row["id"],
            incident_key=row["incident_key"],
            title=row["title"],
            summary=row["summary"],
            severity=Severity(row["severity"]),
            status=IncidentStatus(row["status"]),
            primary_host=row["primary_host"],
            primary_user=row["primary_user"],
            first_seen=cls._parse_dt(row["first_seen"]),  # type: ignore
            last_seen=cls._parse_dt(row["last_seen"]),    # type: ignore
            alert_count=row["alert_count"],
            event_count=row["event_count"],
            created_at=cls._parse_dt(row["created_at"]),  # type: ignore
            updated_at=cls._parse_dt(row["updated_at"]),  # type: ignore
            resolved_at=cls._parse_dt(row["resolved_at"]),
            resolution_note=row["resolution_note"],
        )

    @classmethod
    def _row_to_entity(cls, row: sqlite3.Row) -> IncidentEntity:
        """Convert a SQLite row into an IncidentEntity domain model."""
        meta_dict: Dict[str, Any] = {}
        if row["metadata_json"]:
            try:
                meta_dict = json.loads(row["metadata_json"])
            except Exception:
                pass

        return IncidentEntity(
            id=row["id"],
            incident_id=row["incident_id"],
            entity_key=row["entity_key"],
            entity_type=EntityType(row["entity_type"]),
            display_name=row["display_name"],
            metadata=meta_dict,
        )

    @classmethod
    def _row_to_relationship(cls, row: sqlite3.Row) -> IncidentRelationship:
        """Convert a SQLite row into an IncidentRelationship domain model."""
        ev_list: List[str] = []
        if row["evidence_event_ids_json"]:
            try:
                ev_list = json.loads(row["evidence_event_ids_json"])
            except Exception:
                pass

        return IncidentRelationship(
            id=row["id"],
            incident_id=row["incident_id"],
            source_entity_key=row["source_entity_key"],
            target_entity_key=row["target_entity_key"],
            relationship_type=row["relationship_type"],
            confidence=ConfidenceLevel(row["confidence"]),
            evidence_event_ids=ev_list,
            matched_at=cls._parse_dt(row["matched_at"]),  # type: ignore
        )

    @staticmethod
    def _ensure_entity_exists(cur: sqlite3.Cursor, incident_id: int, entity_key: str) -> None:
        """Ensure an endpoint referenced by a relationship exists in incident_entities."""
        cur.execute(
            "SELECT 1 FROM incident_entities WHERE incident_id = ? AND entity_key = ?",
            (incident_id, entity_key),
        )
        if not cur.fetchone():
            etype = "HOST"
            dname = entity_key
            if entity_key.startswith("user:"):
                etype = "USER"
                dname = entity_key[5:]
            elif entity_key.startswith("host:"):
                etype = "HOST"
                dname = entity_key[5:]
            elif entity_key.startswith("ip:"):
                etype = "IP"
                dname = entity_key[3:]
            elif entity_key.startswith("process:"):
                etype = "PROCESS"
                dname = entity_key[8:]
            elif entity_key.startswith("file:"):
                etype = "FILE"
                dname = entity_key[5:]
            elif entity_key.startswith("command:"):
                etype = "COMMAND"
                dname = entity_key[8:]
            elif entity_key.startswith("session:"):
                etype = "SESSION"
                dname = entity_key[8:]

            cur.execute(
                """
                INSERT INTO incident_entities (
                    incident_id, entity_key, entity_type, display_name, metadata_json
                ) VALUES (?, ?, ?, ?, '{}')
                ON CONFLICT(incident_id, entity_key) DO NOTHING
                """,
                (incident_id, entity_key, etype, dname),
            )

    @classmethod
    def _insert_or_consolidate_relationship(
        cls, cur: sqlite3.Cursor, incident_id: int, rel: IncidentRelationship, now_iso: str
    ) -> None:
        """Insert a relationship idempotently, consolidating evidence IDs and confidence."""
        # 1. Ensure endpoints exist in incident_entities to prevent dangling references
        cls._ensure_entity_exists(cur, incident_id, rel.source_entity_key)
        cls._ensure_entity_exists(cur, incident_id, rel.target_entity_key)

        ev_ids = (
            getattr(rel, "evidence_event_ids", None)
            or getattr(rel, "evidence_event_ids_json", [])
        )
        ev_set = set(ev_ids) if ev_ids else set()
        rel_matched_iso = rel.matched_at.isoformat() if rel.matched_at else now_iso
        rel_type = (
            rel.relationship_type.value
            if hasattr(rel.relationship_type, "value")
            else str(rel.relationship_type)
        )
        conf_val = (
            rel.confidence.value
            if hasattr(rel.confidence, "value")
            else str(rel.confidence)
        )

        cur.execute(
            """
            SELECT id, confidence, evidence_event_ids_json, matched_at
            FROM incident_relationships
            WHERE incident_id = ? AND source_entity_key = ? AND target_entity_key = ? AND relationship_type = ?
            """,
            (incident_id, rel.source_entity_key, rel.target_entity_key, rel_type),
        )
        existing = cur.fetchone()
        if existing:
            # Consolidate evidence event IDs
            try:
                prior_ev = json.loads(existing["evidence_event_ids_json"] or "[]")
                if isinstance(prior_ev, list):
                    ev_set.update(prior_ev)
            except Exception:
                pass

            conf_hierarchy = {"DIRECT": 5, "STRONG": 4, "CORRELATED": 3, "INFERRED": 2, "WEAK": 1}
            prior_conf = existing["confidence"]
            new_conf = (
                conf_val
                if conf_hierarchy.get(conf_val, 1) > conf_hierarchy.get(prior_conf, 1)
                else prior_conf
            )
            earliest_matched = min(filter(None, [existing["matched_at"], rel_matched_iso]))

            cur.execute(
                """
                UPDATE incident_relationships
                SET confidence = ?, evidence_event_ids_json = ?, matched_at = ?
                WHERE id = ?
                """,
                (new_conf, json.dumps(sorted(list(ev_set))), earliest_matched, existing["id"]),
            )
        else:
            cur.execute(
                """
                INSERT INTO incident_relationships (
                    incident_id, source_entity_key, target_entity_key,
                    relationship_type, confidence, evidence_event_ids_json, matched_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id, source_entity_key, target_entity_key, relationship_type) DO UPDATE SET
                    confidence = excluded.confidence,
                    evidence_event_ids_json = excluded.evidence_event_ids_json
                """,
                (
                    incident_id,
                    rel.source_entity_key,
                    rel.target_entity_key,
                    rel_type,
                    conf_val,
                    json.dumps(sorted(list(ev_set))),
                    rel_matched_iso,
                ),
            )


# Global singleton incidents repository
incidents_repo = IncidentsRepository()

