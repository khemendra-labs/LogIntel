"""Entity-Centric Investigation Pivot Engine for LogIntel M5.6.

Computes deep entity pivots across events, alerts, detections, incidents, and cases
without duplicating authoritative event payloads into cases.db.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from logintel.ai.domain.investigation_intel import EntityPivotAnalysis
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database, db as default_db


class EntityPivotResolver:
    """Resolves multi-dimensional investigation pivots for entities."""

    def __init__(
        self,
        database: Optional[Database] = None,
        case_repository: Optional[CaseRepository] = None,
    ) -> None:
        self.db = database or default_db
        self.case_repo = case_repository or CaseRepository(forensic_db=self.db)

    def resolve_entity_pivot(
        self,
        case_id: int,
        entity_type: str,
        entity_value: str,
    ) -> EntityPivotAnalysis:
        """Resolve all related events, alerts, detections, incidents, and cases for an entity."""
        clean_val = entity_value.strip()
        etype = entity_type.upper()

        related_events: List[Dict[str, Any]] = []
        related_alerts: List[Dict[str, Any]] = []
        related_detections: List[Dict[str, Any]] = []
        related_incidents: List[int] = []
        related_cases: List[int] = []
        related_entities: List[Dict[str, Any]] = []
        temporal_activity: List[Dict[str, Any]] = []

        with self.db.connection() as conn:
            cur = conn.cursor()

            # 1. Query events matching entity based on entity type
            if etype in ("IP", "SRC_IP", "DST_IP"):
                q = "SELECT id, timestamp, source, event_type, host, username, process_name, src_ip, dst_ip, summary FROM events WHERE src_ip = ? OR dst_ip = ? ORDER BY timestamp DESC LIMIT 50"
                params = [clean_val, clean_val]
            elif etype in ("USER", "USERNAME"):
                q = "SELECT id, timestamp, source, event_type, host, username, process_name, src_ip, dst_ip, summary FROM events WHERE username = ? ORDER BY timestamp DESC LIMIT 50"
                params = [clean_val]
            elif etype in ("HOST", "HOSTNAME"):
                q = "SELECT id, timestamp, source, event_type, host, username, process_name, src_ip, dst_ip, summary FROM events WHERE host = ? ORDER BY timestamp DESC LIMIT 50"
                params = [clean_val]
            elif etype in ("PROCESS", "COMMAND"):
                q = "SELECT id, timestamp, source, event_type, host, username, process_name, src_ip, dst_ip, summary FROM events WHERE process_name LIKE ? OR raw_message LIKE ? ORDER BY timestamp DESC LIMIT 50"
                params = [f"%{clean_val}%", f"%{clean_val}%"]
            else:
                q = "SELECT id, timestamp, source, event_type, host, username, process_name, src_ip, dst_ip, summary FROM events WHERE summary LIKE ? OR raw_message LIKE ? ORDER BY timestamp DESC LIMIT 50"
                params = [f"%{clean_val}%", f"%{clean_val}%"]

            rows = cur.execute(q, params).fetchall()
            related_events = [dict(r) for r in rows]

            # 2. Query alerts matching entity (directly via host or indirectly via incident link)
            alert_rows = cur.execute(
                """
                SELECT DISTINCT a.id, a.first_seen, a.last_seen, a.title, a.severity, a.status, a.host
                FROM alerts a
                LEFT JOIN incident_alerts ia ON a.id = ia.alert_id
                LEFT JOIN incidents inc ON ia.incident_id = inc.id
                LEFT JOIN incident_entities ie ON inc.id = ie.incident_id
                WHERE a.host = ?
                   OR inc.primary_user = ?
                   OR inc.primary_host = ?
                   OR ie.display_name = ?
                   OR ie.entity_key LIKE ?
                ORDER BY a.last_seen DESC
                LIMIT 20
                """,
                (clean_val, clean_val, clean_val, clean_val, f"%{clean_val}%"),
            ).fetchall()
            related_alerts = [dict(r) for r in alert_rows]
            for al in related_alerts:
                ia_rows = cur.execute("SELECT incident_id FROM incident_alerts WHERE alert_id = ?", (al["id"],)).fetchall()
                for ia in ia_rows:
                    if ia["incident_id"] not in related_incidents:
                        related_incidents.append(ia["incident_id"])

            # 3. Query detections matching entity
            detection_rows = cur.execute(
                """
                SELECT DISTINCT d.id, d.alert_id, d.rule_id, d.timestamp, d.host, d.summary, d.evidence_count
                FROM detections d
                LEFT JOIN alerts a ON d.alert_id = a.id
                LEFT JOIN incident_alerts ia ON a.id = ia.alert_id
                LEFT JOIN incidents inc ON ia.incident_id = inc.id
                WHERE d.host = ?
                   OR inc.primary_user = ?
                   OR inc.primary_host = ?
                ORDER BY d.timestamp DESC
                LIMIT 20
                """,
                (clean_val, clean_val, clean_val),
            ).fetchall()
            related_detections = [dict(r) for r in detection_rows]

            # 4. Query incident entities
            ie_rows = cur.execute(
                """
                SELECT incident_id, entity_type, entity_key, display_name
                FROM incident_entities
                WHERE entity_key LIKE ? OR display_name = ?
                LIMIT 20
                """,
                (f"%{clean_val}%", clean_val),
            ).fetchall()
            for ie in ie_rows:
                inc_id = ie["incident_id"]
                if inc_id not in related_incidents:
                    related_incidents.append(inc_id)

            # 5. Connected entities from relationships
            rel_rows = cur.execute(
                """
                SELECT source_entity_key, target_entity_key, relationship_type, confidence
                FROM incident_relationships
                WHERE source_entity_key LIKE ? OR target_entity_key LIKE ?
                LIMIT 20
                """,
                (f"%{clean_val}%", f"%{clean_val}%"),
            ).fetchall()
            for rel in rel_rows:
                target = rel["target_entity_key"] if clean_val not in rel["target_entity_key"] else rel["source_entity_key"]
                related_entities.append({
                    "connected_entity": target,
                    "relationship": rel["relationship_type"],
                    "confidence": rel["confidence"],
                })

        # 6. Check related cases
        for inc_id in related_incidents:
            c = self.case_repo.get_case_by_incident(inc_id)
            if c and c.case_id not in related_cases:
                related_cases.append(c.case_id)

        # 7. Build temporal activity summary (counts per timestamp bucket)
        for ev in related_events[:30]:
            temporal_activity.append({
                "timestamp": ev.get("timestamp"),
                "event_id": ev.get("id"),
                "summary": ev.get("summary"),
                "source": ev.get("source"),
            })

        evidence_refs = [f"[event:{ev['id']}]" for ev in related_events[:5]] + [f"[alert:{al['id']}]" for al in related_alerts[:3]]

        return EntityPivotAnalysis(
            entity_type=etype,
            entity_value=clean_val,
            case_id=case_id,
            related_events=related_events,
            related_alerts=related_alerts,
            related_detections=related_detections,
            related_incidents=related_incidents,
            related_cases=related_cases,
            related_entities=related_entities,
            temporal_activity=temporal_activity,
            evidence_references=evidence_refs,
        )
