"""Deterministic Incident Correlation Engine for LogIntel."""

from __future__ import annotations

import ipaddress
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from logintel.correlation.config import CorrelationConfig
from logintel.correlation.scenarios import evaluate_escalation
from logintel.logging import get_logger
from logintel.models.events import Severity
from logintel.models.incidents import (
    ConfidenceLevel,
    EntityType,
    Incident,
    IncidentEntity,
    IncidentRelationship,
    IncidentStatus,
    RelationshipType,
)
from logintel.storage.alerts_repo import AlertsRepository, alerts_repo
from logintel.storage.db import Database, db
from logintel.storage.incidents_repo import IncidentsRepository, incidents_repo

logger = get_logger("correlation.engine")


class IncidentCorrelationEngine:
    """Evaluates operational alerts deterministically into aggregated multi-stage security incidents.
    
    Guarantees:
    - Pure local-first execution (zero external API calls or AI/LLM dependence).
    - Event-time sliding correlation windows with configurable duration.
    - Host, User, and IP entity affinity matching.
    - Cross-host lateral movement detection and multi-host campaign clustering.
    - Multi-stage attack progression classification and severity escalation.
    - Automatic attack graph entity extraction and directed relationship derivation.
    - Thread-safe and transaction-safe operations.
    """

    def __init__(
        self,
        database: Optional[Database] = None,
        incidents_repository: Optional[IncidentsRepository] = None,
        alerts_repository: Optional[AlertsRepository] = None,
        config: Optional[CorrelationConfig] = None,
    ) -> None:
        self.db = database or db
        self.incidents_repo = incidents_repository or incidents_repo
        self.alerts_repo = alerts_repository or alerts_repo
        self.config = config or CorrelationConfig()
        self._lock = threading.RLock()

    # =========================================================================
    # Primary Correlation Methods
    # =========================================================================

    def correlate_alert(self, alert_id: int) -> Optional[Incident]:
        """Correlate a single operational alert into an active incident or create a new incident."""
        with self._lock:
            # 1. Check if already correlated
            existing_inc_id = self._get_incident_id_for_alert(alert_id)
            if existing_inc_id is not None:
                return self.incidents_repo.get_incident(existing_inc_id)

            # 2. Fetch alert details and related telemetry
            alert_details = self.alerts_repo.get_alert_details(alert_id)
            if not alert_details:
                logger.warning("Alert with ID %d not found for correlation", alert_id)
                return None

            alert = alert_details["alert"]
            host = alert["host"]
            alert_sev = Severity(alert["severity"])
            alert_first_seen = self._parse_dt(alert["first_seen"])
            alert_last_seen = self._parse_dt(alert["last_seen"])

            # 3. Extract entities and event metadata from underlying evidence
            evidence_events = self._fetch_evidence_events(alert_details)
            extracted_entities, extracted_rels, primary_user, attacker_ips = self._extract_graph_components(
                host=host,
                alert_id=alert_id,
                alert_first_seen=alert_first_seen,
                evidence_events=evidence_events,
            )

            # 4. Search candidate active incidents within the correlation window
            candidates = self._find_matching_active_incidents(
                host=host,
                primary_user=primary_user,
                attacker_ips=attacker_ips,
                alert_time=alert_first_seen,
            )

            if candidates:
                # Correlate into best-matching active incident (prefer host match, then IP)
                target_incident = candidates[0]
                merged_inc = self._merge_into_incident(
                    incident=target_incident,
                    alert_id=alert_id,
                    new_entities=extracted_entities,
                    new_relationships=extracted_rels,
                    evidence_events=evidence_events,
                )

                # Bridge-merge any other candidate active incidents connected by this alert
                if len(candidates) > 1 and merged_inc and merged_inc.id:
                    did_merge = False
                    for other_inc in candidates[1:]:
                        if other_inc.id and other_inc.id != merged_inc.id:
                            try:
                                merged_inc = self.incidents_repo.merge_incidents(
                                    source_incident_id=other_inc.id,
                                    target_incident_id=merged_inc.id,
                                )
                                did_merge = True
                            except Exception as e:
                                logger.warning("Could not bridge-merge incident %d into %d: %s", other_inc.id, merged_inc.id, e)
                    if did_merge and merged_inc and merged_inc.id:
                        self._check_lateral_movement_and_escalate(merged_inc.id)
                        merged_inc = self.incidents_repo.get_incident(merged_inc.id)
                return merged_inc

            # 5. No active candidate matched: Create a new incident
            return self._create_new_incident(
                alert=alert,
                primary_user=primary_user,
                alert_first_seen=alert_first_seen,
                alert_last_seen=alert_last_seen,
                entities=extracted_entities,
                relationships=extracted_rels,
            )

    def correlate_unassigned_alerts(self) -> List[Incident]:
        """Batch-correlate all unassigned alerts into incidents chronologically."""
        with self._lock:
            with self.db.connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT a.id
                    FROM alerts a
                    LEFT JOIN incident_alerts ia ON a.id = ia.alert_id
                    WHERE ia.id IS NULL
                    ORDER BY a.first_seen ASC
                    """
                )
                unassigned_ids = [r[0] for r in cur.fetchall()]

            incidents_by_id: Dict[int, Incident] = {}
            for aid in unassigned_ids:
                inc = self.correlate_alert(aid)
                if inc and inc.id:
                    incidents_by_id[inc.id] = inc

            return list(incidents_by_id.values())

    # =========================================================================
    # Candidate Matching & Search
    # =========================================================================

    def _find_matching_active_incidents(
        self,
        host: str,
        primary_user: Optional[str],
        attacker_ips: Set[str],
        alert_time: datetime,
    ) -> List[Incident]:
        """Find active (OPEN / INVESTIGATING) incidents matching temporal and entity criteria."""
        active_incidents = self.incidents_repo.list_incidents(status=IncidentStatus.OPEN, limit=100)
        active_incidents.extend(
            self.incidents_repo.list_incidents(status=IncidentStatus.INVESTIGATING, limit=100)
        )

        matched: List[Tuple[int, Incident]] = []  # (priority_score, Incident)

        for inc in active_incidents:
            if not inc.last_seen or not inc.first_seen:
                continue

            # Check time-window proximity
            time_since_last = abs((alert_time - inc.last_seen).total_seconds())
            if time_since_last > self.config.window_seconds:
                continue

            # Check max incident duration boundary
            total_span = (alert_time - inc.first_seen).total_seconds()
            if total_span > self.config.max_incident_duration_seconds:
                continue

            score = 0

            # 1. Host match (primary host or any host entity in the incident)
            inc_hosts = {inc.primary_host.strip().lower()} if inc.primary_host else set()
            inc_host_entities = self.incidents_repo.get_incident_entities(inc.id, EntityType.HOST)
            inc_hosts.update(e.display_name.strip().lower() for e in inc_host_entities)

            host_clean = host.strip().lower()
            if host_clean in inc_hosts:
                score += 100
                if primary_user and inc.primary_user == primary_user:
                    score += 50
                matched.append((score, inc))
                continue

            # 2. Cross-host correlation via attacker IP
            if self.config.cross_host_correlation and attacker_ips:
                # Query whether candidate incident contains any of the attacker IPs
                inc_entities = self.incidents_repo.get_incident_entities(inc.id, EntityType.IP)
                inc_ip_keys = {e.display_name for e in inc_entities}
                if attacker_ips.intersection(inc_ip_keys):
                    score += 80  # High cross-host correlation affinity
                    matched.append((score, inc))
                    continue

            # 3. Cross-host correlation via target user account
            if self.config.cross_host_correlation and primary_user:
                if inc.primary_user == primary_user and primary_user != "root":
                    score += 40
                    matched.append((score, inc))
                    continue

        # Sort by match priority descending, then earliest first_seen, then lowest incident ID (stable deterministic tie-breaking)
        matched.sort(
            key=lambda t: (
                -t[0],
                t[1].first_seen or datetime.max.replace(tzinfo=timezone.utc),
                t[1].id or 0,
            )
        )
        return [t[1] for t in matched]

    # =========================================================================
    # Merging & Escalation Logic
    # =========================================================================

    def _merge_into_incident(
        self,
        incident: Incident,
        alert_id: int,
        new_entities: List[IncidentEntity],
        new_relationships: List[IncidentRelationship],
        evidence_events: List[Dict[str, Any]],
    ) -> Incident:
        """Add an alert to an existing incident, update graph, and evaluate severity escalation."""
        inc_id = incident.id
        assert inc_id is not None

        # 1. Link alert
        updated_inc = self.incidents_repo.add_alerts_to_incident(inc_id, [alert_id])

        # 2. Add entities & relationships
        if new_entities:
            # Re-assign incident_id
            for ent in new_entities:
                ent.incident_id = inc_id
            self.incidents_repo.add_entities(inc_id, new_entities)

        if new_relationships:
            for rel in new_relationships:
                rel.incident_id = inc_id
            self.incidents_repo.add_relationships(inc_id, new_relationships)

        # 3. Check for lateral movement and multi-stage progression
        self._check_lateral_movement_and_escalate(inc_id)

        return self.incidents_repo.get_incident(inc_id)  # type: ignore

    def _check_lateral_movement_and_escalate(self, inc_id: int) -> None:
        """Check for multi-host lateral movement relationships and apply severity escalation."""
        existing_hosts = {
            e.display_name
            for e in self.incidents_repo.get_incident_entities(inc_id, EntityType.HOST)
        }
        is_multi_host = len(existing_hosts) > 1

        if is_multi_host and len(existing_hosts) >= 2:
            host_list = sorted(list(existing_hosts))
            h_src = host_list[0]
            for h_dst in host_list[1:]:
                self.incidents_repo.add_relationships(
                    inc_id,
                    [
                        IncidentRelationship(
                            incident_id=inc_id,
                            source_entity_key=f"host:{h_src}",
                            target_entity_key=f"host:{h_dst}",
                            relationship_type=RelationshipType.LATERAL_MOVEMENT.value,
                            confidence=ConfidenceLevel.STRONG,
                        )
                    ],
                )

        if self.config.multi_stage_escalation:
            self._evaluate_and_apply_escalation(inc_id, is_multi_host)

    def _create_new_incident(
        self,
        alert: Dict[str, Any],
        primary_user: Optional[str],
        alert_first_seen: datetime,
        alert_last_seen: datetime,
        entities: List[IncidentEntity],
        relationships: List[IncidentRelationship],
    ) -> Incident:
        """Create a fresh incident seeded from the trigger alert."""
        host = alert["host"]
        alert_id = alert["id"]
        window_bucket = int(alert_first_seen.timestamp()) // self.config.window_seconds
        user_slug = primary_user or "system"
        inc_key = f"inc:{host}:{user_slug}:{window_bucket}:{alert_id}"

        title = f"Security Incident on {host}: {alert['title']}"
        summary = alert["description"]
        sev = Severity(alert["severity"])

        incident = Incident(
            incident_key=inc_key,
            title=title,
            summary=summary,
            severity=sev,
            status=IncidentStatus.OPEN,
            primary_host=host,
            primary_user=primary_user,
            first_seen=alert_first_seen,
            last_seen=alert_last_seen,
            alert_count=1,
            event_count=0,
        )

        created = self.incidents_repo.create_incident(
            incident=incident,
            alert_ids=[alert_id],
            entities=entities,
            relationships=relationships,
        )
        return created

    def _evaluate_and_apply_escalation(self, incident_id: int, is_multi_host: bool) -> None:
        """Re-assess incident severity and title based on multi-stage progression."""
        incident = self.incidents_repo.get_incident(incident_id)
        if not incident:
            return

        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT DISTINCT r.category
                FROM detection_rules r
                INNER JOIN alerts a ON r.id = a.rule_id
                INNER JOIN incident_alerts ia ON a.id = ia.alert_id
                WHERE ia.incident_id = ?
                """,
                (incident_id,),
            )
            categories = {r[0] for r in cur.fetchall()}

        new_sev, scenario_title = evaluate_escalation(
            current_severity=incident.severity,
            categories=categories,
            alert_count=incident.alert_count,
            is_multi_host=is_multi_host,
        )

        # Update if escalated
        needs_update = False
        new_title = incident.title
        new_summary = incident.summary

        # Check severity level comparison
        severity_order = {
            Severity.DEBUG: 0,
            Severity.INFORMATIONAL: 1,
            Severity.NOTICE: 2,
            Severity.WARNING: 3,
            Severity.ALERT: 4,
            Severity.CRITICAL: 5,
        }

        if severity_order.get(new_sev, 0) > severity_order.get(incident.severity, 0):
            incident.severity = new_sev
            needs_update = True

        if scenario_title and scenario_title not in incident.title:
            new_title = f"{scenario_title} [{incident.primary_host}]"
            new_summary = f"{incident.summary} (Correlated Multi-Stage Pattern: {scenario_title})"
            needs_update = True

        if needs_update:
            now_iso = datetime.now(timezone.utc).isoformat()
            with self.db.connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    """
                    UPDATE incidents
                    SET severity = ?, title = ?, summary = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (incident.severity.value, new_title, new_summary, now_iso, incident_id),
                )
                conn.commit()

    # =========================================================================
    # Entity & Relationship Extraction
    # =========================================================================

    def _extract_graph_components(
        self,
        host: str,
        alert_id: int,
        alert_first_seen: datetime,
        evidence_events: List[Dict[str, Any]],
    ) -> Tuple[List[IncidentEntity], List[IncidentRelationship], Optional[str], Set[str]]:
        """Extract graph nodes and directed relationships from alert telemetry with canonical entities."""
        entities: Dict[str, IncidentEntity] = {}
        relationships: List[IncidentRelationship] = []

        # 1. Base Host Entity (canonical lowercase)
        host_clean = host.strip().lower() if host else "unknown"
        host_key = f"host:{host_clean}"
        entities[host_key] = IncidentEntity(
            incident_id=0,
            entity_key=host_key,
            entity_type=EntityType.HOST,
            display_name=host_clean,
        )

        primary_user: Optional[str] = None
        attacker_ips: Set[str] = set()

        for ev in evidence_events:
            ev_id = ev.get("id")
            raw_user = ev.get("username")
            raw_src_ip = ev.get("src_ip")
            raw_proc = ev.get("process_name")
            ev_type = ev.get("event_type", "")
            ev_outcome = ev.get("outcome", "")

            # User entity (strip whitespace, exclude placeholders)
            ev_user = raw_user.strip() if raw_user and isinstance(raw_user, str) else None
            if ev_user and ev_user not in ("-", "unknown", ""):
                user_key = f"user:{ev_user}"
                if user_key not in entities:
                    entities[user_key] = IncidentEntity(
                        incident_id=0,
                        entity_key=user_key,
                        entity_type=EntityType.USER,
                        display_name=ev_user,
                    )
                if not primary_user:
                    primary_user = ev_user

                # User -> Host relationship
                rel_type = RelationshipType.AUTHENTICATED_TO.value
                confidence = (
                    ConfidenceLevel.DIRECT if ev_outcome == "SUCCESS" else ConfidenceLevel.STRONG
                )
                relationships.append(
                    IncidentRelationship(
                        incident_id=0,
                        source_entity_key=user_key,
                        target_entity_key=host_key,
                        relationship_type=rel_type,
                        confidence=confidence,
                        evidence_event_ids=[ev_id] if ev_id else [],
                    )
                )

                # Process entity (strip whitespace)
                ev_proc = raw_proc.strip() if raw_proc and isinstance(raw_proc, str) else None
                if ev_proc:
                    proc_key = f"process:{ev_proc}"
                    if proc_key not in entities:
                        entities[proc_key] = IncidentEntity(
                            incident_id=0,
                            entity_key=proc_key,
                            entity_type=EntityType.PROCESS,
                            display_name=ev_proc,
                        )
                    relationships.append(
                        IncidentRelationship(
                            incident_id=0,
                            source_entity_key=user_key,
                            target_entity_key=proc_key,
                            relationship_type=RelationshipType.EXECUTED.value,
                            confidence=ConfidenceLevel.DIRECT,
                            evidence_event_ids=[ev_id] if ev_id else [],
                        )
                    )

            # IP entity (canonical IP parsing via ipaddress)
            canonical_ip = self.canonicalize_ip(raw_src_ip)

            if canonical_ip:
                ip_key = f"ip:{canonical_ip}"
                attacker_ips.add(canonical_ip)
                if ip_key not in entities:
                    entities[ip_key] = IncidentEntity(
                        incident_id=0,
                        entity_key=ip_key,
                        entity_type=EntityType.IP,
                        display_name=canonical_ip,
                    )
                # IP -> Host connection
                relationships.append(
                    IncidentRelationship(
                        incident_id=0,
                        source_entity_key=ip_key,
                        target_entity_key=host_key,
                        relationship_type=RelationshipType.CONNECTED_TO.value,
                        confidence=ConfidenceLevel.DIRECT,
                        evidence_event_ids=[ev_id] if ev_id else [],
                    )
                )

        return list(entities.values()), relationships, primary_user, attacker_ips

    def _fetch_evidence_events(self, alert_details: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Retrieve full event rows for evidence items associated with an alert."""
        event_ids: Set[str] = set()
        for det in alert_details.get("detections", []):
            for ev in det.get("evidence", []):
                eid = ev.get("event_id")
                if eid:
                    event_ids.add(eid)

        if not event_ids:
            return []

        placeholders = ",".join("?" for _ in event_ids)
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                f"""
                SELECT id, host, username, src_ip, dst_ip, process_name, event_type, outcome, summary
                FROM events
                WHERE id IN ({placeholders})
                """,
                list(event_ids),
            )
            return [dict(row) for row in cur.fetchall()]

    def _get_incident_id_for_alert(self, alert_id: int) -> Optional[int]:
        """Check if an alert is already linked to an incident."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT incident_id FROM incident_alerts WHERE alert_id = ?",
                (alert_id,),
            )
            row = cur.fetchone()
            return row[0] if row else None

    @staticmethod
    def _parse_dt(val: Any) -> datetime:
        """Parse datetime string or return datetime instance with UTC timezone."""
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val
        if isinstance(val, str):
            dt = datetime.fromisoformat(val)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt
        return datetime.now(timezone.utc)

    @staticmethod
    def canonicalize_ip(raw_ip: Optional[str]) -> Optional[str]:
        """Normalize IPv4/IPv6 addresses to standard RFC format, handling bracketed IPv6, ports, and whitespace."""
        if not raw_ip or not isinstance(raw_ip, str):
            return None
        ip_clean = raw_ip.strip()
        if ip_clean.lower() in ("127.0.0.1", "::1", "", "-", "unknown", "localhost"):
            return None

        # Handle bracketed IPv6 with optional port: [2001:db8::1]:443 or [2001:db8::1]
        if ip_clean.startswith("[") and "]" in ip_clean:
            ip_clean = ip_clean[1:ip_clean.index("]")]
        # Handle IPv4 with port: 10.0.0.1:8080
        elif ":" in ip_clean and "." in ip_clean:
            ip_clean = ip_clean.split(":")[0]

        # Normalize IPv4 with leading zeros (e.g. 192.168.001.001 -> 192.168.1.1)
        if "." in ip_clean and ":" not in ip_clean:
            parts = ip_clean.split(".")
            if len(parts) == 4 and all(p.isdigit() and len(p) <= 3 for p in parts):
                try:
                    ip_clean = ".".join(str(int(p)) for p in parts)
                except ValueError:
                    pass

        try:
            parsed_addr = ipaddress.ip_address(ip_clean)
            if not parsed_addr.is_loopback and not parsed_addr.is_unspecified:
                return str(parsed_addr)
            return None
        except ValueError:
            return ip_clean.lower()


# Global singleton correlation engine
correlation_engine = IncidentCorrelationEngine()
