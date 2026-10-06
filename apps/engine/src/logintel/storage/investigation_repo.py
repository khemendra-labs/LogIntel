"""Investigation Repository for LogIntel Milestone 4.

Provides evidence-centric investigation queries, entity pivots, attack-path reconstruction,
MITRE ATT&CK mapping, threat hunting, analyst notes management, and investigation exports.
"""

from __future__ import annotations

import csv
import io
import json
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from logintel.logging import get_logger
from logintel.models.events import Severity
from logintel.models.incidents import ConfidenceLevel, EntityType, RelationshipType
from logintel.models.investigation import (
    AttackPathNode,
    AttackPathReconstruction,
    AttackPathStep,
    AttackPathStepNature,
    CreateNoteRequest,
    EntityPivotSummary,
    EventForensics,
    InvestigationNote,
    InvestigationNoteAudit,
    MitreMapping,
    NoteTargetType,
    ThreatHuntFilter,
    ThreatHuntResponse,
)
from logintel.storage.alerts_repo import AlertsRepository, alerts_repo
from logintel.storage.db import Database, db
from logintel.storage.incidents_repo import IncidentsRepository, incidents_repo

logger = get_logger("storage.investigation")

# Canonical deterministic rule to MITRE ATT&CK technique mapping
RULE_TO_MITRE: Dict[str, Tuple[str, str, str]] = {
    "auth.ssh_bruteforce": ("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    "auth.password_spray": ("T1110.003", "Brute Force: Password Spraying", "Credential Access"),
    "auth.invalid_user": ("T1110", "Brute Force", "Credential Access"),
    "auth.root_login": ("T1078.003", "Valid Accounts: Local Accounts", "Initial Access"),
    "auth.repeated_failures": ("T1110.001", "Brute Force: Password Guessing", "Credential Access"),
    "priv.unauthorized_sudo": ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "priv.sudo_failure": ("T1548.003", "Abuse Elevation Control Mechanism: Sudo", "Privilege Escalation"),
    "priv.sudo_root_shell": ("T1548.003", "Abuse Elevation Control Mechanism: Sudo and Sudo Caching", "Privilege Escalation"),
    "account.account_root_creation": ("T1136.001", "Create Account: Local Account", "Persistence"),
    "account.account_deletion_burst": ("T1531", "Account Access Removal", "Impact"),
    "proc.reconnaissance_tools": ("T1082", "System Information Discovery", "Discovery"),
    "proc.apparmor_denial": ("T1562.001", "Impair Defenses: Disable or Modify Tools", "Defense Evasion"),
    "proc.segfault_burst": ("T1499", "Endpoint Denial of Service", "Impact"),
    "net.sensitive_port_probe": ("T1046", "Network Service Discovery", "Discovery"),
    "net.firewall_scan_burst": ("T1046", "Network Service Discovery", "Discovery"),
    "net.threat_feed_ioc_match": ("T1071", "Application Layer Protocol", "Command and Control"),
}


class InvestigationRepository:
    """Repository handling analyst notes, entity pivots, attack-path synthesis, and threat hunting."""

    def __init__(
        self,
        database: Optional[Database] = None,
        incidents_repository: Optional[IncidentsRepository] = None,
        alerts_repository: Optional[AlertsRepository] = None,
    ) -> None:
        self.db = database or db
        self.incidents_repo = incidents_repository or IncidentsRepository(self.db)
        self.alerts_repo = alerts_repository or AlertsRepository(self.db)
        self._lock = threading.RLock()

    # =========================================================================
    # 1. Analyst Notes & Annotations
    # =========================================================================

    def add_note(
        self,
        incident_id: int,
        author: Union[str, CreateNoteRequest],
        content: Optional[str] = None,
        target_type: NoteTargetType = NoteTargetType.INCIDENT,
        target_id: Optional[str] = None,
    ) -> InvestigationNote:
        """Add an analyst note to an investigation audit trail."""
        if isinstance(author, CreateNoteRequest):
            req = author
            author_str = req.author
            content_str = req.content
            target_type = req.target_type
            target_id = req.target_id
        else:
            author_str = author
            content_str = content or ""

        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()
        ttype_val = target_type.value if hasattr(target_type, "value") else str(target_type)

        with self._lock:
            with self.db.connection() as conn:
                cur = conn.cursor()
                # Verify incident exists
                cur.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,))
                if not cur.fetchone():
                    raise ValueError(f"Incident {incident_id} not found")

                cur.execute(
                    """
                    INSERT INTO investigation_notes (
                        incident_id, author, content, created_at, target_type, target_id, is_deleted
                    ) VALUES (?, ?, ?, ?, ?, ?, 0)
                    """,
                    (incident_id, author_str.strip(), content_str.strip(), now_iso, ttype_val, target_id),
                )
                note_id = cur.lastrowid

                # Record immutable audit entry
                cur.execute(
                    """
                    INSERT INTO investigation_notes_audit (
                        note_id, incident_id, action, actor, content, target_type, target_id, created_at, action_timestamp, reason
                    ) VALUES (?, ?, 'CREATED', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        note_id,
                        incident_id,
                        author_str.strip(),
                        content_str.strip(),
                        ttype_val,
                        target_id,
                        now_iso,
                        now_iso,
                        "Initial analyst note entry",
                    ),
                )
                conn.commit()

        return InvestigationNote(
            id=note_id,
            incident_id=incident_id,
            author=author_str.strip(),
            content=content_str.strip(),
            created_at=now_utc,
            target_type=NoteTargetType(ttype_val.lower()),
            target_id=target_id,
            is_deleted=False,
            deleted_at=None,
            deleted_by=None,
            deletion_reason=None,
        )

    def list_notes(self, incident_id: int, include_deleted: bool = False) -> List[InvestigationNote]:
        """Fetch analyst notes for an incident. By default excludes tombstoned notes."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            where_sql = "WHERE incident_id = ?"
            if not include_deleted:
                where_sql += " AND is_deleted = 0"

            cur.execute(
                f"""
                SELECT id, incident_id, author, content, created_at, target_type, target_id,
                       is_deleted, deleted_at, deleted_by, deletion_reason
                FROM investigation_notes
                {where_sql}
                ORDER BY created_at ASC, id ASC
                """,
                (incident_id,),
            )
            rows = cur.fetchall()

        notes = []
        for r in rows:
            created_dt = datetime.fromisoformat(r["created_at"])
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            del_dt = None
            if r["deleted_at"]:
                del_dt = datetime.fromisoformat(r["deleted_at"])
                if del_dt.tzinfo is None:
                    del_dt = del_dt.replace(tzinfo=timezone.utc)
            notes.append(
                InvestigationNote(
                    id=r["id"],
                    incident_id=r["incident_id"],
                    author=r["author"],
                    content=r["content"],
                    created_at=created_dt,
                    target_type=NoteTargetType(r["target_type"]),
                    target_id=r["target_id"],
                    is_deleted=bool(r["is_deleted"]),
                    deleted_at=del_dt,
                    deleted_by=r["deleted_by"],
                    deletion_reason=r["deletion_reason"],
                )
            )
        return notes

    def get_note(self, note_id: int) -> Optional[InvestigationNote]:
        """Fetch a specific note by ID."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, incident_id, author, content, created_at, target_type, target_id,
                       is_deleted, deleted_at, deleted_by, deletion_reason
                FROM investigation_notes
                WHERE id = ?
                """,
                (note_id,),
            )
            r = cur.fetchone()
            if not r:
                return None
            created_dt = datetime.fromisoformat(r["created_at"])
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            del_dt = None
            if r["deleted_at"]:
                del_dt = datetime.fromisoformat(r["deleted_at"])
                if del_dt.tzinfo is None:
                    del_dt = del_dt.replace(tzinfo=timezone.utc)
            return InvestigationNote(
                id=r["id"],
                incident_id=r["incident_id"],
                author=r["author"],
                content=r["content"],
                created_at=created_dt,
                target_type=NoteTargetType(r["target_type"]),
                target_id=r["target_id"],
                is_deleted=bool(r["is_deleted"]),
                deleted_at=del_dt,
                deleted_by=r["deleted_by"],
                deletion_reason=r["deletion_reason"],
            )

    def delete_note(self, note_id: int, actor: str = "Analyst", reason: Optional[str] = None) -> bool:
        """Mark an analyst note as deleted (tombstone) while preserving historical audit record."""
        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()
        reason_str = reason or "Analyst requested note removal"

        with self._lock:
            with self.db.connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT id, incident_id, author, content, target_type, target_id, created_at, is_deleted FROM investigation_notes WHERE id = ?",
                    (note_id,),
                )
                existing = cur.fetchone()
                if not existing or existing["is_deleted"]:
                    return False

                # Soft delete tombstone
                cur.execute(
                    """
                    UPDATE investigation_notes
                    SET is_deleted = 1, deleted_at = ?, deleted_by = ?, deletion_reason = ?
                    WHERE id = ?
                    """,
                    (now_iso, actor, reason_str, note_id),
                )

                # Record immutable audit entry
                cur.execute(
                    """
                    INSERT INTO investigation_notes_audit (
                        note_id, incident_id, action, actor, content, target_type, target_id, created_at, action_timestamp, reason
                    ) VALUES (?, ?, 'DELETED', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        note_id,
                        existing["incident_id"],
                        actor,
                        existing["content"],
                        existing["target_type"],
                        existing["target_id"],
                        existing["created_at"],
                        now_iso,
                        reason_str,
                    ),
                )
                conn.commit()
                return True

    def get_notes_audit_trail(self, incident_id: int) -> List[InvestigationNoteAudit]:
        """Fetch the immutable historical audit trail of all note operations for an incident."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, note_id, incident_id, action, actor, content, target_type, target_id,
                       created_at, action_timestamp, reason
                FROM investigation_notes_audit
                WHERE incident_id = ?
                ORDER BY id ASC
                """,
                (incident_id,),
            )
            rows = cur.fetchall()

        audit_entries = []
        for r in rows:
            created_dt = datetime.fromisoformat(r["created_at"])
            if created_dt.tzinfo is None:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            action_dt = datetime.fromisoformat(r["action_timestamp"])
            if action_dt.tzinfo is None:
                action_dt = action_dt.replace(tzinfo=timezone.utc)
            audit_entries.append(
                InvestigationNoteAudit(
                    id=r["id"],
                    note_id=r["note_id"],
                    incident_id=r["incident_id"],
                    action=r["action"],
                    actor=r["actor"],
                    content=r["content"],
                    target_type=NoteTargetType(r["target_type"]),
                    target_id=r["target_id"],
                    created_at=created_dt,
                    action_timestamp=action_dt,
                    reason=r["reason"],
                )
            )
        return audit_entries

    # =========================================================================
    # 2. Deep Event Forensics
    # =========================================================================

    def get_event_forensics(self, event_id: str) -> Optional[EventForensics]:
        """Traverse complete forensic context and raw provenance for an event."""
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM events WHERE id = ?", (event_id,))
            ev_row = cur.fetchone()
            if not ev_row:
                return None

            ev_dict = dict(ev_row)

            # Raw provenance block
            provenance = {
                "source_file": ev_row["source_file"],
                "source_offset": ev_row["source_offset"],
                "parser": ev_row["parser"],
                "event_fingerprint": ev_row["event_fingerprint"],
                "raw_message": ev_row["raw_message"],
                "timestamp": ev_row["timestamp"],
                "ingested_at": ev_row["ingested_at"],
            }

            # Find matching detections via detection_evidence
            cur.execute(
                """
                SELECT d.id, d.rule_id, d.alert_id, d.timestamp, d.host, d.summary, de.role
                FROM detections d
                INNER JOIN detection_evidence de ON d.id = de.detection_id
                WHERE de.event_id = ?
                """,
                (event_id,),
            )
            det_rows = cur.fetchall()
            detections = [dict(r) for r in det_rows]

            # Find linked alerts
            alert_ids = {d["alert_id"] for d in detections if d.get("alert_id")}
            alerts: List[Dict[str, Any]] = []
            if alert_ids:
                placeholders = ",".join("?" for _ in alert_ids)
                cur.execute(
                    f"SELECT id, title, severity, status, host, first_seen, last_seen FROM alerts WHERE id IN ({placeholders})",
                    list(alert_ids),
                )
                alerts = [dict(r) for r in cur.fetchall()]

            # Find linked incidents
            incidents: List[Dict[str, Any]] = []
            if alert_ids:
                placeholders = ",".join("?" for _ in alert_ids)
                cur.execute(
                    f"""
                    SELECT i.id, i.incident_key, i.title, i.severity, i.status, i.first_seen, i.last_seen
                    FROM incidents i
                    INNER JOIN incident_alerts ia ON i.id = ia.incident_id
                    WHERE ia.alert_id IN ({placeholders})
                    """,
                    list(alert_ids),
                )
                incidents = [dict(r) for r in cur.fetchall()]

            # Associated entities
            entities = []
            if ev_row["host"]:
                entities.append(f"host:{ev_row['host'].lower()}")
            if ev_row["username"]:
                entities.append(f"user:{ev_row['username']}")
            if ev_row["src_ip"]:
                entities.append(f"ip:{ev_row['src_ip']}")
            if ev_row["process_name"]:
                entities.append(f"process:{ev_row['process_name']}")

            # Query relationships supported by this event
            cur.execute(
                """
                SELECT id, incident_id, source_entity_key, target_entity_key,
                       relationship_type, confidence, matched_at
                FROM incident_relationships
                WHERE evidence_event_ids_json LIKE ?
                """,
                (f"%{event_id}%",),
            )
            relationships = [dict(r) for r in cur.fetchall()]

        return EventForensics(
            event_id=event_id,
            event=ev_dict,
            provenance=provenance,
            detections=detections,
            alerts=alerts,
            incidents=incidents,
            entities=list(set(entities)),
            relationships=relationships,
        )

    # =========================================================================
    # 3. Entity-Centric Pivots
    # =========================================================================

    def get_entity_pivot(self, entity_key: str, incident_id: Optional[int] = None) -> Optional[EntityPivotSummary]:
        """Perform deep entity pivot investigation across canonical events and incident relationships.
        
        Supports all seven canonical entity types:
        - HOST: matching host column
        - USER: matching username column
        - IP: matching src_ip or dst_ip columns
        - PROCESS: matching process_name or process_executable columns
        - COMMAND: matching process_command_line or process_executable columns
        - FILE: matching process_executable, raw_message, or summary columns
        - SESSION: matching session_id column
        """
        parts = entity_key.split(":", 1)
        if len(parts) != 2:
            return None
        etype_str, evalue = parts[0].upper(), parts[1]

        valid_types = {"HOST", "USER", "IP", "PROCESS", "COMMAND", "FILE", "SESSION"}
        if etype_str not in valid_types:
            return None

        with self.db.connection() as conn:
            cur = conn.cursor()

            # Dynamic field mapping based on entity type
            if etype_str == "HOST":
                query_cond = "LOWER(host) = LOWER(?)"
                params = [evalue]
            elif etype_str == "USER":
                query_cond = "LOWER(username) = LOWER(?)"
                params = [evalue]
            elif etype_str == "IP":
                query_cond = "(src_ip = ? OR dst_ip = ?)"
                params = [evalue, evalue]
            elif etype_str == "PROCESS":
                query_cond = "(LOWER(process_name) = LOWER(?) OR LOWER(process_executable) = LOWER(?))"
                params = [evalue, evalue]
            elif etype_str == "COMMAND":
                query_cond = "(process_command_line = ? OR process_command_line LIKE ? OR LOWER(process_executable) = LOWER(?))"
                params = [evalue, f"%{evalue}%", evalue]
            elif etype_str == "FILE":
                query_cond = "(process_executable = ? OR raw_message LIKE ? OR summary LIKE ?)"
                params = [evalue, f"%{evalue}%", f"%{evalue}%"]
            elif etype_str == "SESSION":
                query_cond = "session_id = ?"
                params = [evalue]
            else:
                query_cond = "LOWER(host) = LOWER(?)"
                params = [evalue]

            cur.execute(
                f"""
                SELECT COUNT(*), MIN(timestamp), MAX(timestamp)
                FROM events
                WHERE {query_cond}
                """,
                params,
            )
            agg = cur.fetchone()
            total_events = agg[0] or 0
            first_seen_str = agg[1]
            last_seen_str = agg[2]

            first_seen = datetime.fromisoformat(first_seen_str).replace(tzinfo=timezone.utc) if first_seen_str else None
            last_seen = datetime.fromisoformat(last_seen_str).replace(tzinfo=timezone.utc) if last_seen_str else None

            # Get associated hosts
            cur.execute(
                f"SELECT DISTINCT host FROM events WHERE {query_cond} AND host IS NOT NULL LIMIT 20",
                params,
            )
            assoc_hosts = [r[0] for r in cur.fetchall()]

            # Get associated users
            cur.execute(
                f"SELECT DISTINCT username FROM events WHERE {query_cond} AND username IS NOT NULL AND username NOT IN ('-', '', 'unknown') LIMIT 20",
                params,
            )
            assoc_users = [r[0] for r in cur.fetchall()]

            # Get associated IPs
            cur.execute(
                f"SELECT DISTINCT src_ip FROM events WHERE {query_cond} AND src_ip IS NOT NULL AND src_ip NOT IN ('127.0.0.1', '::1', '') LIMIT 20",
                params,
            )
            assoc_ips = [r[0] for r in cur.fetchall()]

            # Get associated processes
            cur.execute(
                f"SELECT DISTINCT process_name FROM events WHERE {query_cond} AND process_name IS NOT NULL LIMIT 20",
                params,
            )
            assoc_procs = [r[0] for r in cur.fetchall()]

            # Get associated commands
            cur.execute(
                f"SELECT DISTINCT process_command_line FROM events WHERE {query_cond} AND process_command_line IS NOT NULL LIMIT 20",
                params,
            )
            assoc_cmds = [r[0] for r in cur.fetchall()]

            # Recent events sample
            cur.execute(
                f"""
                SELECT id, timestamp, event_type, severity, outcome, summary, raw_message
                FROM events
                WHERE {query_cond}
                ORDER BY timestamp DESC, id ASC
                LIMIT 15
                """,
                params,
            )
            recent_events = [dict(r) for r in cur.fetchall()]

            # Relationships query from incident_relationships
            rel_query = """
                SELECT r.*, i.incident_key
                FROM incident_relationships r
                INNER JOIN incidents i ON r.incident_id = i.id
                WHERE r.source_entity_key = ? OR r.target_entity_key = ?
            """
            rel_params = [entity_key, entity_key]
            if incident_id:
                rel_query += " AND r.incident_id = ?"
                rel_params.append(incident_id)
            rel_query += " ORDER BY r.id DESC LIMIT 50"

            cur.execute(rel_query, rel_params)
            relationships = [dict(r) for r in cur.fetchall()]

            # Fetch related incidents directly matching this entity or through primary_host/primary_user
            cur.execute(
                """
                SELECT DISTINCT i.id, i.incident_key, i.title, i.severity, i.status, i.first_seen, i.last_seen
                FROM incidents i
                LEFT JOIN incident_entities ie ON i.id = ie.incident_id
                WHERE ie.entity_key = ? OR LOWER(i.primary_host) = LOWER(?) OR i.primary_user = ?
                ORDER BY i.last_seen DESC LIMIT 10
                """,
                (entity_key, evalue, evalue),
            )
            incidents_list = [dict(r) for r in cur.fetchall()]

            # If total_events == 0, fallback to incident time bounds
            if total_events == 0 and incidents_list:
                cur.execute(
                    """
                    SELECT MIN(i.first_seen), MAX(i.last_seen)
                    FROM incidents i
                    JOIN incident_entities ie ON i.id = ie.incident_id
                    WHERE ie.entity_key = ?
                    """,
                    (entity_key,),
                )
                time_agg = cur.fetchone()
                if time_agg and time_agg[0]:
                    try:
                        first_seen = datetime.fromisoformat(time_agg[0]).replace(tzinfo=timezone.utc)
                        last_seen = datetime.fromisoformat(time_agg[1]).replace(tzinfo=timezone.utc)
                    except Exception:
                        pass

            # Related alerts query
            if etype_str == "HOST":
                cur.execute(
                    "SELECT id, title, severity, status, host, first_seen, last_seen FROM alerts WHERE LOWER(host) = LOWER(?) ORDER BY last_seen DESC LIMIT 10",
                    (evalue,),
                )
                alerts_list = [dict(r) for r in cur.fetchall()]
                total_alerts = len(alerts_list)
            else:
                cur.execute(
                    """
                    SELECT DISTINCT a.id, a.title, a.severity, a.status, a.host, a.first_seen, a.last_seen
                    FROM alerts a
                    JOIN incident_alerts ia ON a.id = ia.alert_id
                    JOIN incident_entities ie ON ia.incident_id = ie.incident_id
                    WHERE ie.entity_key = ?
                    ORDER BY a.last_seen DESC LIMIT 10
                    """,
                    (entity_key,),
                )
                alerts_list = [dict(r) for r in cur.fetchall()]
                total_alerts = len(alerts_list)

        return EntityPivotSummary(
            entity_key=entity_key,
            entity_type=etype_str,
            display_name=evalue,
            first_seen=first_seen,
            last_seen=last_seen,
            total_events=total_events,
            total_alerts=total_alerts,
            total_incidents=len(incidents_list),
            alert_count=total_alerts,
            incident_count=len(incidents_list),
            associated_hosts=assoc_hosts,
            associated_users=assoc_users,
            associated_ips=assoc_ips,
            associated_processes=assoc_procs,
            associated_commands=assoc_cmds,
            related_relationships=relationships,
            recent_events=recent_events,
            alerts=alerts_list,
            incidents=incidents_list,
        )

    # =========================================================================
    # 4. Attack-Path Reconstruction & Analysis
    # =========================================================================

    def reconstruct_attack_path(self, incident_id: int) -> AttackPathReconstruction:
        """Deterministically reconstruct linear and branching attack progression steps for an incident."""
        relationships = self.incidents_repo.get_incident_relationships(incident_id)
        entities = self.incidents_repo.get_incident_entities(incident_id)

        if not relationships:
            return AttackPathReconstruction(
                incident_id=incident_id,
                steps=[],
                root_causes=[],
                terminal_targets=[],
                is_multi_host=False,
                total_steps=0,
            )

        # Graph node in/out degree calculation
        in_degree: Dict[str, int] = {e.entity_key: 0 for e in entities}
        out_degree: Dict[str, int] = {e.entity_key: 0 for e in entities}
        adj_list: Dict[str, List[Any]] = {e.entity_key: [] for e in entities}

        for rel in relationships:
            src = rel.source_entity_key
            tgt = rel.target_entity_key
            if src not in adj_list:
                adj_list[src] = []
                in_degree[src] = 0
                out_degree[src] = 0
            if tgt not in adj_list:
                adj_list[tgt] = []
                in_degree[tgt] = 0
                out_degree[tgt] = 0

            adj_list[src].append(rel)
            out_degree[src] += 1
            in_degree[tgt] += 1

        root_causes = [k for k, v in in_degree.items() if v == 0]
        terminal_targets = [k for k, v in out_degree.items() if v == 0]

        # Stage classification helper
        def _get_stage_and_desc(rel_type: str, src: str, tgt: str) -> Tuple[str, str]:
            rtype = rel_type.upper()
            if rtype == "CONNECTED_TO":
                return "INITIAL_ACCESS", f"Network traffic ingress from {src} to {tgt}"
            elif rtype == "AUTHENTICATED_TO":
                return "CREDENTIAL_ACCESS", f"Account {src} authenticated against host {tgt}"
            elif rtype in ("EXECUTED", "SPAWNED"):
                return "EXECUTION", f"Execution of process {tgt} by actor {src}"
            elif rtype == "LATERAL_MOVEMENT":
                return "LATERAL_MOVEMENT", f"Cross-host lateral movement from {src} to {tgt}"
            elif rtype == "ACCESSED_FILE":
                return "PERSISTENCE", f"System file access/tampering {tgt} by {src}"
            elif "PRIVILEGE" in rtype:
                return "PRIVILEGE_ESCALATION", f"Privilege boundary escalation attempt by {src} on {tgt}"
            return "DISCOVERY", f"Observed interaction: {src} -> {tgt} ({rel_type})"

        # Breadth-first / topological progression traversal with cycle protection
        visited_edges: Set[str] = set()
        steps: List[AttackPathStep] = []
        step_counter = 1

        # Priority queues: start from root causes or IPs/Users
        start_nodes = root_causes or sorted(list(adj_list.keys()))

        queue = list(start_nodes)
        visited_nodes: Set[str] = set()

        while queue and len(steps) < 50:
            curr = queue.pop(0)
            if curr in visited_nodes:
                continue
            visited_nodes.add(curr)

            for rel in adj_list.get(curr, []):
                edge_id = f"{rel.source_entity_key}->{rel.target_entity_key}:{rel.relationship_type}"
                if edge_id in visited_edges:
                    continue
                visited_edges.add(edge_id)

                stage, desc = _get_stage_and_desc(
                    rel.relationship_type, rel.source_entity_key, rel.target_entity_key
                )

                conf_val = rel.confidence.value if hasattr(rel.confidence, "value") else str(rel.confidence)
                if rel.evidence_event_ids and conf_val in ("DIRECT", "STRONG"):
                    nature = AttackPathStepNature.OBSERVED
                    inference_reason = None
                    derivation_source = f"Direct canonical event evidence ({len(rel.evidence_event_ids)} events)"
                elif conf_val in ("CORRELATED", "INFERRED"):
                    nature = AttackPathStepNature.INFERRED
                    inference_reason = f"Derived through correlation heuristics and temporal entity proximity ({conf_val})"
                    derivation_source = f"Graph relationship: {rel.relationship_type.value if hasattr(rel.relationship_type, 'value') else rel.relationship_type}"
                else:
                    nature = AttackPathStepNature.UNAVAILABLE
                    inference_reason = "No primary canonical event evidence available for direct attribution"
                    derivation_source = "Absence of direct observation"

                steps.append(
                    AttackPathStep(
                        step_number=step_counter,
                        source_node=rel.source_entity_key,
                        target_node=rel.target_entity_key,
                        relationship_type=rel.relationship_type,
                        stage=stage,
                        confidence=rel.confidence,
                        nature=nature,
                        supporting_event_ids=rel.evidence_event_ids,
                        evidence_event_ids=rel.evidence_event_ids,
                        description=desc,
                        inference_reason=inference_reason,
                        derivation_source=derivation_source,
                        timestamp=rel.matched_at,
                    )
                )
                step_counter += 1
                queue.append(rel.target_entity_key)

        # Check if multi-host
        host_count = sum(1 for e in entities if e.entity_type == EntityType.HOST)

        return AttackPathReconstruction(
            incident_id=incident_id,
            steps=steps,
            root_causes=root_causes,
            terminal_targets=terminal_targets,
            is_multi_host=host_count > 1,
            total_steps=len(steps),
        )

    # =========================================================================
    # 5. MITRE ATT&CK Mapping
    # =========================================================================

    def get_incident_mitre_mappings(self, incident_id: int) -> List[MitreMapping]:
        """Derive explainable, evidence-backed MITRE ATT&CK technique mappings for an incident."""
        alerts = self.incidents_repo.get_incident_alerts(incident_id)
        if not alerts:
            return []

        alert_ids = [a.id for a in alerts]
        mappings_by_technique: Dict[str, MitreMapping] = {}

        with self.db.connection() as conn:
            cur = conn.cursor()
            placeholders = ",".join("?" for _ in alert_ids)

            # Query rules and evidence for these alerts
            cur.execute(
                f"""
                SELECT a.id AS alert_id, a.rule_id, dr.name AS rule_name, de.event_id
                FROM alerts a
                LEFT JOIN detection_rules dr ON a.rule_id = dr.id
                LEFT JOIN detections d ON d.alert_id = a.id
                LEFT JOIN detection_evidence de ON de.detection_id = d.id
                WHERE a.id IN ({placeholders})
                """,
                alert_ids,
            )
            rows = cur.fetchall()

        for r in rows:
            rule_id = r["rule_id"]
            if not rule_id or rule_id not in RULE_TO_MITRE:
                continue

            tech_id, tech_name, tactic = RULE_TO_MITRE[rule_id]
            alert_id = r["alert_id"]
            ev_id = r["event_id"]

            if tech_id not in mappings_by_technique:
                mappings_by_technique[tech_id] = MitreMapping(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    rule_id=rule_id,
                    rule_name=r["rule_name"] or rule_id,
                    supporting_alert_ids=[alert_id],
                    supporting_event_ids=[ev_id] if ev_id else [],
                    confidence=ConfidenceLevel.DIRECT,
                )
            else:
                m = mappings_by_technique[tech_id]
                if alert_id not in m.supporting_alert_ids:
                    m.supporting_alert_ids.append(alert_id)
                if ev_id and ev_id not in m.supporting_event_ids:
                    m.supporting_event_ids.append(ev_id)

        # Check for Lateral Movement in relationships
        relationships = self.incidents_repo.get_incident_relationships(incident_id)
        lat_mov_rels = [
            r for r in relationships
            if (r.relationship_type == RelationshipType.LATERAL_MOVEMENT.value
                or (hasattr(r.relationship_type, "value") and r.relationship_type.value == "LATERAL_MOVEMENT"))
        ]
        if lat_mov_rels:
            lat_ev_ids = []
            for r in lat_mov_rels:
                if r.evidence_event_ids:
                    lat_ev_ids.extend(r.evidence_event_ids)
            mappings_by_technique["T1021.004"] = MitreMapping(
                technique_id="T1021.004",
                technique_name="Remote Services: SSH",
                tactic="Lateral Movement",
                rule_id="correlation.lateral_movement",
                rule_name="Cross-Host Lateral Movement",
                supporting_alert_ids=alert_ids,
                supporting_event_ids=list(dict.fromkeys(lat_ev_ids)),
                confidence=ConfidenceLevel.STRONG,
            )

        # Sort deterministically by tactic, then technique_id
        return sorted(list(mappings_by_technique.values()), key=lambda m: (m.tactic, m.technique_id))

    # =========================================================================
    # 6. Threat Hunting / Evidence Search
    # =========================================================================

    def search_events(self, f: ThreatHuntFilter) -> ThreatHuntResponse:
        """Search canonical events and historical evidence with combined multi-attribute filters."""
        where_clauses: List[str] = []
        params: List[Any] = []

        if f.search_text:
            text_pattern = f"%{f.search_text.strip()}%"
            where_clauses.append("(raw_message LIKE ? OR summary LIKE ? OR process_command_line LIKE ?)")
            params.extend([text_pattern, text_pattern, text_pattern])

        if f.start_time:
            where_clauses.append("timestamp >= ?")
            params.append(f.start_time.isoformat())

        if f.end_time:
            where_clauses.append("timestamp <= ?")
            params.append(f.end_time.isoformat())

        if f.host:
            where_clauses.append("LOWER(host) = LOWER(?)")
            params.append(f.host.strip())

        if f.username:
            where_clauses.append("username = ?")
            params.append(f.username.strip())

        if f.src_ip:
            where_clauses.append("src_ip = ?")
            params.append(f.src_ip.strip())

        if f.dst_ip:
            where_clauses.append("dst_ip = ?")
            params.append(f.dst_ip.strip())

        if f.process_name:
            where_clauses.append("LOWER(process_name) = LOWER(?)")
            params.append(f.process_name.strip())

        if f.event_type:
            where_clauses.append("UPPER(event_type) = UPPER(?)")
            params.append(f.event_type.strip())

        if f.source:
            where_clauses.append("LOWER(source) = LOWER(?)")
            params.append(f.source.strip())

        if f.severity:
            where_clauses.append("UPPER(severity) = UPPER(?)")
            params.append(f.severity.strip())

        if f.outcome:
            where_clauses.append("UPPER(outcome) = UPPER(?)")
            params.append(f.outcome.strip())

        if f.ioc:
            ioc_pattern = f"%{f.ioc.strip()}%"
            where_clauses.append("iocs_json LIKE ?")
            params.append(ioc_pattern)

        # Rule ID filtering via subquery
        if f.rule_id:
            where_clauses.append(
                """
                id IN (
                    SELECT de.event_id FROM detection_evidence de
                    INNER JOIN detections d ON de.detection_id = d.id
                    WHERE d.rule_id = ?
                )
                """
            )
            params.append(f.rule_id.strip())

        # Alert ID filtering via subquery
        if f.alert_id:
            where_clauses.append(
                """
                id IN (
                    SELECT de.event_id FROM detection_evidence de
                    INNER JOIN detections d ON de.detection_id = d.id
                    WHERE d.alert_id = ?
                )
                """
            )
            params.append(f.alert_id)

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""

        with self.db.connection() as conn:
            cur = conn.cursor()

            # Count total
            cur.execute(f"SELECT COUNT(*) FROM events {where_sql}", params)
            total = cur.fetchone()[0] or 0

            # Query paginated rows (deterministic ordering: timestamp DESC, id ASC)
            query_sql = f"""
                SELECT id, timestamp, ingested_at, host, source, event_type, severity,
                       username, src_ip, dst_ip, process_name, outcome, summary, raw_message, parser
                FROM events
                {where_sql}
                ORDER BY timestamp DESC, id ASC
                LIMIT ? OFFSET ?
            """
            cur.execute(query_sql, params + [f.limit, f.offset])
            items = [dict(r) for r in cur.fetchall()]

        active_filters = []
        if f.search_text:
            active_filters.append(f"text='{f.search_text}'")
        if f.host:
            active_filters.append(f"host='{f.host}'")
        if f.username:
            active_filters.append(f"user='{f.username}'")
        if f.src_ip:
            active_filters.append(f"src_ip='{f.src_ip}'")
        if f.event_type:
            active_filters.append(f"event_type='{f.event_type}'")
        if f.outcome:
            active_filters.append(f"outcome='{f.outcome}'")
        if f.process_name:
            active_filters.append(f"process='{f.process_name}'")
        if f.severity:
            active_filters.append(f"severity='{f.severity}'")
        summary_str = ", ".join(active_filters) if active_filters else "All events"

        return ThreatHuntResponse(
            items=items,
            total=total,
            limit=f.limit,
            offset=f.offset,
            query_summary=summary_str,
        )

    # =========================================================================
    # 7. Complete Investigation Dossier & Export
    # =========================================================================

    def get_investigation_dossier(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """Assemble full investigation dossier containing incident, evidence, timeline, graph, attack path, MITRE, and notes."""
        incident = self.incidents_repo.get_incident(incident_id)
        if not incident:
            return None

        alerts = self.incidents_repo.get_incident_alerts(incident_id)
        entities = self.incidents_repo.get_incident_entities(incident_id)
        relationships = self.incidents_repo.get_incident_relationships(incident_id)
        timeline = self.incidents_repo.get_incident_timeline(incident_id)
        attack_path = self.reconstruct_attack_path(incident_id)
        mitre_mappings = self.get_incident_mitre_mappings(incident_id)
        notes = self.list_notes(incident_id)

        return {
            "incident": incident.model_dump(),
            "alerts": [a.model_dump() for a in alerts],
            "entities": [e.model_dump() for e in entities],
            "relationships": [r.model_dump() for r in relationships],
            "timeline": [t.model_dump() for t in timeline],
            "attack_path": attack_path.model_dump(),
            "mitre_mappings": [m.model_dump() for m in mitre_mappings],
            "notes": [n.model_dump() for n in notes],
            "timeline_total": len(timeline),
        }

    def export_investigation(self, incident_id: int, format: str = "markdown") -> str:
        """Export an evidence-backed investigation report in Markdown, JSON, or CSV format."""
        dossier = self.get_investigation_dossier(incident_id)
        if not dossier:
            raise ValueError(f"Incident {incident_id} not found")

        fmt = format.lower().strip()
        if fmt == "json":
            return json.dumps(dossier, indent=2, default=str)

        if fmt == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["Timeline Item ID", "Timestamp", "Type", "Title", "Severity", "Summary"])
            for item in dossier.get("timeline", []):
                writer.writerow([
                    item.get("id"),
                    item.get("timestamp"),
                    item.get("item_type"),
                    item.get("title"),
                    item.get("severity"),
                    item.get("summary"),
                ])
            return output.getvalue()

        # Default Markdown report
        inc = dossier["incident"]
        md = []
        md.append(f"# LogIntel Investigation Dossier — {inc['incident_key']}")
        md.append(f"\n**Title:** {inc['title']}")
        md.append(f"**Severity:** {inc['severity']} | **Status:** {inc['status']}")
        md.append(f"**Primary Host:** {inc['primary_host']} | **Primary User:** {inc['primary_user'] or 'N/A'}")
        md.append(f"**First Seen:** {inc['first_seen']} | **Last Seen:** {inc['last_seen']}")
        md.append(f"**Total Alerts:** {inc['alert_count']} | **Total Evidence Events:** {inc['event_count']}")

        md.append("\n## Summary")
        md.append(inc["summary"])

        md.append("\n## Attack Progression & Path Reconstruction")
        ap = dossier.get("attack_path", {})
        steps = ap.get("steps", [])
        if steps:
            for s in steps:
                md.append(f"- **Step {s['step_number']} [{s['stage']} / {s['nature']}]:** `{s['source_node']}` —[{s['relationship_type']}]→ `{s['target_node']}` ({s['description']})")
        else:
            md.append("No attack progression steps derived.")

        md.append("\n## MITRE ATT&CK Mappings")
        mitre = dossier.get("mitre_mappings", [])
        if mitre:
            for m in mitre:
                md.append(f"- **[{m['technique_id']}] {m['technique_name']}** (Tactic: {m['tactic']}, Rule: `{m['rule_id']}`) — Supporting Alerts: {m['supporting_alert_ids']}, Supporting Events: {len(m['supporting_event_ids'])}")
        else:
            md.append("No MITRE techniques mapped.")

        md.append("\n## Associated Entities")
        for ent in dossier.get("entities", []):
            md.append(f"- `{ent['entity_key']}` ({ent['entity_type']}: {ent['display_name']})")

        md.append("\n## Analyst Notes & Annotation History")
        notes = dossier.get("notes", [])
        if notes:
            for n in notes:
                md.append(f"- **[{n['created_at']}] {n['author']}:** {n['content']}")
        else:
            md.append("No analyst annotations recorded.")

        md.append("\n---")
        md.append(f"*Report generated deterministically by LogIntel Investigation Workspace at {datetime.now(timezone.utc).isoformat()}*")

        return "\n".join(md)

    def get_unified_host_graph(self, incident_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve unified Linux host graph contextualized for an incident and its primary host."""
        from logintel.correlation.host_graph import host_graph_builder
        inc = self.incidents_repo.get_incident(incident_id)
        if not inc:
            return None

        # Gather evidence event IDs across incident alerts
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT DISTINCT de.event_id
                FROM incident_alerts ia
                INNER JOIN detections d ON ia.alert_id = d.alert_id
                INNER JOIN detection_evidence de ON d.id = de.detection_id
                WHERE ia.incident_id = ?
                """,
                (incident_id,),
            )
            event_ids = [r["event_id"] for r in cur.fetchall() if r["event_id"]]

        events_data: List[Dict[str, Any]] = []
        if event_ids:
            placeholders = ",".join("?" for _ in event_ids)
            with self.db.connection() as conn:
                cur = conn.cursor()
                cur.execute(
                    f"""
                    SELECT id, host, username, src_ip, dst_ip, process_name, event_type, outcome, summary, metadata_json, timestamp
                    FROM events
                    WHERE id IN ({placeholders})
                    """,
                    event_ids,
                )
                for r in cur.fetchall():
                    row_dict = dict(r)
                    if row_dict.get("metadata_json"):
                        try:
                            import json
                            row_dict["metadata"] = json.loads(row_dict["metadata_json"])
                        except Exception:
                            row_dict["metadata"] = {}
                    events_data.append(row_dict)

        host_graph = host_graph_builder.build_from_events(host=inc.primary_host, events=events_data)
        return host_graph.model_dump(mode="json")

    def get_host_telemetry_graph(self, host: str, limit: int = 200) -> Dict[str, Any]:
        """Generate unified Linux host graph from historical events for a specified host."""
        from logintel.correlation.host_graph import host_graph_builder
        events_data: List[Dict[str, Any]] = []
        with self.db.connection() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT id, host, username, src_ip, dst_ip, process_name, event_type, outcome, summary, metadata_json, timestamp
                FROM events
                WHERE LOWER(host) = LOWER(?)
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (host, limit),
            )
            for r in cur.fetchall():
                row_dict = dict(r)
                if row_dict.get("metadata_json"):
                    try:
                        import json
                        row_dict["metadata"] = json.loads(row_dict["metadata_json"])
                    except Exception:
                        row_dict["metadata"] = {}
                events_data.append(row_dict)

        host_graph = host_graph_builder.build_from_events(host=host, events=events_data)
        return host_graph.model_dump(mode="json")


# Global singleton investigation repository
investigation_repo = InvestigationRepository()
