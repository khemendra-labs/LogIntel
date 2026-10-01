"""Milestone 4 — Comprehensive Forensic Investigation Workspace & Threat Hunting Test Suite.

Validates:
- Migration 5 (investigation_notes and composite search indexes)
- Analyst Notes CRUD & audit trail
- Deep Event Forensics & provenance lineage
- Entity Pivot (IP, Host, User, Process)
- Attack Path Reconstruction (observed vs inferred, cycle detection, depth limits)
- Deterministic MITRE ATT&CK Mapping
- Multi-parameter Threat Hunting & bounded pagination
- Investigation Dossier Export (Markdown, JSON, CSV)
- Concurrency & WAL transaction safety
- Authenticated REST API routes
"""

from __future__ import annotations

import concurrent.futures
import json
import sqlite3
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from logintel.api.app import create_app
from logintel.models.investigation import (
    AttackPathStepNature,
    CreateNoteRequest,
    NoteTargetType,
    ThreatHuntFilter,
)
from logintel.storage.db import Database
from logintel.storage.incidents_repo import IncidentsRepository
from logintel.storage.investigation_repo import InvestigationRepository
from logintel.storage.migrations import apply_migrations


@pytest.fixture
def temp_db():
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "investigation_test.db"
        db = Database(db_path)
        db.initialize()
        yield db
        db.close()


@pytest.fixture
def seeded_db(temp_db):
    """Seed database with realistic multi-stage security incident evidence."""
    with temp_db.connection() as conn:
        cur = conn.cursor()

        # 1. Insert Hosts
        cur.execute(
            "INSERT INTO hosts (id, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            ("host-1", "srv-db01", "2026-09-30T10:00:00Z", "2026-09-30T10:30:00Z"),
        )
        cur.execute(
            "INSERT INTO hosts (id, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?)",
            ("host-2", "workstation-05", "2026-09-30T10:00:00Z", "2026-09-30T10:30:00Z"),
        )

        # 2. Insert Canonical Events
        events_data = [
            (
                "evt-101",
                "2026-09-30T10:00:00Z",
                "2026-09-30T10:00:05Z",
                "srv-db01",
                "auth.log",
                "auth",
                "WARNING",
                "root",
                None,
                "sshd",
                4120,
                None,
                "192.168.1.100",
                44321,
                "192.168.1.10",
                22,
                "ssh_login",
                "failure",
                "Failed SSH password for root from 192.168.1.100",
                "Failed password for root from 192.168.1.100 port 44321 ssh2",
                "auth_parser",
                "fp-101",
            ),
            (
                "evt-102",
                "2026-09-30T10:02:00Z",
                "2026-09-30T10:02:05Z",
                "srv-db01",
                "auth.log",
                "auth",
                "INFORMATIONAL",
                "admin",
                1001,
                "sshd",
                4130,
                None,
                "192.168.1.100",
                44322,
                "192.168.1.10",
                22,
                "ssh_login",
                "success",
                "Accepted SSH publickey for admin from 192.168.1.100",
                "Accepted publickey for admin from 192.168.1.100 port 44322 ssh2",
                "auth_parser",
                "fp-102",
            ),
            (
                "evt-103",
                "2026-09-30T10:05:00Z",
                "2026-09-30T10:05:02Z",
                "srv-db01",
                "syslog",
                "sudo",
                "ALERT",
                "admin",
                1001,
                "sudo",
                4200,
                "/usr/bin/bash",
                None,
                None,
                None,
                None,
                "sudo_exec",
                "success",
                "admin executed /usr/bin/bash as root via sudo",
                "sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/bash",
                "sudo_parser",
                "fp-103",
            ),
            (
                "evt-104",
                "2026-09-30T10:10:00Z",
                "2026-09-30T10:10:05Z",
                "srv-db01",
                "syslog",
                "exec",
                "CRITICAL",
                "root",
                0,
                "nmap",
                4350,
                "/usr/bin/nmap -sS 192.168.1.0/24",
                None,
                None,
                None,
                None,
                "exec",
                "success",
                "root executed /usr/bin/nmap lateral probe",
                "root : PWD=/root ; COMMAND=/usr/bin/nmap -sS 192.168.1.0/24",
                "exec_parser",
                "fp-104",
            ),
        ]

        cur.executemany(
            """
            INSERT INTO events (
                id, timestamp, ingested_at, host, source, event_type, severity,
                username, uid, process_name, process_pid, process_command_line,
                src_ip, src_port, dst_ip, dst_port, action, outcome,
                summary, raw_message, parser, event_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            events_data,
        )

        # 3. Insert Detection Rules (needed for alerts FK)
        cur.execute(
            """
            INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES ('auth.ssh_bruteforce', 'SSH Brute Force', 'Detects repeated SSH failures', 'CRITICAL', 'authentication', 'threshold', 'yaml...')
            """
        )
        cur.execute(
            """
            INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES ('priv.unauthorized_sudo', 'Unauthorized Sudo Escalation', 'Detects shell via sudo', 'CRITICAL', 'privilege', 'pattern', 'yaml...')
            """
        )

        # 4. Insert Alerts
        cur.execute(
            """
            INSERT INTO alerts (rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES ('auth.ssh_bruteforce', 'dedup-ssh-1', 'SSH Attack Detected', 'Repeated SSH failures', 'CRITICAL', 'OPEN', 'srv-db01', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z', 1)
            """
        )
        alert_id_1 = cur.lastrowid
        cur.execute(
            """
            INSERT INTO alerts (rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES ('priv.unauthorized_sudo', 'dedup-sudo-1', 'Privilege Escalation Detected', 'Admin to root via bash', 'CRITICAL', 'OPEN', 'srv-db01', '2026-09-30T10:05:00Z', '2026-09-30T10:05:00Z', 1)
            """
        )
        alert_id_2 = cur.lastrowid

        cur.execute(
            """
            INSERT INTO detections (alert_id, rule_id, timestamp, host, summary, evidence_count)
            VALUES (?, 'auth.ssh_bruteforce', '2026-09-30T10:00:00Z', 'srv-db01', 'SSH bruteforce attempt', 1)
            """,
            (alert_id_1,),
        )
        det_id_1 = cur.lastrowid
        cur.execute(
            """
            INSERT INTO detections (alert_id, rule_id, timestamp, host, summary, evidence_count)
            VALUES (?, 'priv.unauthorized_sudo', '2026-09-30T10:05:00Z', 'srv-db01', 'Sudo bash root escalation', 1)
            """,
            (alert_id_2,),
        )
        det_id_2 = cur.lastrowid

        # Link detections to events via detection_evidence
        cur.execute(
            "INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (?, ?, ?)",
            (det_id_1, "evt-101", "primary"),
        )
        cur.execute(
            "INSERT INTO detection_evidence (detection_id, event_id, role) VALUES (?, ?, ?)",
            (det_id_2, "evt-103", "primary"),
        )

        # 5. Insert Incident
        cur.execute(
            """
            INSERT INTO incidents (
                incident_key, title, summary, severity, status, primary_host, primary_user,
                first_seen, last_seen, alert_count, event_count
            ) VALUES (
                'INC-2026-0001', 'Multi-Stage Infiltration & Privilege Escalation',
                'External SSH brute force followed by admin login and root shell spawn',
                'CRITICAL', 'INVESTIGATING', 'srv-db01', 'admin',
                '2026-09-30T10:00:00Z', '2026-09-30T10:10:00Z', 2, 4
            )
            """
        )
        incident_id = cur.lastrowid

        # Link alerts to incident
        cur.execute(
            "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
            (incident_id, alert_id_1),
        )
        cur.execute(
            "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (?, ?)",
            (incident_id, alert_id_2),
        )

        # 6. Insert Entities into incident graph
        entities = [
            (incident_id, "ip:192.168.1.100", "IP", "192.168.1.100", json.dumps({"ip": "192.168.1.100"})),
            (incident_id, "user:admin", "USER", "admin", json.dumps({"username": "admin"})),
            (incident_id, "user:root", "USER", "root", json.dumps({"username": "root"})),
            (incident_id, "host:srv-db01", "HOST", "srv-db01", json.dumps({"hostname": "srv-db01"})),
            (incident_id, "process:sshd", "PROCESS", "sshd", json.dumps({"name": "sshd"})),
            (incident_id, "process:sudo", "PROCESS", "sudo", json.dumps({"name": "sudo"})),
            (incident_id, "process:bash", "PROCESS", "bash", json.dumps({"name": "bash"})),
        ]
        cur.executemany(
            """
            INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name, metadata_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            entities,
        )

        # 7. Insert Attributed Relationships (Edges)
        relationships = [
            (incident_id, "ip:192.168.1.100", "host:srv-db01", "CONNECTED_TO", "STRONG", json.dumps(["evt-101", "evt-102"])),
            (incident_id, "user:admin", "host:srv-db01", "AUTHENTICATED_TO", "STRONG", json.dumps(["evt-102"])),
            (incident_id, "user:admin", "process:sudo", "SPAWNED", "STRONG", json.dumps(["evt-103"])),
            (incident_id, "process:sudo", "process:bash", "SPAWNED", "STRONG", json.dumps(["evt-103"])),
            (incident_id, "process:bash", "user:root", "EXECUTED", "STRONG", json.dumps(["evt-103", "evt-104"])),
        ]
        cur.executemany(
            """
            INSERT INTO incident_relationships (
                incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            relationships,
        )

        conn.commit()

    return temp_db


def test_migration_5_schema_invariants(temp_db):
    """Verify Migration 5 created investigation_notes and composite indexes."""
    with temp_db.connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT MAX(version) FROM schema_migrations")
        assert cur.fetchone()[0] >= 5

        # Check investigation_notes table columns
        cur.execute("PRAGMA table_info(investigation_notes)")
        cols = {row[1]: row[2] for row in cur.fetchall()}
        assert "id" in cols
        assert "incident_id" in cols
        assert "author" in cols
        assert "content" in cols
        assert "created_at" in cols
        assert "target_type" in cols
        assert "target_id" in cols

        # Check indexes exist
        cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
        indexes = {row[0] for row in cur.fetchall()}
        assert "idx_investigation_notes_incident" in indexes
        assert "idx_investigation_notes_created" in indexes
        assert "idx_investigation_notes_target" in indexes
        assert "idx_events_search_composite" in indexes
        assert "idx_events_process_time" in indexes

        # Check foreign key integrity
        cur.execute("PRAGMA foreign_key_check")
        assert cur.fetchall() == []


def test_investigation_notes_lifecycle(seeded_db):
    """Verify adding, listing, fetching, and deleting analyst notes."""
    repo = InvestigationRepository(seeded_db)

    # 1. Add Note 1 (Incident general)
    note1 = repo.add_note(
        1,
        CreateNoteRequest(
            author="SecAnalyst-Alpha",
            content="Initial triage: confirmed external attack IP 192.168.1.100.",
            target_type="INCIDENT",
        ),
    )
    assert note1.id is not None
    assert note1.incident_id == 1
    assert note1.author == "SecAnalyst-Alpha"
    assert note1.target_type in (NoteTargetType.INCIDENT, "incident", "INCIDENT")

    # 2. Add Note 2 (Entity specific)
    note2 = repo.add_note(
        1,
        CreateNoteRequest(
            author="ForensicLead",
            content="Host compromised via stolen admin credentials.",
            target_type="ENTITY",
            target_id="host:srv-db01",
        ),
    )
    assert note2.id is not None
    assert note2.target_type in (NoteTargetType.ENTITY, "entity", "ENTITY")
    assert note2.target_id == "host:srv-db01"

    # 3. List notes
    notes = repo.list_notes(1)
    assert len(notes) == 2
    assert notes[0].id == note1.id
    assert notes[1].id == note2.id

    # 4. Get note
    fetched = repo.get_note(note1.id)
    assert fetched is not None
    assert fetched.content == note1.content

    # 5. Delete note (soft-delete with tombstone and audit logging)
    deleted = repo.delete_note(note1.id, actor="ForensicLead", reason="Obsolete observation")
    assert deleted is True

    # 6. Verify list has only 1 active note by default
    remaining = repo.list_notes(1, include_deleted=False)
    assert len(remaining) == 1
    assert remaining[0].id == note2.id

    # 7. Verify list with include_deleted=True contains tombstoned note
    all_notes = repo.list_notes(1, include_deleted=True)
    assert len(all_notes) == 2
    deleted_note = next(n for n in all_notes if n.id == note1.id)
    assert deleted_note.is_deleted is True
    assert deleted_note.deleted_by == "ForensicLead"
    assert deleted_note.deletion_reason == "Obsolete observation"
    assert deleted_note.deleted_at is not None

    # 8. Verify append-only audit trail
    audit_entries = repo.get_notes_audit_trail(1)
    assert len(audit_entries) >= 3  # note1 CREATED, note2 CREATED, note1 DELETED
    actions = [e.action for e in audit_entries]
    assert "CREATED" in actions
    assert "DELETED" in actions
    del_entry = next(e for e in audit_entries if e.action == "DELETED")
    assert del_entry.note_id == note1.id
    assert del_entry.actor == "ForensicLead"
    assert del_entry.reason == "Obsolete observation"


def test_deep_event_forensics(seeded_db):
    """Verify deep event inspection exposes immutable provenance, detections, alerts, entities, and relationships."""
    repo = InvestigationRepository(seeded_db)

    # Inspect evt-101 (SSH fail)
    forensics = repo.get_event_forensics("evt-101")
    assert forensics is not None
    assert forensics.event_id == "evt-101"
    assert forensics.event["host"] == "srv-db01"
    assert forensics.provenance["raw_message"] == "Failed password for root from 192.168.1.100 port 44321 ssh2"
    assert forensics.provenance["event_fingerprint"] == "fp-101"

    # Detections & Alerts lineage
    assert len(forensics.detections) == 1
    assert forensics.detections[0]["rule_id"] == "auth.ssh_bruteforce"
    assert len(forensics.alerts) == 1
    assert forensics.alerts[0]["title"] == "SSH Attack Detected"

    # Incidents lineage
    assert len(forensics.incidents) == 1
    assert forensics.incidents[0]["incident_key"] == "INC-2026-0001"

    # Extracted entities and relationships
    entity_keys = {e["id"] if isinstance(e, dict) else e for e in forensics.entities}
    assert "host:srv-db01" in entity_keys
    assert "user:root" in entity_keys
    assert "ip:192.168.1.100" in entity_keys

    rel_types = {r["relationship_type"] for r in forensics.relationships}
    assert "CONNECTED_TO" in rel_types


def test_entity_pivot_ip_and_host(seeded_db):
    """Verify entity pivots return correlated activity, users, processes, alerts, and incidents."""
    repo = InvestigationRepository(seeded_db)

    # 1. IP Pivot
    ip_pivot = repo.get_entity_pivot("ip:192.168.1.100")
    assert ip_pivot is not None
    assert ip_pivot.entity_key == "ip:192.168.1.100"
    assert ip_pivot.entity_type == "IP"
    assert "srv-db01" in ip_pivot.associated_hosts
    assert "admin" in ip_pivot.associated_users
    assert ip_pivot.alert_count >= 1
    assert ip_pivot.incident_count >= 1
    assert len(ip_pivot.recent_events) >= 2

    # 2. Host Pivot
    host_pivot = repo.get_entity_pivot("host:srv-db01")
    assert host_pivot is not None
    assert host_pivot.entity_type == "HOST"
    assert "admin" in host_pivot.associated_users
    assert "root" in host_pivot.associated_users
    assert "192.168.1.100" in host_pivot.associated_ips
    assert "sudo" in host_pivot.associated_processes
    assert "/usr/bin/bash" in host_pivot.associated_commands

    # 3. User Pivot
    user_pivot = repo.get_entity_pivot("user:admin")
    assert user_pivot is not None
    assert "srv-db01" in user_pivot.associated_hosts
    assert "sudo" in user_pivot.associated_processes

    # 4. Process Pivot
    proc_pivot = repo.get_entity_pivot("process:sudo")
    assert proc_pivot is not None
    assert proc_pivot.entity_type == "PROCESS"
    assert proc_pivot.entity_key == "process:sudo"
    assert proc_pivot.total_events >= 1

    # 5. Command Pivot
    cmd_pivot = repo.get_entity_pivot("command:/usr/bin/bash")
    assert cmd_pivot is not None
    assert cmd_pivot.entity_type == "COMMAND"
    assert cmd_pivot.entity_key == "command:/usr/bin/bash"

    # 6. File Pivot (Non-existent in seeded, verify clean empty/fallback handling)
    file_pivot = repo.get_entity_pivot("file:/etc/shadow")
    assert file_pivot is not None
    assert file_pivot.entity_type == "FILE"
    assert file_pivot.entity_key == "file:/etc/shadow"
    assert file_pivot.total_events == 0

    # 7. Session Pivot (Verify fallback/empty handling)
    session_pivot = repo.get_entity_pivot("session:sess-12345")
    assert session_pivot is not None
    assert session_pivot.entity_type == "SESSION"
    assert session_pivot.entity_key == "session:sess-12345"


def test_attack_path_reconstruction_determinism(seeded_db):
    """Verify attack path reconstructs topological progression with observed vs inferred classification."""
    repo = InvestigationRepository(seeded_db)

    path = repo.reconstruct_attack_path(1)
    assert path is not None
    assert path.incident_id == 1
    assert len(path.steps) >= 4

    # Check first step (Inbound IP to host)
    first_step = path.steps[0]
    assert first_step.step_number == 1
    assert first_step.nature == AttackPathStepNature.OBSERVED
    assert first_step.relationship_type == "CONNECTED_TO"
    assert len(first_step.evidence_event_ids) > 0
    assert "Direct canonical event evidence" in first_step.derivation_source
    assert first_step.inference_reason is None

    # Check root causes identified
    assert "ip:192.168.1.100" in path.root_causes or "user:admin" in path.root_causes

    # Determinism check: reconstruct 5 times, ensure identical step count, ordering, and nature
    for _ in range(5):
        repeat_path = repo.reconstruct_attack_path(1)
        assert len(repeat_path.steps) == len(path.steps)
        for s1, s2 in zip(path.steps, repeat_path.steps):
            assert s1.step_number == s2.step_number
            assert s1.relationship_type == s2.relationship_type
            assert s1.nature == s2.nature
            assert s1.evidence_event_ids == s2.evidence_event_ids
            assert s1.derivation_source == s2.derivation_source
            assert s1.inference_reason == s2.inference_reason


def test_attack_path_cycle_and_bound_handling(temp_db):
    """Verify attack path engine safely bounds depth and prevents infinite cycles."""
    repo = InvestigationRepository(temp_db)

    with temp_db.connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO incidents (incident_key, title, summary, severity, status, primary_host, first_seen, last_seen)
            VALUES ('INC-CYC-1', 'Cycle Test', 'Synthetic cycle', 'WARNING', 'OPEN', 'h1', '2026-09-30T10:00:00Z', '2026-09-30T10:00:00Z')
            """
        )
        inc_id = cur.lastrowid

        # Insert entities
        for name in ["A", "B", "C"]:
            cur.execute(
                "INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name) VALUES (?, ?, ?, ?)",
                (inc_id, f"host:{name}", "HOST", name),
            )

        # Create cycle: A -> B -> C -> A
        cycle_edges = [
            (inc_id, "host:A", "host:B", "CONNECTED_TO", "STRONG", json.dumps(["ev-1"])),
            (inc_id, "host:B", "host:C", "CONNECTED_TO", "STRONG", json.dumps(["ev-2"])),
            (inc_id, "host:C", "host:A", "CONNECTED_TO", "STRONG", json.dumps(["ev-3"])),
        ]
        cur.executemany(
            """
            INSERT INTO incident_relationships (
                incident_id, source_entity_key, target_entity_key, relationship_type, confidence, evidence_event_ids_json
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            cycle_edges,
        )
        conn.commit()

    # Reconstruction must terminate and not blow up
    path = repo.reconstruct_attack_path(inc_id)
    assert path is not None
    # Maximum 3 edges in the cycle should be visited once
    assert len(path.steps) <= 3


def test_deterministic_mitre_mapping(seeded_db):
    """Verify MITRE ATT&CK mapping is strictly derived from verified rules and supporting alerts."""
    repo = InvestigationRepository(seeded_db)

    mappings = repo.get_incident_mitre_mappings(1)
    assert len(mappings) >= 2

    tech_ids = {m.technique_id for m in mappings}
    assert "T1110.001" in tech_ids  # SSH brute force
    assert "T1548.003" in tech_ids  # Sudo escalation

    ssh_map = next(m for m in mappings if m.technique_id == "T1110.001")
    assert ssh_map.tactic == "Credential Access"
    assert ssh_map.rule_id == "auth.ssh_bruteforce"
    assert len(ssh_map.supporting_alert_ids) == 1
    assert ssh_map.evidence_event_count >= 1


def test_multi_parameter_threat_hunting(seeded_db):
    """Verify threat hunting searches canonical events with multi-parameter filtering and bounded pagination."""
    repo = InvestigationRepository(seeded_db)

    # 1. Free-text query
    res1 = repo.search_events(ThreatHuntFilter(query="password for root"))
    assert res1.total_matches == 1
    assert res1.items[0]["id"] == "evt-101"

    # 2. Combined filters: host + outcome + event_type
    res2 = repo.search_events(
        ThreatHuntFilter(
            host="srv-db01",
            outcome="success",
            event_type="sudo",
        )
    )
    assert res2.total_matches == 1
    assert res2.items[0]["id"] == "evt-103"

    # 3. Process filter
    res3 = repo.search_events(ThreatHuntFilter(process="nmap"))
    assert res3.total_matches == 1
    assert res3.items[0]["id"] == "evt-104"

    # 4. IP filter
    res4 = repo.search_events(ThreatHuntFilter(ip="192.168.1.100"))
    assert res4.total_matches == 2  # evt-101 and evt-102

    # 5. Bounded Pagination & Determinism
    res_page0 = repo.search_events(ThreatHuntFilter(limit=2, offset=0))
    res_page1 = repo.search_events(ThreatHuntFilter(limit=2, offset=2))
    assert len(res_page0.items) == 2
    assert len(res_page1.items) == 2
    # Ensure no overlap and deterministic ordering (most recent first)
    page0_ids = {e["id"] for e in res_page0.items}
    page1_ids = {e["id"] for e in res_page1.items}
    assert page0_ids.isdisjoint(page1_ids)


def test_investigation_dossier_export(seeded_db):
    """Verify investigation export generates Markdown, JSON, and CSV with complete evidence citations."""
    repo = InvestigationRepository(seeded_db)

    # 1. Markdown Export
    md_export = repo.export_investigation(1, "markdown")
    assert isinstance(md_export, str)
    assert "# LogIntel Investigation Dossier" in md_export
    assert "INC-2026-0001" in md_export
    assert "MITRE ATT&CK Mappings" in md_export
    assert "Attack Progression & Path Reconstruction" in md_export

    # 2. JSON Export
    json_export = repo.export_investigation(1, "json")
    assert isinstance(json_export, str)
    data = json.loads(json_export)
    assert data["incident"]["incident_key"] == "INC-2026-0001"
    assert len(data["attack_path"]["steps"]) > 0
    assert len(data["mitre_mappings"]) > 0

    # 3. CSV Export
    csv_export = repo.export_investigation(1, "csv")
    assert isinstance(csv_export, str)
    lines = csv_export.strip().split("\n")
    assert len(lines) >= 2
    assert "Timeline Item ID,Timestamp,Type,Title,Severity,Summary" in lines[0]


def test_concurrent_investigation_access(seeded_db):
    """Verify thread-safe concurrent searches, notes, and pivots under SQLite WAL."""
    repo = InvestigationRepository(seeded_db)

    def worker(worker_id: int):
        # 1. Perform search
        res = repo.search_events(ThreatHuntFilter(query="admin", limit=10))
        # 2. Perform entity pivot
        pivot = repo.get_entity_pivot("host:srv-db01")
        # 3. Add note
        note = repo.add_note(
            1,
            CreateNoteRequest(
                author=f"Worker-{worker_id}",
                content=f"Concurrent audit observation from worker {worker_id}",
                target_type="INCIDENT",
            ),
        )
        return res.total_matches, pivot.total_events, note.id

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = [executor.submit(worker, i) for i in range(12)]
        results = [f.result() for f in futures]

    assert len(results) == 12
    # Verify all 12 notes persisted
    all_notes = repo.list_notes(1)
    assert len(all_notes) >= 12


def test_investigation_rest_apis(seeded_db, monkeypatch):
    """Verify REST API routes enforce authentication and return valid M4 responses."""
    from logintel.storage.investigation_repo import investigation_repo, InvestigationRepository
    from logintel.storage.incidents_repo import incidents_repo, IncidentsRepository
    from logintel.storage.alerts_repo import alerts_repo, AlertsRepository

    monkeypatch.setattr("logintel.api.auth._ACTIVE_TOKEN", "valid-test-token")
    test_inv_repo = InvestigationRepository(seeded_db)
    test_inc_repo = IncidentsRepository(seeded_db)
    test_alt_repo = AlertsRepository(seeded_db)

    # Patch the storage singletons used across routes
    monkeypatch.setattr(investigation_repo, "db", seeded_db)
    monkeypatch.setattr(investigation_repo, "incidents_repo", test_inc_repo)
    monkeypatch.setattr(investigation_repo, "alerts_repo", test_alt_repo)
    monkeypatch.setattr(incidents_repo, "db", seeded_db)
    monkeypatch.setattr(alerts_repo, "db", seeded_db)

    app = create_app()
    client = TestClient(app)

    # 1. Unauthenticated requests must be rejected with 401
    unauth_resp = client.get("/api/v1/investigations/1")
    assert unauth_resp.status_code == 401

    headers = {"Authorization": "Bearer valid-test-token"}

    # 2. Get Dossier
    r = client.get("/api/v1/investigations/1", headers=headers)
    assert r.status_code == 200
    dossier = r.json()
    assert dossier["incident"]["incident_key"] == "INC-2026-0001"

    # 3. Get Attack Path
    r = client.get("/api/v1/investigations/1/attack-path", headers=headers)
    assert r.status_code == 200
    path = r.json()
    assert len(path["steps"]) > 0

    # 4. Get MITRE
    r = client.get("/api/v1/investigations/1/mitre", headers=headers)
    assert r.status_code == 200
    mitre = r.json()
    assert mitre["total"] >= 2

    # 5. Notes CRUD via API
    r = client.post(
        "/api/v1/investigations/1/notes",
        headers=headers,
        json={"author": "API-Analyst", "content": "Logged via API", "target_type": "INCIDENT"},
    )
    assert r.status_code == 201
    created_note = r.json()
    note_id = created_note["id"]

    r = client.get("/api/v1/investigations/1/notes", headers=headers)
    assert r.status_code == 200
    assert any(n["id"] == note_id for n in r.json()["items"])

    r = client.delete(f"/api/v1/investigations/notes/{note_id}?actor=LeadAuditor&reason=TestClosure", headers=headers)
    assert r.status_code == 200
    assert r.json()["deleted"] is True

    # 5b. Verify note audit trail endpoint
    r = client.get("/api/v1/investigations/1/notes/audit", headers=headers)
    assert r.status_code == 200
    audit_data = r.json()
    assert audit_data["total"] >= 2
    actions = [e["action"] for e in audit_data["items"]]
    assert "CREATED" in actions
    assert "DELETED" in actions

    # 6. Event Forensics inspect
    r = client.get("/api/v1/investigations/events/evt-101/inspect", headers=headers)
    assert r.status_code == 200
    ev_forensics = r.json()
    assert ev_forensics["event_id"] == "evt-101"

    # 7. Entity Pivot
    r = client.get("/api/v1/investigations/entities/host%3Asrv-db01/pivot", headers=headers)
    assert r.status_code == 200
    pivot = r.json()
    assert pivot["entity_key"] == "host:srv-db01"

    # 8. Threat Hunting Search
    r = client.post(
        "/api/v1/investigations/hunt",
        headers=headers,
        json={"query": "root", "limit": 10},
    )
    assert r.status_code == 200
    hunt = r.json()
    assert hunt["total_matches"] >= 1

    # 9. Export
    r = client.get("/api/v1/investigations/1/export?format=markdown", headers=headers)
    assert r.status_code == 200
    export_res = r.json()
    assert "LogIntel Investigation Dossier" in export_res["content"]
