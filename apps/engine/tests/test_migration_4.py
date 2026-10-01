"""Tests for M3.2 Schema Migration 4 (Incident Correlation & Attack Graph)."""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

import pytest

from logintel.storage.db import Database
from logintel.storage.migrations import MIGRATIONS, apply_migrations


def test_fresh_migration_to_v4():
    """Verify applying migrations to a fresh database creates version 4 with all M3 tables and indexes."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "test_v4.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()
            # 1. Version check
            cur.execute("SELECT MAX(version) FROM schema_migrations")
            assert cur.fetchone()[0] >= 4

            # 2. Migration rows
            cur.execute("SELECT version, name FROM schema_migrations ORDER BY version")
            rows = cur.fetchall()
            assert len(rows) >= 4
            assert rows[3][0] == 4
            assert rows[3][1] == "m3_incident_correlation_and_graph"

            # 3. Table existence check
            cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = {r[0] for r in cur.fetchall()}
            expected_tables = {
                "events",
                "hosts",
                "sources",
                "ingestion_state",
                "schema_migrations",
                "detection_rules",
                "alerts",
                "detections",
                "detection_evidence",
                "incidents",
                "incident_alerts",
                "incident_entities",
                "incident_relationships",
            }
            assert expected_tables.issubset(tables)

            # 4. Verify M3 indexes exist
            cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
            indexes = {r[0] for r in cur.fetchall()}
            expected_indexes = {
                # Incidents
                "idx_incidents_status_last_seen",
                "idx_incidents_severity",
                "idx_incidents_primary_host",
                "idx_incidents_primary_user",
                "idx_incidents_last_seen",
                # Incident Alerts
                "idx_incident_alerts_incident_id",
                "idx_incident_alerts_alert_id",
                # Incident Entities
                "idx_incident_entities_incident",
                "idx_incident_entities_key",
                "idx_incident_entities_type",
                # Incident Relationships
                "idx_incident_relationships_incident",
                "idx_incident_relationships_source",
                "idx_incident_relationships_target",
                "idx_incident_relationships_type",
                # Composite Event Correlation Indexes
                "idx_events_host_time",
                "idx_events_user_time",
                "idx_events_src_ip_time",
            }
            assert expected_indexes.issubset(indexes)
        test_db.close()


def test_upgrade_from_v3_to_v4_preserves_data():
    """Verify that upgrading an existing v3 database to v4 preserves all M1 and M2 data."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "upgrade_test.db"

        # Apply only migrations 1, 2, 3 manually
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA foreign_keys = ON;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
            );
            """
        )
        for v, name, sql in MIGRATIONS[:3]:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE;")
            for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                conn.execute(stmt)
            conn.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (?, ?)", (v, name)
            )
            conn.execute("COMMIT;")

        # Insert sample M1/M2 data
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO hosts (id, hostname, first_seen, last_seen)
            VALUES ('h-1', 'srv-alpha', '2026-03-30T10:00:00Z', '2026-03-30T10:00:00Z')
            """
        )
        cur.execute(
            """
            INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
            VALUES ('rule-auth-01', 'SSH Brute Force', 'Detects failed logins', 'ALERT', 'authentication', 'threshold', 'yaml...')
            """
        )
        cur.execute(
            """
            INSERT INTO alerts (rule_id, dedup_key, title, description, severity, status, host, first_seen, last_seen, occurrence_count)
            VALUES ('rule-auth-01', 'dedup-01', 'SSH Attack', 'Repeated login failure', 'ALERT', 'OPEN', 'srv-alpha', '2026-03-30T10:00:00Z', '2026-03-30T10:05:00Z', 5)
            """
        )
        cur.execute(
            """
            INSERT INTO events (id, timestamp, ingested_at, host, source, event_type, severity, outcome, summary, raw_message, parser, event_fingerprint)
            VALUES ('ev-01', '2026-03-30T10:00:00Z', '2026-03-30T10:00:01Z', 'srv-alpha', 'syslog', 'AUTH_FAIL', 'WARNING', 'FAILURE', 'Failed password', 'Failed pass for root', 'ssh', 'fp-01')
            """
        )
        conn.commit()
        conn.close()

        # Initialize Database - this should apply migration 4
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as c:
            cur = c.cursor()
            cur.execute("SELECT MAX(version) FROM schema_migrations")
            assert cur.fetchone()[0] >= 4

            # Verify existing data preserved
            cur.execute("SELECT hostname FROM hosts WHERE id = 'h-1'")
            assert cur.fetchone()[0] == "srv-alpha"

            cur.execute("SELECT title, occurrence_count FROM alerts WHERE id = 1")
            alert_row = cur.fetchone()
            assert alert_row[0] == "SSH Attack"
            assert alert_row[1] == 5

            cur.execute("SELECT summary FROM events WHERE id = 'ev-01'")
            assert cur.fetchone()[0] == "Failed password"

            # Verify M3 table is now ready for use
            cur.execute(
                """
                INSERT INTO incidents (
                    incident_key, title, summary, severity, status, primary_host, primary_user,
                    first_seen, last_seen, alert_count, event_count
                ) VALUES (
                    'inc-001', 'Brute Force Breach', 'Multiple failed SSH followed by root login',
                    'CRITICAL', 'OPEN', 'srv-alpha', 'root',
                    '2026-03-30T10:00:00Z', '2026-03-30T10:05:00Z', 1, 1
                )
                """
            )
            cur.execute("SELECT COUNT(*) FROM incidents")
            assert cur.fetchone()[0] == 1
        test_db.close()


def test_migration_idempotency():
    """Verify apply_migrations can be called multiple times safely without side effects."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "idempotent.db"
        test_db = Database(db_path)
        test_db.initialize()

        # Run apply_migrations a second and third time
        with test_db.connection() as conn:
            apply_migrations(conn)
            apply_migrations(conn)

            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM schema_migrations")
            assert cur.fetchone()[0] == len(MIGRATIONS)
        test_db.close()


def test_incident_table_check_constraints():
    """Verify CHECK constraints on incidents table (severity, status, counts)."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "constraints.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            # 1. Invalid severity
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incidents (incident_key, title, summary, severity, primary_host, first_seen, last_seen)
                    VALUES ('k1', 't', 's', 'INVALID_SEV', 'h', '2026-01-01', '2026-01-01')
                    """
                )

            # 2. Invalid status
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incidents (incident_key, title, summary, severity, status, primary_host, first_seen, last_seen)
                    VALUES ('k2', 't', 's', 'CRITICAL', 'BOGUS_STATUS', 'h', '2026-01-01', '2026-01-01')
                    """
                )

            # 3. Negative alert_count
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incidents (incident_key, title, summary, severity, alert_count, primary_host, first_seen, last_seen)
                    VALUES ('k3', 't', 's', 'CRITICAL', -1, 'h', '2026-01-01', '2026-01-01')
                    """
                )

            # 4. Duplicate incident_key
            conn.execute(
                """
                INSERT INTO incidents (incident_key, title, summary, severity, primary_host, first_seen, last_seen)
                VALUES ('unique_key', 't', 's', 'ALERT', 'h', '2026-01-01', '2026-01-01')
                """
            )
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incidents (incident_key, title, summary, severity, primary_host, first_seen, last_seen)
                    VALUES ('unique_key', 't2', 's2', 'NOTICE', 'h', '2026-01-01', '2026-01-01')
                    """
                )
        test_db.close()


def test_foreign_key_cascade_and_restrict():
    """Verify CASCADE deletion on incident deletion and RESTRICT on referenced alert deletion."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "fk.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            # Seed rule, alert, incident
            conn.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES ('r1', 'rule', 'desc', 'ALERT', 'auth', 'threshold', 'yaml')
                """
            )
            conn.execute(
                """
                INSERT INTO alerts (id, rule_id, dedup_key, title, description, severity, host, first_seen, last_seen)
                VALUES (10, 'r1', 'd10', 'Alert 10', 'desc', 'ALERT', 'host-1', '2026-01-01', '2026-01-01')
                """
            )
            conn.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, primary_host, first_seen, last_seen)
                VALUES (1, 'inc-1', 'Inc 1', 'desc', 'CRITICAL', 'host-1', '2026-01-01', '2026-01-01')
                """
            )

            # Link alert to incident
            conn.execute(
                "INSERT INTO incident_alerts (incident_id, alert_id) VALUES (1, 10)"
            )

            # Insert entity and relationship
            conn.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name)
                VALUES (1, 'host:host-1', 'HOST', 'host-1'),
                       (1, 'ip:192.168.1.50', 'IP', '192.168.1.50')
                """
            )
            conn.execute(
                """
                INSERT INTO incident_relationships (
                    incident_id, source_entity_key, target_entity_key, relationship_type, confidence
                ) VALUES (
                    1, 'ip:192.168.1.50', 'host:host-1', 'CONNECTED_TO', 'DIRECT'
                )
                """
            )

            # Attempt to delete the alert -> should fail due to ON DELETE RESTRICT
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute("DELETE FROM alerts WHERE id = 10")

            # Delete the incident -> should cascade to incident_alerts, incident_entities, incident_relationships
            conn.execute("DELETE FROM incidents WHERE id = 1")

            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM incident_alerts WHERE incident_id = 1")
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM incident_entities WHERE incident_id = 1")
            assert cur.fetchone()[0] == 0
            cur.execute("SELECT COUNT(*) FROM incident_relationships WHERE incident_id = 1")
            assert cur.fetchone()[0] == 0

            # Alert itself should still exist
            cur.execute("SELECT COUNT(*) FROM alerts WHERE id = 10")
            assert cur.fetchone()[0] == 1
        test_db.close()


def test_entity_and_relationship_constraints():
    """Verify CHECK and UNIQUE constraints on incident_entities and incident_relationships."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "graph_constraints.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            conn.execute(
                """
                INSERT INTO incidents (id, incident_key, title, summary, severity, primary_host, first_seen, last_seen)
                VALUES (1, 'inc-1', 'Inc 1', 'desc', 'CRITICAL', 'host-1', '2026-01-01', '2026-01-01')
                """
            )

            # 1. Invalid entity_type
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name)
                    VALUES (1, 'bad:1', 'UNKNOWN_TYPE', 'bad')
                    """
                )

            # 2. Duplicate entity_key for same incident
            conn.execute(
                """
                INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name)
                VALUES (1, 'host:srv1', 'HOST', 'srv1')
                """
            )
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incident_entities (incident_id, entity_key, entity_type, display_name)
                    VALUES (1, 'host:srv1', 'HOST', 'srv1 duplicate')
                    """
                )

            # 3. Invalid relationship_type
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incident_relationships (
                        incident_id, source_entity_key, target_entity_key, relationship_type, confidence
                    ) VALUES (
                        1, 'host:srv1', 'ip:1.1.1.1', 'TELEPORTED_TO', 'DIRECT'
                    )
                    """
                )

            # 4. Invalid confidence
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    """
                    INSERT INTO incident_relationships (
                        incident_id, source_entity_key, target_entity_key, relationship_type, confidence
                    ) VALUES (
                        1, 'host:srv1', 'ip:1.1.1.1', 'CONNECTED_TO', 'MAYBE'
                    )
                    """
                )
        test_db.close()


def test_correlation_indexes_query_plans():
    """Verify that composite indexes on events table are utilized by SQLite query planner."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "query_plan.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()

            # Query by host and timestamp
            cur.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM events WHERE host = 'srv-alpha' ORDER BY timestamp DESC"
            )
            plan = [r[3] for r in cur.fetchall()]
            assert any("idx_events_host_time" in step for step in plan), f"Host time index not used: {plan}"

            # Query by username and timestamp
            cur.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM events WHERE username = 'alice' ORDER BY timestamp DESC"
            )
            plan = [r[3] for r in cur.fetchall()]
            assert any("idx_events_user_time" in step for step in plan), f"User time index not used: {plan}"

            # Query by src_ip and timestamp
            cur.execute(
                "EXPLAIN QUERY PLAN SELECT * FROM events WHERE src_ip = '10.0.0.1' ORDER BY timestamp DESC"
            )
            plan = [r[3] for r in cur.fetchall()]
            assert any("idx_events_src_ip_time" in step for step in plan), f"Src IP time index not used: {plan}"
        test_db.close()
