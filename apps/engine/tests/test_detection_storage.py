"""Tests for M2.2 Detection Database Model, Migration 3, and Foreign Key Integrity."""

import sqlite3
import tempfile
from pathlib import Path
import pytest

from logintel.models import Actor, CanonicalEvent, EventType, Outcome, Severity
from logintel.storage.db import Database
from logintel.storage.events_repo import EventsRepository
from logintel.storage.migrations import MIGRATIONS, apply_migrations


def test_fresh_database_migration():
    """Verify that applying migrations to a fresh database creates version 3 with all tables."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "fresh.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()
            # 1. Version check
            cur.execute("SELECT MAX(version) FROM schema_migrations")
            assert cur.fetchone()[0] >= 3

            # 2. Table existence check
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
            }
            assert expected_tables.issubset(tables)

            # 3. Verify indexes exist
            cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
            indexes = {r[0] for r in cur.fetchall()}
            expected_indexes = {
                "idx_alerts_status_last_seen",
                "idx_alerts_rule_id",
                "idx_alerts_host",
                "idx_alerts_last_seen",
                "idx_detections_alert_id",
                "idx_detections_rule_id",
                "idx_detections_timestamp",
                "idx_detections_host",
                "idx_detection_evidence_detection_id",
                "idx_detection_evidence_event_id",
            }
            assert expected_indexes.issubset(indexes)
        test_db.close()


def test_m1_1_upgrade_migration():
    """Verify that an M1.1 database upgraded to Migration 3 preserves all existing events."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "upgrade.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute("PRAGMA foreign_keys = ON;")

        # Apply only Migrations 1 and 2 manually
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
            );
            """
        )
        for v, name, sql in MIGRATIONS[:2]:
            cur.executescript(sql)
            cur.execute("INSERT INTO schema_migrations (version, name) VALUES (?, ?)", (v, name))
        conn.commit()

        # Insert 3 representative canonical events
        for i in range(3):
            ev_id = f"m11-event-{i}"
            cur.execute(
                """
                INSERT INTO events (
                    id, timestamp, ingested_at, host, source, event_type, severity,
                    action, outcome, summary, raw_message, parser, event_fingerprint
                ) VALUES (?, datetime('now', 'utc'), datetime('now', 'utc'), 'srv-1', 'auth.log',
                          'AUTH_LOGIN_FAILURE', 'ALERT', 'LOGIN', 'FAILURE', 'Login fail',
                          'raw fail line', 'openssh', ?)
                """,
                (ev_id, f"fp-{i}"),
            )
        conn.commit()
        conn.close()

        # Now open via Database and initialize (which applies Migration 3)
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT MAX(version) FROM schema_migrations")
            assert cur.fetchone()[0] >= 3

            cur.execute("SELECT COUNT(*) FROM events")
            assert cur.fetchone()[0] == 3

            cur.execute("SELECT id, event_fingerprint FROM events ORDER BY id")
            rows = cur.fetchall()
            assert rows[0][0] == "m11-event-0"
            assert rows[0][1] == "fp-0"
        test_db.close()


def test_evidence_protection_restrict():
    """Mandatory Test: Verifies that an event cited in detection_evidence cannot be deleted (ON DELETE RESTRICT)."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "evidence_protect.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()

            # 1. Insert Event
            event_id = "ev-protect-1"
            cur.execute(
                """
                INSERT INTO events (
                    id, timestamp, ingested_at, host, source, event_type, severity,
                    outcome, summary, raw_message, parser
                ) VALUES (?, datetime('now', 'utc'), datetime('now', 'utc'), 'srv-1', 'auth.log',
                          'AUTH_LOGIN_FAILURE', 'ALERT', 'FAILURE', 'Test summary', 'raw message', 'openssh')
                """,
                (event_id,),
            )

            # 2. Insert Rule
            rule_id = "auth.test_rule"
            cur.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES (?, 'Test Rule', 'Desc', 'ALERT', 'AUTH', 'ATOMIC', 'yaml: content')
                """,
                (rule_id,),
            )

            # 3. Insert Alert
            cur.execute(
                """
                INSERT INTO alerts (rule_id, dedup_key, title, description, severity, host, first_seen, last_seen)
                VALUES (?, 'dedup:key:protect', 'Alert 1', 'Desc', 'ALERT', 'srv-1', datetime('now', 'utc'), datetime('now', 'utc'))
                """,
                (rule_id,),
            )
            alert_id = cur.lastrowid

            # 4. Insert Detection
            cur.execute(
                """
                INSERT INTO detections (alert_id, rule_id, timestamp, host, summary, evidence_count)
                VALUES (?, ?, datetime('now', 'utc'), 'srv-1', 'Det summary', 1)
                """,
                (alert_id, rule_id),
            )
            detection_id = cur.lastrowid

            # 5. Insert Evidence referencing event
            cur.execute(
                """
                INSERT INTO detection_evidence (detection_id, event_id, role)
                VALUES (?, ?, 'TRIGGER')
                """,
                (detection_id, event_id),
            )
            conn.commit()

            # 6. Attempt to delete event -> MUST FAIL WITH FOREIGN KEY RESTRICT
            with pytest.raises(sqlite3.IntegrityError) as exc_info:
                cur.execute("DELETE FROM events WHERE id = ?", (event_id,))
                conn.commit()
            assert "FOREIGN KEY constraint failed" in str(exc_info.value)

            # 7. Verify the event and evidence were NOT modified or corrupted
            cur.execute("SELECT COUNT(*) FROM events WHERE id = ?", (event_id,))
            assert cur.fetchone()[0] == 1
            cur.execute("SELECT COUNT(*) FROM detection_evidence WHERE event_id = ?", (event_id,))
            assert cur.fetchone()[0] == 1
        test_db.close()


def test_detection_cascade_to_evidence():
    """Verify that deleting a detection cascades to its evidence rows without deleting the canonical event."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "cascade.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()

            event_id = "ev-cascade-1"
            cur.execute(
                """
                INSERT INTO events (
                    id, timestamp, ingested_at, host, source, event_type, severity,
                    outcome, summary, raw_message, parser
                ) VALUES (?, datetime('now', 'utc'), datetime('now', 'utc'), 'srv-1', 'auth.log',
                          'AUTH_LOGIN_FAILURE', 'ALERT', 'FAILURE', 'Test summary', 'raw message', 'openssh')
                """,
                (event_id,),
            )

            rule_id = "auth.cascade_rule"
            cur.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES (?, 'Cascade Rule', 'Desc', 'ALERT', 'AUTH', 'ATOMIC', 'yaml: content')
                """,
                (rule_id,),
            )

            cur.execute(
                """
                INSERT INTO alerts (rule_id, dedup_key, title, description, severity, host, first_seen, last_seen)
                VALUES (?, 'dedup:key:cascade', 'Alert 1', 'Desc', 'ALERT', 'srv-1', datetime('now', 'utc'), datetime('now', 'utc'))
                """,
                (rule_id,),
            )
            alert_id = cur.lastrowid

            cur.execute(
                """
                INSERT INTO detections (alert_id, rule_id, timestamp, host, summary, evidence_count)
                VALUES (?, ?, datetime('now', 'utc'), 'srv-1', 'Det summary', 1)
                """,
                (alert_id, rule_id),
            )
            detection_id = cur.lastrowid

            cur.execute(
                """
                INSERT INTO detection_evidence (detection_id, event_id, role)
                VALUES (?, ?, 'TRIGGER')
                """,
                (detection_id, event_id),
            )
            evidence_id = cur.lastrowid
            conn.commit()

            # Delete the detection
            cur.execute("DELETE FROM detections WHERE id = ?", (detection_id,))
            conn.commit()

            # Evidence row should be deleted via ON DELETE CASCADE
            cur.execute("SELECT COUNT(*) FROM detection_evidence WHERE id = ?", (evidence_id,))
            assert cur.fetchone()[0] == 0

            # Canonical event MUST remain intact
            cur.execute("SELECT COUNT(*) FROM events WHERE id = ?", (event_id,))
            assert cur.fetchone()[0] == 1
        test_db.close()


def test_alert_dedup_key_uniqueness():
    """Verify that duplicate alert dedup_keys are rejected by SQLite unique constraint."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "dedup_key.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()

            rule_id = "auth.dedup_rule"
            cur.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES (?, 'Rule', 'Desc', 'ALERT', 'AUTH', 'ATOMIC', 'yaml: content')
                """,
                (rule_id,),
            )

            cur.execute(
                """
                INSERT INTO alerts (rule_id, dedup_key, title, description, severity, host, first_seen, last_seen)
                VALUES (?, 'dedup:unique:123', 'Alert 1', 'Desc', 'ALERT', 'srv-1', datetime('now', 'utc'), datetime('now', 'utc'))
                """,
                (rule_id,),
            )
            conn.commit()

            # Attempt to insert identical dedup_key -> MUST FAIL
            with pytest.raises(sqlite3.IntegrityError) as exc_info:
                cur.execute(
                    """
                    INSERT INTO alerts (rule_id, dedup_key, title, description, severity, host, first_seen, last_seen)
                    VALUES (?, 'dedup:unique:123', 'Alert 2', 'Desc', 'ALERT', 'srv-1', datetime('now', 'utc'), datetime('now', 'utc'))
                    """,
                    (rule_id,),
                )
                conn.commit()
            assert "UNIQUE constraint failed: alerts.dedup_key" in str(exc_info.value)
        test_db.close()


def test_rule_deletion_restricted():
    """Verify that a rule referenced by alerts or detections cannot be deleted (ON DELETE RESTRICT)."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "rule_restrict.db"
        test_db = Database(db_path)
        test_db.initialize()

        with test_db.connection() as conn:
            cur = conn.cursor()

            rule_id = "auth.rule_restrict"
            cur.execute(
                """
                INSERT INTO detection_rules (id, name, description, severity, category, rule_type, definition_yaml)
                VALUES (?, 'Rule', 'Desc', 'ALERT', 'AUTH', 'ATOMIC', 'yaml: content')
                """,
                (rule_id,),
            )

            cur.execute(
                """
                INSERT INTO alerts (rule_id, dedup_key, title, description, severity, host, first_seen, last_seen)
                VALUES (?, 'dedup:key:rule_test', 'Alert', 'Desc', 'ALERT', 'srv-1', datetime('now', 'utc'), datetime('now', 'utc'))
                """,
                (rule_id,),
            )
            conn.commit()

            with pytest.raises(sqlite3.IntegrityError) as exc_info:
                cur.execute("DELETE FROM detection_rules WHERE id = ?", (rule_id,))
                conn.commit()
            assert "FOREIGN KEY constraint failed" in str(exc_info.value)
        test_db.close()


def test_migration_atomicity_on_failure():
    """Verify that a failure during migration rolls back cleanly without leaving partial tables."""
    with tempfile.TemporaryDirectory() as td:
        db_path = Path(td) / "atomic_fail.db"
        conn = sqlite3.connect(str(db_path))

        # Initialize schema_migrations table
        conn.execute(
            """
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
            );
            """
        )
        conn.commit()

        # Attempt to apply a mock migration that fails halfway through
        bad_migration_sql = """
        CREATE TABLE temp_table_ok (id INT PRIMARY KEY);
        CREATE TABLE temp_table_broken (id INT, SYNTAX ERROR HERE ((( );
        """
        old_isolation = conn.isolation_level
        conn.isolation_level = None
        try:
            conn.execute("BEGIN IMMEDIATE;")
            for stmt in [s.strip() for s in bad_migration_sql.split(";") if s.strip()]:
                conn.execute(stmt)
            conn.execute("INSERT INTO schema_migrations (version, name) VALUES (99, 'bad_migration')")
            conn.execute("COMMIT;")
        except Exception:
            conn.execute("ROLLBACK;")
        finally:
            conn.isolation_level = old_isolation

        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name != 'schema_migrations'")
        tables = cur.fetchall()
        assert len(tables) == 0, "Partial table was left behind after failed migration!"

        cur.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = 99")
        assert cur.fetchone()[0] == 0
        conn.close()
