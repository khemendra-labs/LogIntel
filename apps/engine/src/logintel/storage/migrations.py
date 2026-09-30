"""SQLite schema migrations management for LogIntel."""

from __future__ import annotations

import sqlite3
from typing import List, Tuple
from logintel.logging import get_logger

logger = get_logger("storage.migrations")

# (migration_version, name, sql_statement)
MIGRATIONS: List[Tuple[int, str, str]] = [
    (
        1,
        "initial_canonical_schema",
        """
        -- Hosts table
        CREATE TABLE IF NOT EXISTS hosts (
            id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL UNIQUE,
            os_name TEXT,
            os_version TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL
        );

        -- Telemetry sources metadata
        CREATE TABLE IF NOT EXISTS sources (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            source_type TEXT NOT NULL,
            path TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        -- Ingestion state tracking (offsets, cursors, timestamps)
        CREATE TABLE IF NOT EXISTS ingestion_state (
            source_name TEXT PRIMARY KEY,
            cursor TEXT,
            byte_offset INTEGER DEFAULT 0,
            last_ingested_timestamp TEXT,
            last_run_at TEXT NOT NULL,
            total_records_ingested INTEGER DEFAULT 0,
            error_count INTEGER DEFAULT 0,
            last_error TEXT
        );

        -- Canonical events table
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            timestamp TEXT NOT NULL,
            ingested_at TEXT NOT NULL,
            host TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            username TEXT,
            uid INTEGER,
            session_id TEXT,
            terminal TEXT,
            process_name TEXT,
            process_pid INTEGER,
            process_ppid INTEGER,
            process_executable TEXT,
            process_command_line TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dst_ip TEXT,
            dst_port INTEGER,
            protocol TEXT,
            action TEXT,
            outcome TEXT NOT NULL,
            summary TEXT NOT NULL,
            raw_message TEXT NOT NULL,
            iocs_json TEXT NOT NULL DEFAULT '[]',
            parser TEXT NOT NULL,
            source_file TEXT,
            source_offset TEXT,
            metadata_json TEXT NOT NULL DEFAULT '{}'
        );

        -- Performance Indexes
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
        CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
        CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
        CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_dst_ip ON events(dst_ip);
        CREATE INDEX IF NOT EXISTS idx_events_process_name ON events(process_name);
        CREATE INDEX IF NOT EXISTS idx_events_outcome ON events(outcome);
        CREATE INDEX IF NOT EXISTS idx_events_compound_time_type ON events(timestamp DESC, event_type);
        """
    ),
    (
        2,
        "m1_1_hardening_fingerprint_and_indexes",
        """
        -- Add inode to ingestion_state for file tailing tracking across restarts
        ALTER TABLE ingestion_state ADD COLUMN inode INTEGER;

        -- Add event_fingerprint for idempotent ingestion and duplicate suppression
        ALTER TABLE events ADD COLUMN event_fingerprint TEXT;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_events_fingerprint ON events(event_fingerprint);

        -- Composite indexes for filtered queries (eliminates temporary B-trees)
        CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_severity_time ON events(severity, timestamp DESC);
        """
    ),
    (
        3,
        "m2_detection_and_alerts",
        """
        -- Detection rules catalog
        CREATE TABLE IF NOT EXISTS detection_rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            rule_type TEXT NOT NULL,
            definition_yaml TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
        );

        -- Operational alerts table
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL REFERENCES detection_rules(id) ON DELETE RESTRICT,
            dedup_key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE')),
            host TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            occurrence_count INTEGER NOT NULL DEFAULT 1 CHECK (occurrence_count >= 1),
            acknowledged_at TEXT,
            resolved_at TEXT,
            resolution_note TEXT
        );

        -- Detections table (occurrences/instances of rule matching)
        CREATE TABLE IF NOT EXISTS detections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
            rule_id TEXT NOT NULL REFERENCES detection_rules(id) ON DELETE RESTRICT,
            timestamp TEXT NOT NULL,
            host TEXT NOT NULL,
            summary TEXT NOT NULL,
            evidence_count INTEGER NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
            details_json TEXT NOT NULL DEFAULT '{}'
        );

        -- Detection evidence table linking detections to canonical events
        CREATE TABLE IF NOT EXISTS detection_evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detection_id INTEGER NOT NULL REFERENCES detections(id) ON DELETE CASCADE,
            event_id TEXT NOT NULL REFERENCES events(id) ON DELETE RESTRICT,
            role TEXT NOT NULL DEFAULT 'TRIGGER',
            matched_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
        );

        -- Performance indexes for alerts
        CREATE INDEX IF NOT EXISTS idx_alerts_status_last_seen ON alerts(status, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts(rule_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);
        CREATE INDEX IF NOT EXISTS idx_alerts_last_seen ON alerts(last_seen DESC);

        -- Performance indexes for detections
        CREATE INDEX IF NOT EXISTS idx_detections_alert_id ON detections(alert_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_detections_rule_id ON detections(rule_id, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_detections_timestamp ON detections(timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_detections_host ON detections(host);

        -- Performance indexes for detection_evidence
        CREATE INDEX IF NOT EXISTS idx_detection_evidence_detection_id ON detection_evidence(detection_id);
        CREATE INDEX IF NOT EXISTS idx_detection_evidence_event_id ON detection_evidence(event_id);
        """
    )
]


def apply_migrations(conn: sqlite3.Connection) -> None:
    """Ensure the schema_migrations table exists and apply all pending migrations atomically."""
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
        );
        """
    )
    conn.commit()

    cursor.execute("SELECT version FROM schema_migrations")
    applied_versions = {row[0] for row in cursor.fetchall()}

    for version, name, sql in MIGRATIONS:
        if version not in applied_versions:
            logger.info("Applying database migration %d: %s", version, name)
            old_isolation = conn.isolation_level
            conn.isolation_level = None
            try:
                conn.execute("BEGIN IMMEDIATE;")
                statements = [s.strip() for s in sql.split(";") if s.strip()]
                for stmt in statements:
                    conn.execute(stmt)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                    (version, name),
                )
                conn.execute("COMMIT;")
                logger.info("Applied migration %d successfully", version)
            except Exception as e:
                conn.execute("ROLLBACK;")
                logger.error("Failed to apply migration %d (%s): %s", version, name, e)
                raise
            finally:
                conn.isolation_level = old_isolation
