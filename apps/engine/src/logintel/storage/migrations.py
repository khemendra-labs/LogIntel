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
    )
]


def apply_migrations(conn: sqlite3.Connection) -> None:
    """Ensure the schema_migrations table exists and apply all pending migrations."""
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
            cursor.executescript(sql)
            cursor.execute(
                "INSERT INTO schema_migrations (version, name) VALUES (?, ?)",
                (version, name),
            )
            conn.commit()
            logger.info("Applied migration %d successfully", version)
