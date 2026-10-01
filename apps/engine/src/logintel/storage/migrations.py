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
    ),
    (
        4,
        "m3_incident_correlation_and_graph",
        """
        -- Incidents table
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_key TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('CRITICAL', 'ALERT', 'WARNING', 'NOTICE', 'INFORMATIONAL', 'DEBUG')),
            status TEXT NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE', 'CLOSED')),
            primary_host TEXT NOT NULL,
            primary_user TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            alert_count INTEGER NOT NULL DEFAULT 0 CHECK (alert_count >= 0),
            event_count INTEGER NOT NULL DEFAULT 0 CHECK (event_count >= 0),
            created_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
            updated_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
            resolved_at TEXT,
            resolution_note TEXT
        );

        -- Incident alerts association table
        CREATE TABLE IF NOT EXISTS incident_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE RESTRICT,
            added_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
            UNIQUE (incident_id, alert_id)
        );

        -- Incident entities table (attack graph nodes)
        CREATE TABLE IF NOT EXISTS incident_entities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            entity_key TEXT NOT NULL,
            entity_type TEXT NOT NULL CHECK (entity_type IN ('HOST', 'USER', 'IP', 'PROCESS', 'COMMAND', 'FILE', 'SESSION')),
            display_name TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            UNIQUE (incident_id, entity_key)
        );

        -- Incident relationships table (attack graph directed edges)
        CREATE TABLE IF NOT EXISTS incident_relationships (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            source_entity_key TEXT NOT NULL,
            target_entity_key TEXT NOT NULL,
            relationship_type TEXT NOT NULL CHECK (relationship_type IN ('AUTHENTICATED_TO', 'EXECUTED', 'SPAWNED', 'CONNECTED_TO', 'ACCESSED_FILE', 'LATERAL_MOVEMENT', 'CO_OCCURRED')),
            confidence TEXT NOT NULL CHECK (confidence IN ('DIRECT', 'STRONG', 'CORRELATED', 'INFERRED', 'WEAK')),
            evidence_event_ids_json TEXT NOT NULL DEFAULT '[]',
            matched_at TEXT NOT NULL DEFAULT (datetime('now', 'utc'))
        );

        -- Performance indexes for incidents
        CREATE INDEX IF NOT EXISTS idx_incidents_status_last_seen ON incidents(status, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity, last_seen DESC);
        CREATE INDEX IF NOT EXISTS idx_incidents_primary_host ON incidents(primary_host);
        CREATE INDEX IF NOT EXISTS idx_incidents_primary_user ON incidents(primary_user);
        CREATE INDEX IF NOT EXISTS idx_incidents_last_seen ON incidents(last_seen DESC);

        -- Performance indexes for incident_alerts
        CREATE INDEX IF NOT EXISTS idx_incident_alerts_incident_id ON incident_alerts(incident_id);
        CREATE INDEX IF NOT EXISTS idx_incident_alerts_alert_id ON incident_alerts(alert_id);

        -- Performance indexes for incident_entities
        CREATE INDEX IF NOT EXISTS idx_incident_entities_incident ON incident_entities(incident_id);
        CREATE INDEX IF NOT EXISTS idx_incident_entities_key ON incident_entities(entity_key);
        CREATE INDEX IF NOT EXISTS idx_incident_entities_type ON incident_entities(entity_type);

        -- Performance indexes for incident_relationships
        CREATE INDEX IF NOT EXISTS idx_incident_relationships_incident ON incident_relationships(incident_id);
        CREATE INDEX IF NOT EXISTS idx_incident_relationships_source ON incident_relationships(source_entity_key);
        CREATE INDEX IF NOT EXISTS idx_incident_relationships_target ON incident_relationships(target_entity_key);
        CREATE INDEX IF NOT EXISTS idx_incident_relationships_type ON incident_relationships(relationship_type);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_relationships_unique ON incident_relationships(incident_id, source_entity_key, target_entity_key, relationship_type);

        -- Correlation query accelerating indexes on canonical events
        CREATE INDEX IF NOT EXISTS idx_events_host_time ON events(host, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_user_time ON events(username, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_src_ip_time ON events(src_ip, timestamp DESC);
        """
    ),
    (
        5,
        "m4_investigation_workspace_and_notes",
        """
        -- Investigation analyst notes and annotations
        CREATE TABLE IF NOT EXISTS investigation_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
            author TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            target_type TEXT NOT NULL DEFAULT 'incident' CHECK (target_type IN ('incident', 'event', 'entity', 'alert')),
            target_id TEXT,
            is_deleted INTEGER NOT NULL DEFAULT 0,
            deleted_at TEXT,
            deleted_by TEXT,
            deletion_reason TEXT
        );

        -- Investigation notes immutable audit log
        CREATE TABLE IF NOT EXISTS investigation_notes_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            note_id INTEGER NOT NULL,
            incident_id INTEGER NOT NULL,
            action TEXT NOT NULL CHECK (action IN ('CREATED', 'UPDATED', 'DELETED')),
            actor TEXT NOT NULL,
            content TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT,
            created_at TEXT NOT NULL,
            action_timestamp TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
            reason TEXT
        );

        -- Performance indexes for notes queries
        CREATE INDEX IF NOT EXISTS idx_investigation_notes_incident ON investigation_notes(incident_id);
        CREATE INDEX IF NOT EXISTS idx_investigation_notes_created ON investigation_notes(created_at);
        CREATE INDEX IF NOT EXISTS idx_investigation_notes_target ON investigation_notes(target_type, target_id);
        CREATE INDEX IF NOT EXISTS idx_investigation_notes_audit_incident ON investigation_notes_audit(incident_id);
        CREATE INDEX IF NOT EXISTS idx_investigation_notes_audit_note ON investigation_notes_audit(note_id);

        -- Threat hunting query accelerating indexes on canonical events
        CREATE INDEX IF NOT EXISTS idx_events_search_composite ON events(timestamp DESC, event_type, host);
        CREATE INDEX IF NOT EXISTS idx_events_process_time ON events(process_name, timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_lower_host ON events(LOWER(host), timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_upper_event_type ON events(UPPER(event_type), timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_upper_outcome ON events(UPPER(outcome), timestamp DESC);
        CREATE INDEX IF NOT EXISTS idx_events_lower_user ON events(LOWER(username), timestamp DESC);
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

    # Ensure idempotency of M3 relationship uniqueness index on existing databases
    if 4 in applied_versions:
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_incident_relationships_unique "
            "ON incident_relationships(incident_id, source_entity_key, target_entity_key, relationship_type);"
        )
        conn.commit()

    # Ensure idempotency of M4 notes audit table, tombstone columns, and expression indexes on existing databases
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='investigation_notes';")
    if cursor.fetchone():
        cursor.execute("PRAGMA table_info(investigation_notes);")
        existing_cols = {row[1] for row in cursor.fetchall()}
        if "is_deleted" not in existing_cols:
            cursor.execute("ALTER TABLE investigation_notes ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0;")
        if "deleted_at" not in existing_cols:
            cursor.execute("ALTER TABLE investigation_notes ADD COLUMN deleted_at TEXT;")
        if "deleted_by" not in existing_cols:
            cursor.execute("ALTER TABLE investigation_notes ADD COLUMN deleted_by TEXT;")
        if "deletion_reason" not in existing_cols:
            cursor.execute("ALTER TABLE investigation_notes ADD COLUMN deletion_reason TEXT;")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS investigation_notes_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                note_id INTEGER NOT NULL,
                incident_id INTEGER NOT NULL,
                action TEXT NOT NULL CHECK (action IN ('CREATED', 'UPDATED', 'DELETED')),
                actor TEXT NOT NULL,
                content TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                created_at TEXT NOT NULL,
                action_timestamp TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
                reason TEXT
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigation_notes_audit_incident ON investigation_notes_audit(incident_id);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigation_notes_audit_note ON investigation_notes_audit(note_id);")

        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_lower_host ON events(LOWER(host), timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_upper_event_type ON events(UPPER(event_type), timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_upper_outcome ON events(UPPER(outcome), timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_lower_user ON events(LOWER(username), timestamp DESC);")
        conn.commit()

