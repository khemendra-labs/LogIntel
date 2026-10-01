# LOGINTEL — MILESTONE M3.2 FORENSIC REPORT

## Schema Migration 4: Incident Correlation & Attack Graph Modeling

**Repository:** `/home/khemendra-labs/LogIntel`  
**Milestone:** M3.2  
**Previous Gate:** M3.1 VERIFIED — Incident Domain Models  
**Schema Transition:** Version 3 -> Version 4  
**Date:** 2026-09-30  
**Status:** M3.2 VERIFIED — READY FOR M3.3  

---

# 1. Executive Summary

Milestone M3.2 formally transitions the LogIntel relational storage layer from **Schema Version 3** to **Schema Version 4** by implementing database Migration 4: `m3_incident_correlation_and_graph`.

This migration establishes the persistent relational foundation for:
1. **Aggregated Multi-Alert Incidents** (`incidents` table)
2. **Alert-to-Incident Association** (`incident_alerts` table)
3. **Attack Graph Entities / Nodes** (`incident_entities` table)
4. **Attack Graph Directed Relationships / Edges** (`incident_relationships` table)
5. **High-Performance Compound Indexes** across incident status, time, entities, and correlation queries on canonical events.

All changes strictly adhere to local-first SQLite WAL semantics, enforce foreign-key cascading and restriction rules, and preserve 100% of existing M1 and M2 data without requiring full table rewrites or external dependencies.

---

# 2. Schema Migration 4 Specification

Migration 4 is declared in [`apps/engine/src/logintel/storage/migrations.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/storage/migrations.py) as tuple `(4, "m3_incident_correlation_and_graph", <sql>)`.

### 2.1 Table: `incidents`
Tracks correlated security incidents aggregating one or more operational alerts into a unified case.

```sql
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
```

### 2.2 Table: `incident_alerts`
Maintains relational mapping linking alerts to incidents.

```sql
CREATE TABLE IF NOT EXISTS incident_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE RESTRICT,
    added_at TEXT NOT NULL DEFAULT (datetime('now', 'utc')),
    UNIQUE (incident_id, alert_id)
);
```
- **Integrity Rule:** `ON DELETE CASCADE` ensures that removing an incident removes the linking association.
- **Protection Rule:** `ON DELETE RESTRICT` on `alert_id` guarantees that an alert cannot be deleted while linked to an active incident investigation.

### 2.3 Table: `incident_entities`
Stores attack graph nodes extracted from correlated events and alerts.

```sql
CREATE TABLE IF NOT EXISTS incident_entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    entity_key TEXT NOT NULL,
    entity_type TEXT NOT NULL CHECK (entity_type IN ('HOST', 'USER', 'IP', 'PROCESS', 'COMMAND', 'FILE', 'SESSION')),
    display_name TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (incident_id, entity_key)
);
```

### 2.4 Table: `incident_relationships`
Stores directed attack graph edges linking correlated entities with explicit confidence levels and event evidence chains.

```sql
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
```

### 2.5 Query Performance Indexes
Migration 4 establishes 14 performance indexes:

1. **Incident Triage:**
   - `idx_incidents_status_last_seen` (`status`, `last_seen DESC`)
   - `idx_incidents_severity` (`severity`, `last_seen DESC`)
   - `idx_incidents_primary_host` (`primary_host`)
   - `idx_incidents_primary_user` (`primary_user`)
   - `idx_incidents_last_seen` (`last_seen DESC`)
2. **Alert Association:**
   - `idx_incident_alerts_incident_id` (`incident_id`)
   - `idx_incident_alerts_alert_id` (`alert_id`)
3. **Graph Traversal:**
   - `idx_incident_entities_incident` (`incident_id`)
   - `idx_incident_entities_key` (`entity_key`)
   - `idx_incident_entities_type` (`entity_type`)
   - `idx_incident_relationships_incident` (`incident_id`)
   - `idx_incident_relationships_source` (`source_entity_key`)
   - `idx_incident_relationships_target` (`target_entity_key`)
   - `idx_incident_relationships_type` (`relationship_type`)
4. **Canonical Event Correlation Acceleration:**
   - `idx_events_host_time` (`host`, `timestamp DESC`)
   - `idx_events_user_time` (`username`, `timestamp DESC`)
   - `idx_events_src_ip_time` (`src_ip`, `timestamp DESC`)

---

# 3. Verification & Test Suite

Dedicated test suite: [`apps/engine/tests/test_migration_4.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_migration_4.py).

### 3.1 Test Matrix

| Test Name | Focus | Result |
|---|---|---|
| `test_fresh_migration_to_v4` | Fresh database creation, migration version 4, all 13 tables and M3 indexes | **PASSED** |
| `test_upgrade_from_v3_to_v4_preserves_data` | Upgrade v3 DB with M1/M2 data, verify data preservation, verify v4 readiness | **PASSED** |
| `test_migration_idempotency` | Multiple consecutive executions of `apply_migrations` without failure | **PASSED** |
| `test_incident_table_check_constraints` | Validation checks for severity, status, negative counts, unique keys | **PASSED** |
| `test_foreign_key_cascade_and_restrict` | Cascade delete on incident, restrict delete on referenced alert | **PASSED** |
| `test_entity_and_relationship_constraints` | Entity type checks, unique keys per incident, relationship checks | **PASSED** |
| `test_correlation_indexes_query_plans` | SQLite `EXPLAIN QUERY PLAN` verifying compound indexes on `events` | **PASSED** |

### 3.2 Regression Verification

- **Engine Test Suite:** 197 / 197 passed (`pytest apps/engine/tests/`)
- **Desktop Vitest Suite:** 10 / 10 passed (`vitest run`)
- **Desktop TypeScript Check:** 0 errors (`tsc --noEmit`)
- **Live Local DB Upgrade:** Verified at `~/.local/share/logintel/logintel.db` (Schema Version: `4`).

---

# 4. Milestone M3 Progress & Next Gate

- **M3.0 (Architecture Audit):** **VERIFIED**
- **M3.1 (Domain Models):** **VERIFIED**
- **M3.2 (Schema Migration 4):** **VERIFIED**
- **M3.3 (Incident Storage Repository):** **NEXT** (Implement `incidents_repo.py` with CRUD, transaction handling, alert linking, and graph queries).
