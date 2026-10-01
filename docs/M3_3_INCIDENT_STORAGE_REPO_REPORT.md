# LOGINTEL — MILESTONE M3.3 FORENSIC REPORT

## Incident Storage Repository & Graph Data Access Layer

**Repository:** `/home/khemendra-labs/LogIntel`  
**Milestone:** M3.3  
**Previous Gate:** M3.2 VERIFIED — Schema Migration 4  
**Module:** `apps/engine/src/logintel/storage/incidents_repo.py`  
**Date:** 2026-09-30  
**Status:** M3.3 VERIFIED — READY FOR M3.4  

---

# 1. Executive Summary

Milestone M3.3 implements the **Incident Storage Repository** ([`apps/engine/src/logintel/storage/incidents_repo.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/storage/incidents_repo.py)) and exposes `IncidentsRepository` and singleton `incidents_repo` via [`apps/engine/src/logintel/storage/__init__.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/storage/__init__.py).

This repository layer provides full lifecycle, transactional, and traversal access to:
1. **Incident Case Records** (`incidents` table) with lifecycle state transitions and audit timestamps.
2. **Alert Aggregation & Relational Mapping** (`incident_alerts` table) with metric synchronization (`alert_count`, `event_count`, `first_seen`, `last_seen`).
3. **Attack Graph Entities** (`incident_entities` table) supporting node upsertion, metadata persistence, and entity-type filtering.
4. **Attack Graph Directed Relationships** (`incident_relationships` table) with confidence assessment and underlying event evidence chains.
5. **Attack Graph Traversal Payloads** formatted for visualization engines.
6. **Chronological Investigation Timelines** combining alerts, underlying telemetry events, and graph discovery milestones with deterministic tie-breaking.
7. **Full Investigation Workspace Aggregation** providing structured payloads for analyst triage and API endpoints.

---

# 2. Architecture & Design Principles

### 2.1 Transactional Isolation & WAL Concurrency
- Uses `BEGIN IMMEDIATE;` transactions to eliminate SQLite write deadlocks and ensure atomic multi-table mutations across `incidents`, `incident_alerts`, `incident_entities`, and `incident_relationships`.
- Thread safety is guaranteed via `threading.RLock()`.
- Rollback semantics ensure that failure to link alerts or graph entities leaves zero partial records in the database.

### 2.2 Alert Metric Synchronization
When operational alerts are added to or removed from an incident via `add_alerts_to_incident` or `remove_alert_from_incident`:
- `alert_count` is recomputed from the live link table.
- `first_seen` and `last_seen` are synchronized from the min/max timestamps of associated alerts.
- `event_count` is recalculated from the distinct set of underlying canonical events linked through `detection_evidence` and `detections`.
- `updated_at` is touched to track modification times.

### 2.3 Incident Lifecycle State Machine Enforcement
Transitions are validated against `ALLOWED_INCIDENT_STATUS_TRANSITIONS`:
- State machine prohibits illegal leaps (e.g. `OPEN` directly to `CLOSED`).
- Transitions to resolution states (`RESOLVED`, `FALSE_POSITIVE`, `CLOSED`) populate `resolved_at` and `resolution_note`.
- Reopening to `OPEN` clears `resolved_at` and `resolution_note`.

### 2.4 Attack Graph & Timeline Integration
- `get_attack_graph(incident_id)` outputs a standard graph schema (`nodes` and `edges`) suitable for D3/Cytoscape frontend rendering.
- `get_incident_timeline(incident_id)` merges `ALERT`, `EVENT`, and `MILESTONE` items into a strictly non-decreasing chronological stream using `sort_key()` (timestamp ASC, id ASC).

---

# 3. Repository Method Inventory

| Category | Method | Description |
|---|---|---|
| **Incident CRUD** | `create_incident(...)` | Atomically creates incident with optional alerts, entities, and relationships |
| | `get_incident(id)` | Retrieves incident domain model by primary key |
| | `get_incident_by_key(key)` | Retrieves incident domain model by deterministic key |
| | `list_incidents(...)` | Queries incidents with status, severity, host, and user filtering, sorted by `last_seen DESC` |
| | `count_incidents(...)` | Counts matching incidents for pagination |
| | `update_incident_status(...)` | Validates and updates status; updates `resolved_at` / `resolution_note` |
| | `delete_incident(id)` | Deletes incident; cascades to links and graph data, leaves underlying alerts intact |
| **Alert Association** | `add_alerts_to_incident(id, alert_ids)` | Links alerts and resyncs metrics (`alert_count`, `event_count`, `first_seen`, `last_seen`) |
| | `remove_alert_from_incident(id, alert_id)` | Unlinks an alert and resyncs metrics |
| | `get_incident_alerts(id)` | Fetches all operational `Alert` records linked to the incident |
| | `get_incident_alert_ids(id)` | Fetches integer IDs of linked alerts |
| **Attack Graph** | `add_entities(id, entities)` | Upserts incident entities (updates display name and metadata on key collision) |
| | `get_incident_entities(id, entity_type)` | Retrieves incident entities, optionally filtered by `EntityType` |
| | `add_relationships(id, rels)` | Persists directed relationships with confidence and evidence event IDs |
| | `get_incident_relationships(id, rel_type)` | Retrieves relationships, optionally filtered by relationship type |
| | `get_attack_graph(id)` | Returns graph payload with `nodes` and `edges` for visualization |
| **Investigation** | `get_incident_timeline(id)` | Compiles chronologically sorted stream of alerts, evidence events, and milestones |
| | `get_incident_details(id)` | Aggregates incident, alerts, graph, and timeline into a unified investigation payload |

---

# 4. Test Verification Suite

Test Suite: [`apps/engine/tests/test_incidents_repo.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_incidents_repo.py)  
Total Suite Tests: **11 passed in 0.72s**

| Test Name | Focus | Result |
|---|---|---|
| `test_create_and_get_incident` | Incident creation, default fields, lookup by ID and key | **PASSED** |
| `test_create_incident_with_alerts_entities_and_relationships` | Atomic creation, metric derivation, entity/rel retrieval | **PASSED** |
| `test_list_and_count_incidents` | Filter by status, severity, host, user, pagination offset/limit | **PASSED** |
| `test_incident_status_transitions_valid` | Full lifecycle transition (OPEN -> INVESTIGATING -> CONTAINED -> RESOLVED -> CLOSED -> OPEN) | **PASSED** |
| `test_incident_status_transitions_invalid` | Rejection of illegal transitions with `InvalidIncidentStatusTransitionError` | **PASSED** |
| `test_add_and_remove_alerts` | Dynamic linking and unlinking of alerts, metric recalculation | **PASSED** |
| `test_entities_upsert_and_filtering` | Upsert existing entity, filter entities by type (`USER`, `HOST`) | **PASSED** |
| `test_relationships_and_attack_graph_format` | Graph formation (`nodes`, `edges`), properties, confidence | **PASSED** |
| `test_incident_timeline_chronological_ordering` | Timeline aggregation and deterministic sorting | **PASSED** |
| `test_get_incident_details_workspace_payload` | Unified investigation payload for frontend/API | **PASSED** |
| `test_delete_incident_cascade` | Cascade deletion of incident associations while preserving alerts | **PASSED** |

---

# 5. Full Regression Status

- **Engine Test Suite:** **208 passed** (0 failures, 1 warning)
- **Desktop Vitest Suite:** **10 passed** (0 failures)
- **Desktop TypeScript:** **0 errors**

---

# 6. Milestone Progress & Next Gate

- **M3.0 (Architecture Audit):** **VERIFIED**
- **M3.1 (Domain Models):** **VERIFIED**
- **M3.2 (Schema Migration 4):** **VERIFIED**
- **M3.3 (Incident Storage Repository):** **VERIFIED**
- **M3.4 (Incident Correlation Engine):** **NEXT** (Implement `IncidentCorrelationEngine` aggregating alerts by time-window, host/entity affinity, and cross-rule multi-stage attack scenarios).
