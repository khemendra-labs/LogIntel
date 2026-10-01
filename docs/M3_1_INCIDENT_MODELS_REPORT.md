# LogIntel — Milestone M3.1 Incident Domain Models Report

**Repository:** `/home/khemendra-labs/LogIntel`  
**Milestone:** M3.1 — Incident, Entity, Relationship, and Timeline Domain Models  
**Status:** **M3.1 VERIFIED — READY FOR M3.2**  
**Schema Version:** 3 (Unmodified — Migration 4 scheduled for M3.2)  
**Backend Tests:** **190 passed** (10 dedicated M3.1 tests, 0 regressions)  
**Frontend Tests:** **10 passed**  

---

## 1. Executive Summary

Milestone **M3.1** introduces the core domain models required for incident correlation, entity graph modeling, and unified investigation timelines without modifying the underlying SQLite schema. 

All domain models adhere to strict Pydantic v2 type validation, enforce finite-state machine lifecycle transitions for security incidents, define canonical entity taxonomies, and provide deterministic sorting guarantees for investigation timelines.

---

## 2. Implemented Domain Models

File: [`apps/engine/src/logintel/models/incidents.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/models/incidents.py)  
Exported via: [`apps/engine/src/logintel/models/__init__.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/models/__init__.py)

### 2.1 Incident Model (`Incident`)
- **Attributes:**
  - `id`: Optional primary key identifier.
  - `incident_key`: Unique human-readable key (e.g., `INC-20260930-001`).
  - `title`: Short descriptive title.
  - `summary`: Correlated activity description.
  - `severity`: Standard LogIntel `Severity` (`CRITICAL`, `ALERT`, `WARNING`, `NOTICE`).
  - `status`: Finite state machine `IncidentStatus` (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`, `CLOSED`).
  - `primary_host`: Core host boundary.
  - `primary_user`: Attributed user identity.
  - `first_seen`, `last_seen`: UTC timestamps bounding the activity window.
  - `alert_count`, `event_count`: Corroborating evidence metrics.
  - `created_at`, `updated_at`: UTC audit timestamps.
  - `resolved_at`, `resolution_note`: Formal closure metadata.

### 2.2 Incident Lifecycle State Machine
```text
           ┌──────────────────────────────────────────────┐
           │                     OPEN                     │◄───────────────────┐
           └───┬───────────────────┬──────────────────┬───┘                    │
               │                   │                  │                        │
               ▼                   ▼                  ▼                        │
       ┌───────────────┐   ┌───────────────┐  ┌────────────────┐               │
       │ INVESTIGATING │──►│   CONTAINED   │  │ FALSE_POSITIVE │               │
       └───┬───────────┘   └───────┬───────┘  └────────────────┘               │
           │                       │                  │                        │
           ▼                       ▼                  ▼                        │
       ┌───────────────────────────────────┐          │                        │ (reopen)
       │             RESOLVED              │──────────┴────────────────────────┘
       └─────────────────┬─────────────────┘
                         │
                         ▼
       ┌───────────────────────────────────┐
       │              CLOSED               │
       └───────────────────────────────────┘
```
- Implements `ALLOWED_INCIDENT_STATUS_TRANSITIONS`.
- Enforces strict transition validation via `InvalidIncidentStatusTransitionError`.
- Forbids direct invalid jumps (e.g. `CLOSED -> INVESTIGATING` without reopening to `OPEN`).

### 2.3 Normalized Entity Model (`IncidentEntity`)
- `entity_type`: Categorical `EntityType` (`HOST`, `USER`, `IP`, `PROCESS`, `COMMAND`, `FILE`, `SESSION`).
- `entity_key`: Normalized prefix-scoped key (`host:<name>`, `user:<username>`, `ip:<addr>`, etc.).
- `display_name`: Human-readable label for UI rendering.
- `metadata`: Flexible structured dictionary for OS details, PIDs, UIDs, and port metadata.

### 2.4 Incident Relationship Model (`IncidentRelationship`)
- Directed relationship connecting `source_entity_key` to `target_entity_key`.
- `relationship_type`: Semantic action (`AUTHENTICATED_TO`, `LOGGED_INTO`, `EXECUTED`, `SPAWNED`, `CONNECTED_TO`, `ATTRIBUTED_TO`, `DROPPED_BY_FIREWALL`, etc.).
- `confidence`: Strict categorical confidence assessment (`DIRECT`, `STRONG`, `CORRELATED`, `INFERRED`, `WEAK`).
- `evidence_event_ids`: Explicit list of backing telemetry event UUIDs providing 100% forensic explainability.

### 2.5 Unified Investigation Timeline Model (`TimelineItem`)
- `item_type`: `TimelineItemType` (`MILESTONE`, `ALERT`, `EVENT`).
- `sort_key()`: Implements strict deterministic ordering guarantee (`timestamp ASC, id ASC`) to eliminate timestamp tie collisions.

---

## 3. Test Verification Suite

Test Suite: [`apps/engine/tests/test_incident_models.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_incident_models.py)  
Total Tests: **10 passed in 0.15s**

1. `test_incident_instantiation_defaults`: Default status `OPEN`, severity, timestamp initialization.
2. `test_incident_custom_severity_and_status`: Explicit override verification.
3. `test_incident_missing_required_fields`: Pydantic schema validation enforcement.
4. `test_valid_incident_status_transitions`: Authorized status transitions across all lifecycle states.
5. `test_invalid_incident_status_transitions`: Illegal transition rejection raising `InvalidIncidentStatusTransitionError`.
6. `test_entity_types_and_instantiation`: Entity taxonomy, keys, and metadata serialization.
7. `test_confidence_level_ordering_and_categories`: Deterministic confidence levels.
8. `test_incident_relationship_instantiation`: Directed graph edges with backing event IDs.
9. `test_incident_alert_link`: Alert-to-incident foreign link model.
10. `test_timeline_item_instantiation_and_sorting`: Stable chronological sorting with deterministic tie-breaker.

---

## 4. Milestone M3 Progress & Next Step

- **M3.0 (Architecture Audit):** **VERIFIED**
- **M3.1 (Domain Models):** **VERIFIED**
- **M3.2 (Schema Migration 4):** **NEXT** (Create `incidents`, `incident_alerts`, `incident_entities`, `incident_relationships`, and performance indexes).
