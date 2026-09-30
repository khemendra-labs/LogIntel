# LogIntel — M2.7 Evidence, Alert Lifecycle & Deduplication Implementation Report

## Executive Summary

Phase **M2.7: Evidence, Alert Lifecycle & Deduplication** has been successfully implemented, validated, and forensically verified in accordance with the LogIntel M2 roadmap.

The operational alert layer transforms discrete `DetectionResult` evaluations into consolidated, tracked, and stateful security investigation alerts with deterministic deduplication, cooldown suppression, evidence lineage linking, and validated lifecycle state transitions.

```text
STATUS: M2.7 VERIFIED — READY FOR M2.8
SCHEMA VERSION: 3 (UNMODIFIED)
MIGRATION 4: NOT CREATED
DATABASE EVENTS: 17,442 PRESERVED (INTACT)
BACKEND TESTS: 153 PASSED (10 dedicated M2.7 tests)
FRONTEND TESTS: 4 PASSED
ZERO SCOPE CREEP: M2.8–M2.11 NOT IMPLEMENTED
```

---

## 1. Alert Lifecycle Architecture & State Machine

Alerts model operational security findings aggregating one or more rule detection occurrences.

### Lifecycle State Machine
```text
               ┌───────────────────────┐
               │         OPEN          │◄────────┐
               └───────────┬───────────┘         │
                           │                     │
            ┌──────────────┴──────────────┐      │
            ▼                             ▼      │
   ┌─────────────────┐           ┌──────────────┐│
   │  ACKNOWLEDGED   │           │FALSE_POSITIVE││
   └────────┬────────┘           └──────────────┘│
            │                             ▲      │
            ▼                             │      │
   ┌─────────────────┐                    │      │
   │    RESOLVED     │────────────────────┘      │
   └────────┬────────┘                           │
            │                                    │
            └────────────────────────────────────┘ (Reopened)
```

- **`OPEN`**: Initial state of an alert when a detection rule matches.
- **`ACKNOWLEDGED`**: Analyst triage and ownership assignment (`acknowledged_at` populated).
- **`RESOLVED`**: Threat mitigated or closed with required resolution note (`resolved_at`, `resolution_note` populated).
- **`FALSE_POSITIVE`**: Benign activity dismissed with rationale (`resolved_at`, `resolution_note` populated).
- **Reopening**: Transitioning back to `OPEN` clears `resolved_at` and `resolution_note` while preserving detection history.
- **Invalid Transitions**: Any transition violating the state machine raises `InvalidStatusTransitionError`.

---

## 2. Deterministic Deduplication & Cooldown

Implemented in [`AlertsRepository`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/storage/alerts_repo.py):

1. **Deterministic `dedup_key` Computation**:
   - For threshold rules: `f"{rule_id}:{group_key}"` where `group_key` is the normalized partition (e.g. `src_ip=203.0.113.10|host=srv-01`).
   - For atomic rules: `f"{rule_id}:{host}:{username}"` (or `f"{rule_id}:{host}"`).
2. **Atomic Aggregation within Cooldown Window**:
   - When a detection occurs for an active (`OPEN` or `ACKNOWLEDGED`) alert:
     - SQLite transaction (`BEGIN IMMEDIATE;`) ensures lock-free concurrency and zero duplicate insert race conditions.
     - `last_seen` updated to detection timestamp.
     - `occurrence_count` incremented.
     - A new `detections` row inserted linked to `alert.id`.
     - Evidence references inserted into `detection_evidence` with roles (`TRIGGER`, `AGGREGATE`, `CONTEXT`).
3. **Historical Preservation on Incident Re-occurrence**:
   - If an alert was `RESOLVED` or `FALSE_POSITIVE` and a new detection matches the same rule/group:
     - The resolved alert's dedup key is retired to `f"{dedup_key}:archived:{old_alert_id}"` for permanent compliance audit trail.
     - A brand-new `OPEN` alert is initialized with `occurrence_count = 1`.

---

## 3. Database & Foreign Key Protections

- Uses existing tables created in Migration 3:
  - `detection_rules`: Populated via `alerts_repo.sync_rules(load_default_rules())`.
  - `alerts`: Tracks alert lifecycle and deduplication.
  - `detections`: Tracks individual detection occurrences (`ON DELETE CASCADE` from alerts).
  - `detection_evidence`: Links detections to canonical events (`ON DELETE RESTRICT` on events, `CASCADE` on detections).
- Zero schema migrations (no Migration 4, schema version remains 3).

---

## 4. Test Verification Metrics

### Dedicated M2.7 Test Suite
File: [`apps/engine/tests/test_alert_lifecycle.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_alert_lifecycle.py)
**10 tests passing, 0 failing:**

- `test_sync_rules_to_database`: Verifies batch upsert of canonical rules into `detection_rules` catalog table.
- `test_alert_creation_atomic`: Verifies atomic detection creates `OPEN` alert with linked detection and `TRIGGER` evidence.
- `test_alert_deduplication_cooldown`: Verifies repeated detections within cooldown aggregate into single alert with incremented `occurrence_count`.
- `test_alert_distinct_group_keys_create_distinct_alerts`: Verifies distinct hosts/IPs produce separate alerts.
- `test_alert_lifecycle_valid_transitions`: Verifies `OPEN` -> `ACKNOWLEDGED` -> `RESOLVED` -> `OPEN` state transitions and timestamp tracking.
- `test_alert_lifecycle_invalid_transitions_rejected`: Verifies forbidden transitions raise `InvalidStatusTransitionError`.
- `test_new_alert_after_resolution`: Verifies re-occurrence after resolution archives old record and creates fresh alert.
- `test_list_and_count_alerts_with_filtering`: Verifies alert queries filtered by status, severity, host, and pagination.
- `test_concurrent_detection_recording`: Verifies multi-threaded concurrency safety (20 parallel threads) with exact occurrence counts and zero deadlocks.
- `test_get_alert_details_with_evidence_fields`: Verifies complete retrieval of alert with joined detection and evidence event metadata.

### Full Engine Test Suite
Command: `./apps/engine/.venv/bin/pytest apps/engine/tests/ -v`
**153 tests passing, 0 failing, 0 regressions.**

### Frontend Test Suite
Command: `npm test` in `apps/desktop`
**4 tests passing, 0 failing.**

---

## 5. Production Database Verification

```text
Database Path:        /home/khemendra-labs/.local/share/logintel/logintel.db
Schema Version:       3 (Migration 3: m2_detection_and_alerts)
Migration 4:          NOT CREATED
Events Table Count:   17,442 rows (INTACT)
Foreign Key Check:    0 violations
Journal Mode:         wal
```

---

## 6. Scope Boundary Compliance

| Milestone Phase | Status | Notes |
| :--- | :--- | :--- |
| **M2.1** Detection Core Specification | VERIFIED | Schema, validators, canonical registry |
| **M2.2** Detection DB Model / Migration 3 | VERIFIED | Tables, indexes, FK protections |
| **M2.3 / M2.3.1** In-Memory Engine | VERIFIED | Sliding window, ReDoS safety, deterministic |
| **M2.4** Authentication Rules | VERIFIED | 5 canonical authentication rules |
| **M2.5** Privilege & Process Rules | VERIFIED | 6 canonical privilege & process rules |
| **M2.6** Account / Network / IOC Rules | VERIFIED | 5 canonical account & network rules |
| **M2.7** Alert Lifecycle / Deduplication | **VERIFIED** | **Completed & tested in this phase** |
| **M2.8** REST API Detection Endpoints | DEFERRED | Explicitly forbidden during M2.7 |
| **M2.9** GUI Detection Interface | DEFERRED | Explicitly forbidden during M2.7 |
| **M2.10** Historical Replay Harness | DEFERRED | Explicitly forbidden during M2.7 |
| **M2.11** Debian Packaging & Production | DEFERRED | Explicitly forbidden during M2.7 |

---

## 7. Phase Gate Verdict

```text
==================================================================
PHASE GATE: M2.7 VERIFIED — READY FOR M2.8
Alert persistence, lifecycle state machine, cooldown deduplication,
and evidence linkage are verified across 10 dedicated tests and 153
total suite tests.
No schema migrations, zero database alterations, zero scope creep.
Awaiting user authorization to proceed to M2.8.
==================================================================
```
