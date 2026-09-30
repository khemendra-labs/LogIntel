# LogIntel — M2.8 Detection REST API Implementation Report

## Executive Summary

Phase **M2.8: Detection REST API** has been successfully implemented, validated, and forensically verified in accordance with the LogIntel M2 roadmap.

The detection REST API exposes engine-backed, authenticated operational endpoints for inspecting detection rules, querying consolidated alerts, inspecting rich detection/evidence lineage, and managing alert triage lifecycle states.

```text
STATUS: M2.8 VERIFIED — READY FOR M2.9
SCHEMA VERSION: 3 (UNMODIFIED)
MIGRATION 4: NOT CREATED
DATABASE EVENTS: 17,470 PRESERVED (INTACT)
BACKEND TESTS: 163 PASSED (10 dedicated M2.8 tests)
FRONTEND TESTS: 4 PASSED
ZERO SCOPE CREEP: M2.9–M2.11 NOT IMPLEMENTED
```

---

## 1. REST API Endpoints Specification

All endpoints are mounted under `/api/v1` and strictly require Bearer token authentication validated against the engine token (`~/.local/share/logintel/engine.token`).

### Detection Rules Catalog

#### `GET /api/v1/detection/rules`
- **Query Parameters**:
  - `category` (optional, string: `AUTH`, `PRIVILEGE`, `PROCESS`, `ACCOUNT`, `NETWORK`)
  - `enabled` (optional, boolean: `true` / `false`)
- **Response**:
  ```json
  {
    "items": [
      {
        "id": "auth.ssh_bruteforce",
        "name": "SSH Brute Force Attempt",
        "description": "Multiple SSH authentication failures detected from the same source IP within a sliding time window.",
        "severity": "HIGH",
        "category": "AUTH",
        "rule_type": "THRESHOLD",
        "enabled": true,
        "cooldown_seconds": 900,
        "conditions_count": 2
      }
    ],
    "total": 16
  }
  ```

#### `GET /api/v1/detection/rules/{rule_id}`
- **Path Parameter**: `rule_id` (string, e.g. `auth.ssh_bruteforce`)
- **Returns**: 200 with full rule AST structure + raw YAML representation, or 404 if not found.
  ```json
  {
    "rule": {
      "id": "auth.ssh_bruteforce",
      "name": "SSH Brute Force Attempt",
      "severity": "HIGH",
      "category": "AUTH",
      "rule_type": "THRESHOLD",
      "enabled": true,
      "conditions": { ... },
      "threshold": { "count": 5, "window_seconds": 120 },
      "group_by": ["src_ip"]
    },
    "yaml_definition": "id: auth.ssh_bruteforce\nname: SSH Brute Force Attempt\n..."
  }
  ```

---

### Operational Alerts & Lifecycle Management

#### `GET /api/v1/alerts`
- **Query Parameters**:
  - `status` (optional, e.g. `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`)
  - `severity` (optional, e.g. `INFORMATIONAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, `ALERT`)
  - `host` (optional, string)
  - `rule_id` (optional, string)
  - `limit` (default: 50, max: 500)
  - `offset` (default: 0)
- **Response**: Paginated alert objects:
  ```json
  {
    "items": [
      {
        "id": 1,
        "rule_id": "priv.unauthorized_sudo",
        "dedup_key": "priv.unauthorized_sudo:srv-api-01:attacker",
        "title": "Unauthorized Sudo Command Attempt",
        "description": "User attacker attempted to execute a command via sudo without authorization.",
        "severity": "ALERT",
        "status": "OPEN",
        "host": "srv-api-01",
        "first_seen": "2026-09-30T10:00:00Z",
        "last_seen": "2026-09-30T10:00:00Z",
        "occurrence_count": 1,
        "acknowledged_at": null,
        "resolved_at": null,
        "resolution_note": null
      }
    ],
    "total": 1,
    "limit": 50,
    "offset": 0
  }
  ```

#### `GET /api/v1/alerts/{alert_id}`
- **Path Parameter**: `alert_id` (integer)
- **Returns**: Full investigation dossier including the parent alert, all associated detection occurrences, and backing canonical event evidence IDs and roles.
  ```json
  {
    "alert": {
      "id": 1,
      "rule_id": "priv.unauthorized_sudo",
      "status": "OPEN",
      "host": "srv-api-01",
      ...
    },
    "detections": [
      {
        "id": 1,
        "alert_id": 1,
        "rule_id": "priv.unauthorized_sudo",
        "matched_at": "2026-09-30T10:00:00Z",
        "summary": "Unauthorized sudo by attacker",
        "details": { "matched_fields": { "username": "attacker" } },
        "evidence": [
          {
            "id": 1,
            "detection_id": 1,
            "event_id": "ev-api-unauth",
            "role": "TRIGGER",
            "matched_at": "2026-09-30T10:00:00Z"
          }
        ]
      }
    ]
  }
  ```

#### `PATCH /api/v1/alerts/{alert_id}/status`
- **Request Body**:
  ```json
  {
    "status": "RESOLVED",
    "resolution_note": "Attacker account locked and SSH keys revoked."
  }
  ```
- **State Validation**:
  - Enforces lifecycle state machine transitions (`OPEN` -> `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`; `ACKNOWLEDGED` -> `RESOLVED`, `FALSE_POSITIVE`, `OPEN`; `RESOLVED`/`FALSE_POSITIVE` -> `OPEN`).
  - Returns `400 Bad Request` with structured error message if an invalid state transition is requested (e.g. `RESOLVED` -> `ACKNOWLEDGED`).
  - Returns `404 Not Found` if the alert ID does not exist.

---

## 2. Test Verification

Dedicated integration test suite implemented in [`apps/engine/tests/test_detection_api.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_detection_api.py):

| Test Case | Scope / Assertion | Status |
| :--- | :--- | :--- |
| `test_detection_endpoints_require_auth` | Validates all 5 detection endpoints reject unauthenticated calls with 401 | PASSED |
| `test_detection_endpoints_reject_invalid_token` | Validates forged/invalid tokens are rejected with 401 | PASSED |
| `test_list_detection_rules_all` | Validates listing returns full 16 canonical rules | PASSED |
| `test_list_detection_rules_filter_category` | Validates filtering rules by category (`AUTH`: 5, `PRIVILEGE`: 3, `PROCESS`: 3, `ACCOUNT`: 2, `NETWORK`: 3) | PASSED |
| `test_get_detection_rule_detail_success` | Validates retrieving single rule with valid YAML format | PASSED |
| `test_get_detection_rule_detail_not_found` | Validates 404 on nonexistent rule | PASSED |
| `test_list_alerts_empty_or_populated` | Validates paginated response format | PASSED |
| `test_alert_lifecycle_via_api` | End-to-end integration: record detection -> query alert -> acknowledge -> resolve -> reject invalid transition -> reopen | PASSED |
| `test_patch_alert_status_invalid_inputs` | Validates 404 for unknown alerts and 400 for invalid status enums | PASSED |
| `test_list_alerts_invalid_query_params` | Validates 400 for bad status and severity query parameters | PASSED |

### Complete Test Results
- **Backend**: `163 passed, 1 warning in 7.18s`
- **Frontend**: `4 passed in 1.37s`

---

## 3. Database Integrity & Scope Boundary Check

- **Schema Version**: `3` (Verified: `SELECT version FROM schema_migrations` -> `[1, 2, 3]`)
- **Foreign Key Check**: Zero violations
- **Storage Mode**: SQLite WAL mode
- **Event Count**: 17,470 intact
- **Forbidden Phases**:
  - M2.9 GUI: Not modified
  - M2.10 Replay: Not implemented
  - M2.11 Packaging: Not modified

---

## 4. Gate Conclusion

```text
======================================================
M2.8 VERIFIED — READY FOR M2.9
======================================================
```
