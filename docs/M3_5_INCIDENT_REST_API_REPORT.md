# LOGINTEL — MILESTONE M3.5 FORENSIC REPORT

## Incident Management & Attack Graph REST API

**Repository:** `/home/khemendra-labs/LogIntel`  
**Milestone:** M3.5  
**Previous Gate:** M3.4 VERIFIED — Incident Correlation Engine  
**Module:** `apps/engine/src/logintel/api/routes.py`  
**Date:** 2026-09-30  
**Status:** M3.5 VERIFIED — READY FOR M3.6  

---

# 1. Executive Summary

Milestone M3.5 implements the complete **Incident Management, Attack Graph, and Timeline REST API surface** in [`apps/engine/src/logintel/api/routes.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/api/routes.py).

This API layer enables the LogIntel desktop frontend and IPC clients to:
1. **Query and filter security incidents** by lifecycle status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `FALSE_POSITIVE`, `CLOSED`), severity, host, and user account with pagination.
2. **Retrieve complete incident investigation dossiers** containing aggregated metrics, linked operational alerts, attack graph topology, and chronological timelines.
3. **Execute validated lifecycle status transitions** (`PATCH /api/v1/incidents/{id}/status`) with audit notes and resolution timestamps.
4. **Fetch graph traversal payloads** (`GET /api/v1/incidents/{id}/graph`) providing nodes (`HOST`, `USER`, `IP`, `PROCESS`) and directed edges (`CONNECTED_TO`, `AUTHENTICATED_TO`, `EXECUTED`, `LATERAL_MOVEMENT`) formatted for frontend rendering.
5. **Stream investigation timelines** (`GET /api/v1/incidents/{id}/timeline`) delivering chronologically ordered events, alerts, and milestones with deterministic tie-breaking.
6. **Trigger on-demand incident correlation** (`POST /api/v1/incidents/correlate`) to cluster all unassigned alerts.

---

# 2. REST API Route Inventory

All incident endpoints are registered under `/api/v1` and protected by the engine authentication dependency (`verify_engine_token`).

| Method | Endpoint | Description | Request Body / Query | Response Model |
|---|---|---|---|---|
| `GET` | `/api/v1/incidents` | Query incidents with filters and pagination | `status`, `severity`, `host`, `user`, `limit`, `offset` | `IncidentsQueryResponse` |
| `GET` | `/api/v1/incidents/{id}` | Full incident detail payload (workspace) | Path `id` | `Dict[str, Any]` (`incident`, `alerts`, `graph`, `timeline`) |
| `GET` | `/api/v1/incidents/{id}/alerts` | Operational alerts linked to an incident | Path `id` | `Dict[str, Any]` (`items`, `total`) |
| `PATCH` | `/api/v1/incidents/{id}/status` | Perform validated status transition | `UpdateIncidentStatusRequest` (`status`, `resolution_note`) | Updated `Incident` |
| `GET` | `/api/v1/incidents/{id}/graph` | Attack graph nodes and edges payload | Path `id` | `IncidentGraphResponse` (`nodes`, `edges`) |
| `GET` | `/api/v1/incidents/{id}/timeline` | Chronological investigation timeline stream | Path `id` | `IncidentTimelineResponse` (`items`, `total`) |
| `POST` | `/api/v1/incidents/correlate` | Trigger unassigned alerts correlation | None | `CorrelateIncidentsResponse` (`correlated_incidents_count`, `incident_ids`) |

---

# 3. Security, Validation & Error Handling

1. **Authentication Enforcement:**
   - All incident routes require a valid `Authorization: Bearer <token>` matching the runtime session secret.
   - Missing or forged tokens immediately return `401 Unauthorized`.
2. **Schema & Enum Validation:**
   - `status` query and body parameters are validated against `IncidentStatus`; invalid values return `400 Bad Request` with permitted values.
   - `severity` parameters are validated against `Severity`; invalid values return `400 Bad Request`.
3. **State Machine Verification:**
   - Illegal status transitions (e.g. attempting to jump from `OPEN` directly to `CLOSED`) raise `InvalidIncidentStatusTransitionError` and return `400 Bad Request`.
4. **404 Resource Protection:**
   - Querying or mutating non-existent incident IDs returns `404 Not Found`.

---

# 4. Test Verification Suite

Test Suite: [`apps/engine/tests/test_incidents_api.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_incidents_api.py)  
Total Suite Tests: **10 passed in 1.77s**

| Test Name | Focus | Result |
|---|---|---|
| `test_incident_endpoints_require_auth` | Rejection of unauthenticated requests across all 7 routes with 401 | **PASSED** |
| `test_incident_endpoints_reject_invalid_token` | Rejection of forged Bearer token | **PASSED** |
| `test_list_incidents_success_and_filtering` | Pagination and filtering by status, severity, host, and user | **PASSED** |
| `test_list_incidents_invalid_parameters` | Input validation errors on bogus status and severity | **PASSED** |
| `test_get_incident_detail_found_and_not_found` | Full investigation workspace payload retrieval and 404 handling | **PASSED** |
| `test_get_incident_alerts_endpoint` | Sub-resource query for operational alerts linked to incident | **PASSED** |
| `test_update_incident_status_lifecycle` | Valid transitions, resolution notes/timestamps, illegal transition rejection | **PASSED** |
| `test_get_incident_attack_graph_endpoint` | Graph payload serialization (`nodes`, `edges`) | **PASSED** |
| `test_get_incident_timeline_endpoint` | Chronologically ordered investigation stream payload | **PASSED** |
| `test_trigger_correlation_endpoint` | On-demand POST execution of alert correlation | **PASSED** |

---

# 5. Full Regression Status

- **Engine Test Suite:** **227 passed** (0 failures, 1 warning)
- **Desktop Vitest Suite:** **10 passed** (0 failures)
- **Desktop TypeScript Check:** **0 errors**

---

# 6. Milestone Progress & Next Gate

- **M3.0 (Architecture Audit):** **VERIFIED**
- **M3.1 (Domain Models):** **VERIFIED**
- **M3.2 (Schema Migration 4):** **VERIFIED**
- **M3.3 (Incident Storage Repository):** **VERIFIED**
- **M3.4 (Incident Correlation Engine):** **VERIFIED**
- **M3.5 (Incident & Attack Graph REST API):** **VERIFIED**
- **M3.6 (Desktop Client API & Types Integration):** **NEXT** (Extend desktop `src/lib/api.ts` and `src/types/` with TypeScript interfaces and client functions for incidents, attack graphs, and timelines).
