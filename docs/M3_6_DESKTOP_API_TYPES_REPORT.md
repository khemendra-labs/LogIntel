# LOGINTEL — MILESTONE M3.6 FORENSIC REPORT

## Desktop Client API & Types Integration (Incidents, Attack Graphs & Timelines)

**Repository:** `/home/khemendra-labs/LogIntel`  
**Milestone:** M3.6  
**Previous Gate:** M3.5 VERIFIED — Incident & Attack Graph REST API  
**Modules:**
- [`apps/desktop/src/types/incidents.ts`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/types/incidents.ts)
- [`apps/desktop/src/lib/api.ts`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/lib/api.ts)
- [`apps/desktop/src/__tests__/api.test.ts`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/__tests__/api.test.ts)  
**Date:** 2026-09-30  
**Status:** M3.6 VERIFIED — READY FOR M3.7  

---

# 1. Executive Summary

Milestone M3.6 completes the **TypeScript domain type system and desktop API client integration** for the LogIntel Incident Management, Attack Graph, and Timeline subsystems.

This layer bridges the LogIntel desktop user interface with the engine's REST API, ensuring type safety, strict lifecycle validation, transparent Bearer token authentication, automatic error formatting, and deterministic query construction.

---

# 2. Type System Implementation

File: [`apps/desktop/src/types/incidents.ts`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/types/incidents.ts)

### 2.1 Enums & Status Transition Rules
- **`IncidentStatus`**: `"OPEN" | "INVESTIGATING" | "CONTAINED" | "RESOLVED" | "FALSE_POSITIVE" | "CLOSED"`
- **`ALLOWED_INCIDENT_STATUS_TRANSITIONS`**: Mirroring the engine's finite-state machine to guard client-side UI transitions.
- **`EntityType`**: `"HOST" | "USER" | "IP" | "PROCESS" | "COMMAND" | "FILE" | "SESSION"`
- **`ConfidenceLevel`**: `"DIRECT" | "STRONG" | "CORRELATED" | "INFERRED" | "WEAK"`
- **`RelationshipType`**: Canonical semantics including `AUTHENTICATED_TO`, `CONNECTED_TO`, `EXECUTED`, `SPAWNED`, `LATERAL_MOVEMENT`, `CO_OCCURRED`, etc.
- **`TimelineItemType`**: `"MILESTONE" | "ALERT" | "EVENT"`

### 2.2 Core Models & Interfaces
- **`Incident`**: Aggregated security incident record with temporal bounds (`first_seen`, `last_seen`), counters (`alert_count`, `event_count`), host/user bindings, and resolution metadata.
- **`IncidentEntity`**: Normalized node representing entities involved in the incident.
- **`IncidentRelationship`**: Directed edge connecting entities with confidence and supporting evidence event IDs.
- **`AttackGraphNode` & `AttackGraphEdge`**: Graph visualization structures consumable by graph renderers (e.g. SVG/Canvas/D3/Cytoscape).
- **`TimelineItem`**: Chronological milestone, alert, or corroborating event with tie-breaking capability.
- **`IncidentDetailResponse`**: Complete workspace payload bundling incident metadata, linked operational alerts, attack graph topology, and chronological timeline.
- **`IncidentQueryParams`, `IncidentsQueryResponse`, `UpdateIncidentStatusPayload`, `CorrelateIncidentsResponse`**.

---

# 3. Desktop API Client Methods

File: [`apps/desktop/src/lib/api.ts`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/lib/api.ts)

All methods automatically acquire and attach the engine session Bearer token, handle token rotation retries on 401s, serialize query parameters, and parse structured server error details.

| Method | Parameters | HTTP Endpoint | Description |
|---|---|---|---|
| `fetchIncidents` | `params: IncidentQueryParams` | `GET /api/v1/incidents` | Query incidents with status, severity, host, user, limit, offset filters |
| `fetchIncidentDetail` | `incidentId: number` | `GET /api/v1/incidents/{id}` | Retrieve complete workspace dossier (`incident`, `alerts`, `graph`, `timeline`) |
| `fetchIncidentAlerts` | `incidentId: number` | `GET /api/v1/incidents/{id}/alerts` | Fetch operational alerts associated with incident |
| `updateIncidentStatus` | `incidentId: number`, `status`, `resolutionNote?` | `PATCH /api/v1/incidents/{id}/status` | Execute validated status transition with audit note |
| `fetchIncidentAttackGraph` | `incidentId: number` | `GET /api/v1/incidents/{id}/graph` | Fetch attack graph nodes and directed edges |
| `fetchIncidentTimeline` | `incidentId: number` | `GET /api/v1/incidents/{id}/timeline` | Fetch chronological investigation timeline stream |
| `triggerIncidentCorrelation` | None | `POST /api/v1/incidents/correlate` | Trigger unassigned alerts correlation cycle |

---

# 4. Test Verification Suite

Test Suite: [`apps/desktop/src/__tests__/api.test.ts`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/__tests__/api.test.ts)  
Total Suite Tests: **19 passed in 1.21s** (9 new M3.6 tests + 10 existing tests)

| Test Name | Focus | Result |
|---|---|---|
| `fetchIncidents constructs proper query parameters and filters` | URL query parameters, status/severity/host/user filters, limit/offset, Bearer auth | **PASSED** |
| `fetchIncidentDetail retrieves complete workspace dossier by ID` | Path parameter interpolation, full dossier deserialization | **PASSED** |
| `fetchIncidentAlerts queries linked operational alerts` | Sub-resource query, count and list extraction | **PASSED** |
| `updateIncidentStatus sends PATCH request with new status and resolution note` | PATCH method, JSON body serialization, Bearer auth | **PASSED** |
| `updateIncidentStatus extracts server detail message on failure` | Server error detail message propagation on rejection | **PASSED** |
| `fetchIncidentAttackGraph retrieves nodes and edges topology` | Attack graph nodes, edges, entity types, relationship types | **PASSED** |
| `fetchIncidentTimeline retrieves chronologically ordered items` | Timeline stream deserialization, item types (`ALERT`, `MILESTONE`, `EVENT`) | **PASSED** |
| `triggerIncidentCorrelation executes POST to correlate unassigned alerts` | POST trigger, correlated counts and incident IDs | **PASSED** |
| `triggerIncidentCorrelation throws clear error on API failure` | Error handling on correlation failure | **PASSED** |

---

# 5. Full Regression Status

- **Desktop Vitest Suite:** **19 passed** (0 failures)
- **Desktop TypeScript Check (`tsc --noEmit`):** **0 errors**
- **Engine Test Suite (`pytest`):** **227 passed** (0 failures, 1 warning)

---

# 6. Milestone Progress & Next Gate

- **M3.0 (Architecture Audit):** **VERIFIED**
- **M3.1 (Domain Models):** **VERIFIED**
- **M3.2 (Schema Migration 4):** **VERIFIED**
- **M3.3 (Incident Storage Repository):** **VERIFIED**
- **M3.4 (Incident Correlation Engine):** **VERIFIED**
- **M3.5 (Incident & Attack Graph REST API):** **VERIFIED**
- **M3.6 (Desktop Client API & Types Integration):** **VERIFIED**
- **M3.7 (Incident Investigation Workspace UI Components):** **NEXT** (Implement desktop navigation, Incident List table with filters, Incident Detail Workspace, interactive Attack Graph viewer, and Chronological Timeline viewer).
