# LOGINTEL — COMPLETE DESKTOP PRODUCT INTEGRATION BASELINE REPORT
**Document Reference:** `docs/PRODUCTION_INTEGRATION_BASELINE.md`  
**Execution Date:** 2026-10-22  
**Target Platform:** Ubuntu Linux x86_64 (24.04 LTS / 26.04 Workstation)  
**Architecture:** Local-first, Tauri v2 + React 18 + TypeScript + FastAPI Engine + SQLite WAL  
**Branch / HEAD:** `master` @ `932f3edaa6b8610004560f3142eb63e3c9cdce44`  

---

## 1. Executive Summary

This baseline report establishes the authoritative current state of the LogIntel codebase prior to full product reconciliation and integration across Milestones M1 through M7.12.2.

Substantial forensic, detection, graph analysis, investigation, evidence packaging, threat hunting, multi-host, and quality review capabilities have been implemented in the backend (`apps/engine`) and as rich frontend features (`apps/desktop/src/features`). However, prior to this integration phase, the desktop navigation shell exposed only a subset of these features (6 pages), while critical capabilities (dedicated Case management, Multi-Host analysis, and System Diagnostics) were either buried deep inside nested incident sub-tabs or omitted from discoverable top-level desktop workflows.

Furthermore, Gate 4.1 uncovered two critical packaging/startup failure modes:
1. Host Python 3.14 vs. bundled Python 3.12 ABI mismatch causing backend import failures.
2. Missing backend readiness synchronization in Tauri native shell causing WebKitGTK connection errors (`TypeError: Load failed`).

Both were repaired and tested in Gate 4.2 (`logintel_0.1.0_gate42_amd64.deb`). This program expands that foundation into a unified, complete desktop security application.

---

## 2. Current Application Entry Points

### 2.1 Backend Entry Points
- **Direct CLI Engine Entry Point:** [`apps/engine/src/logintel/main.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/main.py)
  - CLI parser with `--port`, `--host`, `--log-level`, `--daemon`.
  - Spawns Uvicorn server hosting `apps/engine/src/logintel/api/routes.py:app` on `127.0.0.1:41721`.
  - Manages SQLite connection pools (`logintel.db` and `cases.db`) in WAL mode with permission enforcement (0600 file, 0700 dir).
  - Generates single-use IPC bearer token written to `~/.local/share/logintel/.engine_token` (mode 0600).
- **Public & Handshake Endpoints:**
  - `GET /api/v1/handshake`: Open public health probe returning engine status, process ID, and version.
- **Engine Process Wrappers:**
  - `/usr/bin/logintel`: Desktop app launcher.
  - `/usr/bin/logintel-engine`: Standalone backend daemon launcher.
  - `/usr/bin/logintel-replay`: Historical log replay tool.

### 2.2 Desktop Shell Entry Points
- **Tauri Native Application Shell:** [`apps/desktop/src-tauri/src/lib.rs`](file:///home/khemendra-labs/LogIntel/apps/desktop/src-tauri/src/lib.rs)
  - Native Rust launcher using Tauri v2.
  - Resolves Python runtime via executable ancestor traversal.
  - Enforces compatible Python 3.12 ABI (`is_compatible_python()`).
  - Active handshake readiness gate polling `/api/v1/handshake` up to 6 seconds before creating the webview.
  - Child process supervisor terminating engine on application exit.
- **Frontend SPA Shell:** [`apps/desktop/src/main.tsx`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/main.tsx) & [`apps/desktop/src/App.tsx`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/App.tsx)
  - React 18 single-page application mounted inside WebKitGTK 4.1 webview.
  - Global navigation state, operational polling interval (8s), and modal manager.

---

## 3. Existing Top-Level Pages & Navigation

### Current Top-Level Pages (`apps/desktop/src/pages/`)
1. **Overview (`OverviewPage.tsx` - 606 lines):**
   - KPI strip: Total Telemetry, Open Alerts, In Triage, Resolved, Active Incidents, Pipeline status.
   - TimeSeriesChart: Event activity over selectable time windows (6h, 12h, 24h, 3d, 7d).
   - DistributionBarCharts: Event breakdown by source and event type.
   - Recent Alerts & Incidents summary feeds.
2. **Activity (`ActivityPage.tsx` - 364 lines):**
   - Canonical raw forensic event table with search, severity filtering, source filtering, and pagination.
   - Event inspection modal trigger (`EventDetailModal`).
   - Resilient transient connection recovery with bounded backoff and manual retry button.
3. **Alerts (`AlertsPage.tsx` - 280 lines):**
   - Correlated detection alerts list with status tabs (ALL, OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE).
   - Severity filters, rule name search, and triage action triggers.
   - Alert details modal (`AlertDetailModal`).
4. **Incidents (`IncidentsPage.tsx` - 491 lines):**
   - Security incidents table grouped from correlated alerts.
   - Metric cards: Open, Investigating, Contained, Resolved.
   - Status transitions and "Correlate Alerts Now" on-demand correlation engine trigger.
   - Launches `IncidentWorkspaceModal`.
5. **Threat Hunting (`ThreatHuntingPage.tsx` - 487 lines):**
   - IOC query interface (IP, Hash, Domain, User).
   - Process lineage forensics and behavioral hunting queries.
   - Entity pivot triggers (`EntityPivotModal`) and forensic event modal (`EventForensicsModal`).
6. **Rules Catalog (`RulesPage.tsx` - 380 lines):**
   - Full catalog of deterministic detection rules (Authentication, Privilege, Network, Execution).
   - Severity, category, and MITRE ATT&CK tactic filter chips.

---

## 4. Existing Investigation Features & Components

Located in [`apps/desktop/src/features/`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/features/):

| Component | Size | Milestone | Purpose | Status |
| :--- | :--- | :--- | :--- | :--- |
| `IncidentWorkspaceModal.tsx` | 66.1 KB | M3–M7 | Primary modal workspace shell housing 15 investigation sub-tabs | Complete, modal-only |
| `InvestigationUnifiedTimeline.tsx` | 38.8 KB | M7.2 | Unified timeline with interactive replay scrubber & bookmarking | Fully functional |
| `InvestigationEvidenceWorkbench.tsx` | 39.7 KB | M7.3 | Logical evidence collections, item assignment, Blake2b manifests | Fully functional |
| `InvestigationFindingsWorkbench.tsx` | 44.7 KB | M7.4 | Structured finding authoring, hypothesis evaluation & comparison | Fully functional |
| `InvestigationThreatHuntWorkbench.tsx`| 65.1 KB | M7.5 | Governed threat hunting, proposal approvals, query preview & execution | Fully functional |
| `InvestigationReportWorkbench.tsx` | 60.8 KB | M7.6 | Report drafts, version comparisons, Markdown/JSON exports, Blake2b bundles | Fully functional |
| `InvestigationCaseComparisonWorkbench.tsx`| 27.7 KB | M7.7 | Cross-case entity and temporal comparison, campaign discovery | Fully functional |
| `InvestigationQualityReviewWorkbench.tsx` | 33.4 KB | M7.8 | 12 categorical review gates, blocker gates, closure & reopening workflows | Fully functional |
| `InvestigationMultiHostWorkbench.tsx` | 111.6 KB | M7.12 | Multi-host inventory, host timelines, lateral movement traces, visibility gaps | Fully functional |
| `InvestigationIntelligencePanel.tsx` | 66.9 KB | M5 | AI-assisted Q&A, explainability traces, hypotheses, query execution | Fully functional |
| `AttackGraphVisualizer.tsx` | 16.4 KB | M3 | Interactive SVG attack graph renderer with entity nodes and edges | Fully functional |
| `EntityPivotModal.tsx` | 15.9 KB | M4 | 360-degree entity pivot inspector for IP, host, user, process | Fully functional |
| `TelemetryHealthModal.tsx` | 5.1 KB | M1–M2 | Linux telemetry source status, file paths, permissions, ingested counts | Modal-only |
| `EventDetailModal.tsx` | 6.7 KB | M1 | Canonical event field inspector | Fully functional |
| `EventForensicsModal.tsx` | 19.1 KB | M6 | Deep OS forensic view (namespaces, cgroups, network sockets, parent tree) | Fully functional |

---

## 5. Implemented Backend Capabilities & API Census

- **Total API Routes Registered:** 225 endpoints in [`apps/engine/src/logintel/api/routes.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/api/routes.py).
- **Security Boundary:** All routes except `/api/v1/handshake` require `Authorization: Bearer <token>`.
- **Primary Route Groups:**
  1. `/events/*`: Canonical raw telemetry search, statistics, event details.
  2. `/alerts/*`: Detection alert listing, lifecycle status updates, triage notes.
  3. `/incidents/*`: Correlated incidents, attack paths, MITRE mappings, status updates.
  4. `/detection/*`: Detection rule catalog, host rules, replay triggers.
  5. `/investigations/*`: Host forensics, process trees, network sockets, systemd services.
  6. `/cases/*`: Case lifecycle, scope, evidence collections, findings, hypotheses, reports, handoff, review, closure.
  7. `/cases/{case_id}/hosts/*`: Multi-host dossier, lateral traces, host timelines, export.
  8. `/cases/{case_id}/review/*`: Review gates, closure evaluation, blocker enforcement.
  9. `/cases/{case_id}/timeline/unified*`: Multi-source unified timeline and replay scrubber.
  10. `/telemetry/*`: Source availability, file permissions, ingestion trigger.
  11. `/system/status`: Engine uptime, memory, database size, total event count.

---

## 6. Database Dependencies & Schema State

The application strictly decouples immutable telemetry data from mutable analyst state across two separate SQLite databases:

### 6.1 Authoritative Forensic Telemetry: `logintel.db`
- **Location:** `~/.local/share/logintel/logintel.db`
- **Current Data Volume:** 52,130 canonical events verified intact.
- **Journal Mode:** WAL (Write-Ahead Logging).
- **Migration Version:** 5 (Managed in [`apps/engine/src/logintel/storage/migrations.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/storage/migrations.py)):
  - Version 1: `initial_canonical_schema` (hosts, sources, ingestion_state, events).
  - Version 2: `m1_1_hardening_fingerprint_and_indexes` (fingerprints, composite indexes).
  - Version 3: `m2_detection_and_alerts` (detection rules, alerts, alert evidence).
  - Version 4: `m3_incident_correlation_and_graph` (incidents, incident alerts, entities, relationships).
  - Version 5: `m4_investigation_workspace_and_notes` (notes, note audit log).
- **Immutability Invariant:** Zero desktop endpoints execute `INSERT`, `UPDATE`, or `DELETE` on `events`. Read-only forensic telemetry.

### 6.2 Analyst Investigation State: `cases.db`
- **Location:** `~/.local/share/logintel/cases.db`
- **Current Data Volume:** 2,541 investigation cases, 47,318 evidence items verified intact.
- **Journal Mode:** WAL with foreign keys enforced.
- **File Permissions:** 0600 on file, 0700 on directory.
- **Tables:** `investigation_cases`, `case_hypotheses`, `case_evidence_references`, `case_query_records`, `case_report_versions`, `case_audit_log`, `case_collections`, `case_collection_items`, `case_findings`, `case_reviews`.
- **Tenant Isolation:** Every operation validates `{case_id}` in `cases.db`.

---

## 7. Existing Automated Tests & Coverage

- **Total Unit & Integration Tests Passing:** 100 / 100
  - Vitest Desktop Suite: 96 tests passing across 5 test suites:
    - `api.test.ts`: 53 tests (M1–M7.8 API contracts, auth headers, error codes).
    - `multihost.test.ts`: 23 tests (M7.12 multi-host dossier, traces, timelines, scope).
    - `activity_recovery.test.ts`: 9 tests (Transient network error handling, backoff, timer cleanup).
    - `theme.test.ts`: 7 tests (Dark/Light/System theme resolution and switching).
    - `dashboard.test.ts`: 4 tests (KPI metric rendering, distribution transforms).
  - Pytest Engine Suite: 4 tests passing in `tests/test_packaging_and_lifecycle.py` (ABI compatibility, handshake readiness, child cleanup).
- **Production Bundle Build:** `tsc && vite build` completes with 0 errors in 1.48s.

---

## 8. Integration Gaps & Deficiencies Identified

1. **Missing Top-Level Desktop Navigation Items:**
   - **Investigations / Cases:** No top-level sidebar tab to browse all 2,541 existing cases in `cases.db` or create new standalone cases. Users could only access cases through incident modals.
   - **Multi-Host Investigation:** The 111 KB `InvestigationMultiHostWorkbench` was hidden inside a sub-tab of `IncidentWorkspaceModal`, rendering cross-host investigation invisible from the primary desktop layout.
   - **System Diagnostics:** Telemetry source health and pipeline diagnostics were only reachable via a tiny status pill in the header, rather than a full diagnostic view.
2. **Overview Page API Error Concealment:**
   - In `OverviewPage.tsx`, if the backend is offline or disconnected, KPI values silently defaulted to `0` and "STANDBY" without a prominent error banner or retry trigger. The UI must explicitly differentiate "Backend Disconnected" from "Database Empty (0 Events)".
3. **Direct Navigation Between Correlated Entities:**
   - Clicking an alert should lead directly to its evidence and incident.
   - Clicking an incident should open the investigation workspace with preserved tab context.
   - Case context should be preserved across top-level views without leaking state.

---

## 9. Baseline Verdict

- **Codebase Integrity:** Intact. Zero database mutations or destructive changes.
- **Readiness for Gate B-G:** The backend foundation, data models, API endpoints, and React feature components are fully implemented and verified. The primary remaining task is desktop-level reconciliation, wiring missing top-level routes, robust error handling, and end-to-end installer packaging.
