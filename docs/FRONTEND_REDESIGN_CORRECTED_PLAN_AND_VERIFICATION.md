# LOGINTEL FRONTEND REDESIGN: GATE 1 CORRECTIONS AND VERIFIED IMPLEMENTATION PLAN
**Document ID:** `docs/FRONTEND_REDESIGN_CORRECTED_PLAN_AND_VERIFICATION.md`  
**Date:** October 20, 2026  
**Mode:** Strict Read-Only Verification & Plan Correction  
**Author:** Senior Software Verification Engineer and Digital Forensics Architect  

---

## 1. Executive Summary & Verification Context

This report provides the formal, read-only verification of the LogIntel frontend architecture, backend API contracts, and design system plan before Gate 2 approval.

The Gate 1 audit has been reconciled against authoritative source files in `apps/desktop/` and `apps/engine/`. Several critical contract assumptions from the preliminary audit—specifically regarding endpoint paths, source health data models, timeline bucket padding, and alert/incident count mechanics—have been corrected.

**Strict Safety Adherence:**
- **Zero code modifications** were made during this verification.
- **Zero database migrations or schema alterations** were introduced.
- **No Git state changes** (`reset`, `clean`, `commit`, `push`) were performed.
- All existing forensic reports, benchmarks, and M7.12 verification artifacts are preserved intact.

---

## 2. Verified Repository Baseline (Task 1)

### 2.1 Git Status & Working Tree
- **Repository Root:** `/home/khemendra-labs/LogIntel`
- **Active Branch:** `master` (synchronized with `origin/master`)
- **HEAD Commit:** `932f3ed` (*"feat: implement multi-host investigation workbench with backend dossier integration and verification audits"*)
- **Working Tree State:** Completely clean. Zero tracked modifications, zero untracked files.
- **Audit Discrepancy Note:** The initial Gate 1 summary referenced tracked modified files from a prior working state. Direct inspection via `git status --short` confirms all working-tree files are cleanly committed at `932f3ed`.

### 2.2 Preserved Artifacts & Source Integrity
- **Forensic Verification Reports:** All 70+ documents under `docs/` (including `M7.12_FINAL_FORENSIC_RECONCILIATION_AND_CLOSURE_READINESS.md`, `M7.12_COMPREHENSIVE_VERIFICATION_AND_VALIDATION_REPORT.md`, `M7_GITHUB_PUBLICATION_READINESS_AND_PERFORMANCE_AUDIT.md`) are present and unmodified.
- **Milestone Tests:** `apps/engine/tests/test_m712_multihost.py`, `apps/desktop/src/__tests__/multihost.test.ts`, and all milestone regression suites are intact.

### 2.3 Software Versions & Build Verification
- **Desktop Frontend (`apps/desktop`):**
  - Package: `logintel-desktop@0.1.0`
  - Runtime Dependencies: `@tauri-apps/api@^2.1.1`, `@tauri-apps/plugin-shell@^2.0.1`, `react@^18.3.1`, `react-dom@^18.3.1`
  - Dev Dependencies: `@tauri-apps/cli@^2.1.0`, `typescript@^5.4.5`, `vite@^5.2.11`, `vitest@^2.1.9`
  - Build Command: `npm run build` (`tsc && vite build`)
  - Test Command: `npm test -- --run` (`vitest run --run`)
  - Baseline Test Status: **76 tests passed** (53 in `api.test.ts`, 23 in `multihost.test.ts`, duration: 1.90s)
  - Baseline Bundle Measurements:
    - `dist/index.html`: 0.80 kB (gzip: 0.45 kB)
    - `dist/assets/index-*.css`: 8.20 kB (gzip: 2.13 kB)
    - `dist/assets/core-*.js`: 2.49 kB (gzip: 1.01 kB)
    - `dist/assets/index-*.js`: 720.32 kB (gzip: 147.77 kB)
    - Build Duration: 2.13s
- **Telemetry & Investigation Engine (`apps/engine`):**
  - Python Environment: Python 3.12 virtualenv (`apps/engine/.venv`)
  - Framework: FastAPI 0.111.0, Starlette, Pydantic 2.7.1, Uvicorn
  - Storage: SQLite3 with WAL journal mode (`logintel.db` for authoritative telemetry, `cases.db` for analyst state)
  - Test Inventory: **1,195 tests collected** via `pytest --collect-only -q`

---

## 3. Verified Backend API Contracts & Metric Matrix (Task 2)

Every proposed dashboard metric has been audited against actual FastAPI route definitions in `apps/engine/src/logintel/api/routes.py` and repository models.

| Metric / Section | Exact Endpoint & Method | Query Parameters & Defaults | Authoritative Fields in Response | Aggregation & Pagination Semantics | Refresh Safety & Discrepancy Correction |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **All-Time Total Events** | `GET /api/v1/system/status` | None | `total_events: int`<br>`host: str`<br>`version: str`<br>`ingestion_running: bool`<br>`uptime_seconds: float` | Authoritative count derived from `SELECT COUNT(*) FROM events`. Single row returned. | **SAFE for recurring refresh.** Lightweight payload (< 250 bytes). |
| **Event Statistics & Hourly Buckets** | `GET /api/v1/events/stats/summary` | `hours: int = 24` (ge=1, le=720) | `total_events: int`<br>`window_hours: int`<br>`window_events: int`<br>`by_severity: Dict[str, int]`<br>`by_type: Dict[str, int]`<br>`by_source: Dict[str, int]`<br>`timeline: List[{ bucket: str, count: int }]`<br>`recent_alerts: List[CanonicalEvent]` | **Server-side aggregated.**<br>Top 10 event types returned.<br>Timeline buckets are UTC hourly (`%Y-%m-%dT%H:00:00Z`).<br>**Critical:** Backend omits hours with zero events. | **CORRECTION:** Gate 1 stated `/api/v1/events/statistics`. The real route is `/api/v1/events/stats/summary`.<br>**Padding Requirement:** Frontend must pad missing hourly buckets with `0` so inactive intervals are accurately represented on the timeline. |
| **Alert Counts by Status** (Open, Ack, Resolved, False-Pos) | `GET /api/v1/alerts` | `status: Optional[str]`<br>`severity: Optional[str]`<br>`limit: int = 50` (ge=1, le=500)<br>`offset: int = 0` | `items: List[Alert]`<br>`total: int`<br>`limit: int`<br>`offset: int` | **Authoritative count returned.** `alerts_repo.count_alerts(...)` executes `SELECT COUNT(*) FROM alerts WHERE status = ?`.<br>Passing `limit=1` returns `.total` with single item. | **SAFE for recurring refresh when `limit=1`.** Payload < 400 bytes.<br>Do not fetch all alerts to count them. Use `limit=1` and read `.total`. |
| **Incident Counts by Status** (Open, Investigating, etc.) | `GET /api/v1/incidents` | `status: Optional[str]`<br>`severity: Optional[str]`<br>`limit: int = 50` (ge=1, le=500)<br>`offset: int = 0` | `items: List[Incident]`<br>`total: int`<br>`limit: int`<br>`offset: int` | **Authoritative count returned.** `incidents_repo.count_incidents(...)` executes `SELECT COUNT(*) FROM incidents WHERE status = ?`.<br>Passing `limit=1` returns `.total`. | **SAFE for recurring refresh when `limit=1`.** Payload < 400 bytes.<br>"Active Incidents" count = `OPEN` + `INVESTIGATING`. |
| **Telemetry Source Health** | `GET /api/v1/telemetry/health` | None | `overall_status: "HEALTHY" \| "DEGRADED" \| "OFFLINE"`<br>`active_sources_count: int`<br>`total_sources_count: int`<br>`database_size_bytes: int`<br>`sources: List[SourceHealth]` | Fixed list of collectors (`journald`, `auth.log`, `syslog`, `kern.log`). Evaluates file readability, size, permissions, and ingestion state. | **CRITICAL CORRECTION:** Gate 1 claimed `source.status` has values `'active' \| 'inactive' \| 'unavailable'`.<br>**Real Schema:** `source.available` (boolean), `source.error_reason` (string \| null), `source.total_records` (int), `source.last_collected_at` (str \| null), `source.action_hint` (str \| null).<br>Frontend must bind to `available: boolean`. |
| **Recent Security Alerts** | `GET /api/v1/alerts` | `limit: 5`<br>`offset: 0` | `items: List[Alert]` (`id`, `rule_id`, `title`, `severity`, `status`, `host`, `first_seen`, `last_seen`, `occurrence_count`) | Sorted server-side by `last_seen DESC`. | **SAFE.** Fetch top 5 recent alerts for immediate operational triage. Clicking opens `AlertDetailModal`. |
| **Recent Incidents** | `GET /api/v1/incidents` | `limit: 5`<br>`offset: 0` | `items: List[Incident]` (`id`, `incident_key`, `title`, `severity`, `status`, `primary_host`, `primary_user`, `first_seen`, `last_seen`, `alert_count`, `event_count`) | Sorted server-side by `created_at DESC`. | **SAFE.** Fetch top 5 incidents. Clicking opens `IncidentWorkspaceModal`. |
| **Recent Security Events** (Failures & Critical Telemetry) | `GET /api/v1/events/stats/summary` | `hours: int` | `recent_alerts: List[CanonicalEvent]` | Pre-filtered by backend: `severity IN ('WARNING', 'ALERT', 'CRITICAL') OR outcome = 'FAILURE' LIMIT 10`. | **SAFE.** Directly available in the statistics payload. Clicking opens `EventDetailModal`. |

---

## 4. Protection of Data & Evidence Semantics (Task 3)

The architecture strictly adheres to LogIntel's epistemic integrity guarantees:
1. **Authoritative Telemetry Boundary:** `logintel.db` is read-only from the perspective of UI presentation. No SQL mutations, schemas, or forensic records are modified to accommodate dashboard views.
2. **Analyst State Separation:** Investigation notes, hypotheses, and review statuses reside exclusively in `cases.db`. Dashboard metrics distinguish authoritative telemetry facts (e.g. event counts, collector health) from analyst interpretations (e.g. incident notes, triage status).
3. **Epistemic Labeling:** Detections are labeled with deterministic certainty; correlated entity relationships preserve their confidence levels (`DIRECT`, `STRONG`, `CORRELATED`, `INFERRED`, `WEAK`).
4. **Authenticity Guarantee:** Zero mock data, zero synthetic metrics, zero random numbers. Where telemetry or collector data is missing, the UI explicitly displays `Unavailable`, `No Data`, or `0` (only when confirmed zero by the API).

---

## 5. Validated System-Aware Theming Architecture (Task 4)

### 5.1 Tauri / WebKitGTK Desktop Platform Realities
On Ubuntu Linux (GNOME / FreeDesktop portal), WebKitGTK exposes the desktop appearance preference via `window.matchMedia("(prefers-color-scheme: dark)")`.

### 5.2 Flash Prevention & CSS-First Architecture
To eliminate any visual flash on application launch without fragile script dependencies:
1. **CSS Precedence via Media Query Fallback:**
   ```css
   /* Default variables represent Light theme */
   :root {
     --bg-app: #f4f3ee;
     --bg-surface: #ffffff;
     --text-primary: #181c20;
     /* ... tokens ... */
   }

   /* Native OS Dark mode applies automatically before JS executes */
   @media (prefers-color-scheme: dark) {
     :root:not([data-theme="light"]) {
       --bg-app: #0f1216;
       --bg-surface: #171b21;
       --text-primary: #e6edf3;
       /* ... dark tokens ... */
     }
   }

   /* Explicit User Overrides */
   :root[data-theme="dark"] {
     /* Forced Dark */
   }
   :root[data-theme="light"] {
     /* Forced Light */
   }
   ```
2. **Storage Key & Pre-Mount Initialization:**
   `localStorage.getItem("logintel-theme-preference")` stores `'system' | 'light' | 'dark'`.
   A minimal, non-blocking check in `index.html` sets `<html data-theme="...">` synchronously if an explicit preference is found. If set to `'system'` or unset, the attribute is removed, letting `@media (prefers-color-scheme: dark)` handle the system theme with zero delay.
3. **Live OS Event Listener:**
   `useTheme` hook registers `matchMedia.addEventListener('change', ...)` to update in real time when the user alters their desktop GNOME/KDE dark-mode toggle, requiring no application restart.

### 5.3 Theme Application Across All Visual Elements
- **SVG Charts:** Use `var(--chart-line)`, `var(--chart-grid)`, `var(--text-muted)` within SVG elements so charts recolor instantly on theme toggle without re-rendering or canvas recreation.
- **Attack Graph Visualizer:** Canvas node and edge colors bind to computed CSS custom properties.
- **Badges & Indicators:** Severity badges (`CRITICAL`, `ALERT`, `WARNING`, `NOTICE`, `INFO`) use semantic token pairs (`--badge-critical-bg`, `--badge-critical-border`, `--badge-critical-text`) validated for WCAG AA contrast in both light and dark modes.

---

## 6. Dashboard Information Architecture (Task 5)

The redesigned Overview page is organized into an efficient, information-dense 4-tier desktop hierarchy:

```
+--------------------------------------------------------------------------------------------------+
| TIER 1: OPERATIONAL TELEMETRY & SECURITY KPI STRIP (6 compact metrics)                           |
| [ Total Events ] [ Open Alerts ] [ In Triage ] [ Resolved ] [ Active Incidents ] [ Ingestion ]   |
+--------------------------------------------------------------------------------------------------+
| TIER 2: TEMPORAL TELEMETRY & ALERT DYNAMICS (Grid: 2fr / 1fr)                                     |
| +---------------------------------------------------+ +------------------------------------------+ |
| | Event Activity Timeline (Interactive SVG)         | | Alert Severity & Status Distribution     | |
| | [6h] [12h] [24h] [3d] [7d]                        | | - Severity Breakdown (Critical -> Info)  | |
| | (Padded UTC hourly buckets, min/max/avg markers)  | | - Status Lifecycle (Open, Ack, Resolved) | |
| +---------------------------------------------------+ +------------------------------------------+ |
+--------------------------------------------------------------------------------------------------+
| TIER 3: TAXONOMY & CLASSIFICATION (Grid: 1fr / 1fr)                                              |
| +---------------------------------------------------+ +------------------------------------------+ |
| | Top Ingestion Sources                             | | Prominent Event Classifications (Top 10) | |
| | Ranked bars with percentage of window total       | | Categorical tags with event counts       | |
| +---------------------------------------------------+ +------------------------------------------+ |
+--------------------------------------------------------------------------------------------------+
| TIER 4: ACTIONABLE INVESTIGATION WORKBENCH FEEDS (Tabbed / Dual Panel)                            |
| +---------------------------------------------------+ +------------------------------------------+ |
| | Recent Security Alerts (from alerts table)        | | Telemetry Ingestion Source Health        | |
| | Time | Severity | Title | Host | Status | Action  | | Source | Type | Status | Records | Hint  | |
| +---------------------------------------------------+ +------------------------------------------+ |
+--------------------------------------------------------------------------------------------------+
```

### Navigation & Interaction Bindings
- Clicking **Open Alerts** KPI or Alert rows navigates to `/alerts` or opens [`AlertDetailModal.tsx`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/features/AlertDetailModal.tsx).
- Clicking **Active Incidents** KPI navigates to `/incidents` or opens [`IncidentWorkspaceModal.tsx`](file:///home/khemendra-labs/LogIntel/apps/desktop/src/features/IncidentWorkspaceModal.tsx).
- Clicking **Sources** rows navigates to `/activity` with `source` filter applied.
- Clicking **Severity** rows navigates to `/activity` with `severity` filter applied.

---

## 7. Performance Safeguards & Resource Efficiency (Task 6)

### 7.1 Polling Lifecycle Governance
- **In-Flight Lock:** Introduce `isFetchingRef` in `App.tsx` to prevent overlapping network requests if a slow cycle exceeds the polling interval.
- **Scoped Ingestion Polling:**
  - High-frequency polling (10s): Top-level health pill and alert/incident badge counts (`limit=1` queries, payload < 1 KB total).
  - On-Demand / Route-Scoped polling: `fetchEventStatistics(hours)` is executed when the `Overview` tab is active or upon manual "Sync Telemetry" button click. It is **not** continuously polled in the background while analysts are working in `IncidentWorkspaceModal` or `ThreatHuntingPage`.
- **Clean Unmount:** Timers, intervals, and `matchMedia` listeners are cleanly removed in `useEffect` cleanup handlers.

### 7.2 Zero-Dependency Native SVG Visualization
- No external chart libraries (e.g. Chart.js, Recharts) will be introduced.
- Time-series and distribution charts will be implemented as pure, responsive SVG components:
  - Memoized coordinate transformations via `useMemo`.
  - Zero heavy DOM nodes; clean SVG path rendering.
  - Zero addition to npm dependencies or runtime vulnerabilities.

---

## 8. Implementation Sequence & Execution Roadmap (Gate 3 Plan)

Following Gate 2 approval, implementation will proceed in 4 incremental steps:

```mermaid
graph TD
  Step1[Step 1: Design System & Theme Engine] --> Step2[Step 2: SVG Chart Primitives & Transformers]
  Step2 --> Step3[Step 3: Redesigned Overview Dashboard]
  Step3 --> Step4[Step 4: Global Workbench Consistency & Navigation]
  Step4 --> Step5[Step 5: Testing & Production Build Verification]
```

1. **Step 1: Design System Tokens & System-Aware Theming**
   - Update `apps/desktop/src/styles/theme.css` with semantic light/dark variable tokens and OS media-query fallback.
   - Implement `apps/desktop/src/lib/theme.ts` (theme state, storage persistence, OS listener).
   - Add theme switcher control in `apps/desktop/src/components/Header.tsx`.
2. **Step 2: Native Data-Driven SVG Chart Primitives**
   - Create `apps/desktop/src/components/charts/TimeSeriesChart.tsx` (hourly SVG line/area chart with hover tooltip and bucket padding).
   - Create `apps/desktop/src/components/charts/DistributionBarChart.tsx` (horizontal ranked distribution bars).
   - Add unit tests for timeline coordinate scaling and zero-bucket padding.
3. **Step 3: Redesigned Overview Page Integration**
   - Update `apps/desktop/src/pages/OverviewPage.tsx` with the 4-tier operational layout.
   - Bind real backend data: operational KPIs, time-range selector (`6h`, `12h`, `24h`, `3d`, `7d`), alert/incident distribution, source health with `source.available` mapping, and recent alerts/incidents tables.
4. **Step 4: Workbench Polish & App-Level Request Governance**
   - Refactor `loadData` in `apps/desktop/src/App.tsx` with in-flight lock and route-aware fetching.
   - Verify modal contrast in both themes across `IncidentWorkspaceModal.tsx`, `AlertDetailModal.tsx`, and `InvestigationMultiHostWorkbench.tsx`.
5. **Step 5: Testing, Build Verification & Documentation**
   - Add frontend unit tests in `src/__tests__/theme.test.ts` and `src/__tests__/dashboard.test.ts`.
   - Run Vitest suite (`npm test -- --run`) and production build (`npm run build`).
   - Document final verification in `docs/FRONTEND_REDESIGN_FINAL_VERIFICATION_REPORT.md`.

---

## 9. Files Expected to Change During Implementation

| File Path | Nature of Change | Justification |
| :--- | :--- | :--- |
| `apps/desktop/src/styles/theme.css` | Edit | Centralize semantic CSS tokens; implement light/dark variables and media queries. |
| `apps/desktop/src/components/Header.tsx` | Edit | Add theme mode toggle (`System` \| `Light` \| `Dark`); preserve refresh and health triggers. |
| `apps/desktop/src/lib/theme.ts` | New | Theme management hook, persistence, and OS preference listener. |
| `apps/desktop/src/components/charts/TimeSeriesChart.tsx` | New | Reusable, zero-dependency SVG time-series chart with bucket padding and tooltips. |
| `apps/desktop/src/components/charts/DistributionBarChart.tsx` | New | Reusable SVG/CSS distribution bar chart for sources and severity breakdowns. |
| `apps/desktop/src/pages/OverviewPage.tsx` | Edit | Implement 4-tier information-rich operational layout backed by verified APIs. |
| `apps/desktop/src/App.tsx` | Edit | In-flight request locking, route-aware stats polling, and modal drill-down wiring. |
| `apps/desktop/index.html` | Edit | Pre-render theme attribute initialization script to eliminate visual flash. |
| `apps/desktop/src/__tests__/theme.test.ts` | New | Unit tests for theme resolution, storage persistence, and OS change events. |
| `apps/desktop/src/__tests__/dashboard.test.ts` | New | Unit tests for hourly bucket padding, count mapping, and empty-state rendering. |

*Note: No backend files, database schemas, or Tauri native configurations will be altered.*

---

## 10. Risk Assessment & Rollback Strategy

| Identified Risk | Severity | Impact | Mitigation Strategy |
| :--- | :--- | :--- | :--- |
| **OS Dark Mode Mismatch** | Medium | Low contrast if WebKitGTK portal reports inaccurate scheme | Provide explicit user override in Header (`Light` / `Dark`) stored in `localStorage`, overriding OS portal. |
| **Missing Timeline Buckets** | Low | Broken or distorted time-series chart | Client-side hourly transformer computes the full sequence of ISO hour buckets for the window and pads absent intervals with `0`. |
| **Concurrent Polling Contention** | Medium | SQLite database lock on `logintel.db` | Protect `loadData` with `isFetchingRef` guard; restrict heavy `stats/summary` queries to the Overview tab. |
| **Component Regression in Workbenches** | High | Broken investigation modals or lost functionality | Preserve all existing modal props, state interfaces, and API signatures. Run Vitest regression tests at each step. |

**Rollback Procedure:**
All changes are isolated to `apps/desktop/src/`. Because Git working tree is completely clean at `932f3ed`, any failing step can be reverted cleanly using standard Git diff inspection without risking backend or database state.

---

## 11. Read-Only Verification Confirmation

I hereby confirm that:
1. Every detail, schema field, and endpoint in this report has been verified against active source code in `/home/khemendra-labs/LogIntel`.
2. **Zero lines of application source code or tests were modified during this audit.**
3. No database files or schemas were changed.
4. No commits, pushes, or package builds were performed.
5. The implementation plan is verified, corrected, and ready for user approval (Gate 2).
