# LOGINTEL — PRODUCTION NAVIGATION AND WORKBENCH MAP
**Document Reference:** `docs/PRODUCTION_NAVIGATION_AND_WORKBENCH_MAP.md`  
**Audit Phase:** Phase 1: Read-Only Repository, Frontend, Backend & Installer Traceability  
**Execution Date:** 2026-10-22  
**Target Platform:** Ubuntu Linux 24.04 LTS x86_64  
**Scope:** Complete Reconstructed Desktop Navigation Tree & Workbench Hierarchy.

---

## 1. Top-Level Navigation Architecture

The desktop application layout is defined in `apps/desktop/src/App.tsx` and orchestrated via `apps/desktop/src/components/Navigation.tsx`. The application navigation is organized into three operational domains comprising **9 top-level tabs**, **1 central investigation modal container hosting 15 specialized workbenches**, and **5 auxiliary forensic modal dialogs**.

```
LOGINTEL DESKTOP SHELL (apps/desktop/src/App.tsx)
│
├── TOP-LEVEL NAVIGATION BAR (apps/desktop/src/components/Navigation.tsx)
│   │
│   ├── DOMAIN 1: TELEMETRY & OPERATIONS
│   │   ├── [Tab: overview]    Overview Page (apps/desktop/src/pages/OverviewPage.tsx)
│   │   ├── [Tab: activity]    Activity Page (apps/desktop/src/pages/ActivityPage.tsx)
│   │   └── [Tab: diagnostics] System Diagnostics Page (apps/desktop/src/pages/DiagnosticsPage.tsx)
│   │
│   ├── DOMAIN 2: DETECTION & TRIAGE
│   │   ├── [Tab: incidents]   Incidents Page (apps/desktop/src/pages/IncidentsPage.tsx)
│   │   ├── [Tab: alerts]      Alerts Page (apps/desktop/src/pages/AlertsPage.tsx)
│   │   ├── [Tab: rules]       Rules Catalog Page (apps/desktop/src/pages/RulesPage.tsx)
│   │   └── [Tab: hunting]     Threat Hunting Page (apps/desktop/src/pages/ThreatHuntingPage.tsx)
│   │
│   └── DOMAIN 3: INVESTIGATION & FORENSICS
│       ├── [Tab: cases]       Investigations / Cases Page (apps/desktop/src/pages/CasesPage.tsx)
│       └── [Tab: multihost]   Multi-Host Analysis Page (apps/desktop/src/pages/MultiHostPage.tsx)
│
├── CENTRAL INVESTIGATION CONTAINER
│   └── IncidentWorkspaceModal (apps/desktop/src/features/IncidentWorkspaceModal.tsx)
│       ├── Sub-Tab 1:  Attack Graph (apps/desktop/src/features/AttackGraphVisualizer.tsx)
│       ├── Sub-Tab 2:  Attack Path Reconstruction
│       ├── Sub-Tab 3:  Unified Multi-Source Timeline (apps/desktop/src/features/InvestigationUnifiedTimeline.tsx)
│       ├── Sub-Tab 4:  Incident Alerts Roster
│       ├── Sub-Tab 5:  Observed Incident Entities
│       ├── Sub-Tab 6:  MITRE ATT&CK Matrix Mapping
│       ├── Sub-Tab 7:  Notes & Tamper-Evident Audit Ledger
│       ├── Sub-Tab 8:  Evidence Workbench (apps/desktop/src/features/InvestigationEvidenceWorkbench.tsx)
│       ├── Sub-Tab 9:  Findings & Hypotheses (apps/desktop/src/features/InvestigationFindingsWorkbench.tsx)
│       ├── Sub-Tab 10: Governed Threat Hunting (apps/desktop/src/features/InvestigationThreatHuntWorkbench.tsx)
│       ├── Sub-Tab 11: Formal Reports & Packages (apps/desktop/src/features/InvestigationReportWorkbench.tsx)
│       ├── Sub-Tab 12: Cross-Case Comparison (apps/desktop/src/features/InvestigationCaseComparisonWorkbench.tsx)
│       ├── Sub-Tab 13: Forensic Quality Review (apps/desktop/src/features/InvestigationQualityReviewWorkbench.tsx)
│       ├── Sub-Tab 14: Multi-Host Analysis (apps/desktop/src/features/InvestigationMultiHostWorkbench.tsx)
│       └── Sub-Tab 15: Local AI Intelligence (apps/desktop/src/features/InvestigationIntelligencePanel.tsx)
│
└── AUXILIARY FORENSIC MODALS
    ├── EventDetailModal (apps/desktop/src/components/EventDetailModal.tsx)
    ├── AlertDetailModal (apps/desktop/src/components/AlertDetailModal.tsx)
    ├── EntityPivotModal (apps/desktop/src/components/EntityPivotModal.tsx)
    ├── TelemetryHealthModal (apps/desktop/src/components/TelemetryHealthModal.tsx)
    └── EventForensicsModal (apps/desktop/src/features/EventForensicsModal.tsx)
```

---

## 2. Reconstructed Navigation Tree & Workbench Specifications

### 2.1 Top-Level Navigation Pages

| Page Identifier | UI Entry Point | Source File | Prerequisites | Backend API Endpoints Invoked | Test Evidence | Integration Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Overview** | Sidebar "Overview" button | `apps/desktop/src/pages/OverviewPage.tsx` | None | `GET /system/status`<br>`GET /telemetry/health`<br>`GET /events/statistics` | `dashboard.test.ts`<br>`navigation_and_integration.test.ts` | **Fully Functional**.<br>Displays live KPIs (52,130 events); truth-telling offline banner when disconnected. |
| **Activity** | Sidebar "Activity" button | `apps/desktop/src/pages/ActivityPage.tsx` | None | `GET /api/v1/events`<br>`GET /api/v1/events/{id}` | `activity_recovery.test.ts` (9 tests) | **Fully Functional**.<br>Paginates 52,130 events with search, severity filter, source filter, and auto-retry recovery. |
| **System Diagnostics** | Sidebar "System Diagnostics" button | `apps/desktop/src/pages/DiagnosticsPage.tsx` | None | `GET /api/v1/telemetry/health`<br>`GET /api/v1/system/status`<br>`POST /api/v1/system/ingest` | `navigation_and_integration.test.ts` | **Fully Functional**.<br>Full-page audit of all 7 ingestion sources, file permissions, and manual sync trigger. |
| **Incidents** | Sidebar "Incidents" button | `apps/desktop/src/pages/IncidentsPage.tsx` | None | `GET /api/v1/incidents`<br>`POST /api/v1/incidents/correlate` | `api.test.ts` | **Fully Functional**.<br>Filters incidents by status/severity; triggers alert correlation engine. |
| **Alerts** | Sidebar "Alerts" button | `apps/desktop/src/pages/AlertsPage.tsx` | None | `GET /api/v1/alerts`<br>`PATCH /api/v1/alerts/{id}/status` | `api.test.ts` | **Fully Functional**.<br>Status filtering (OPEN, ACKNOWLEDGED, RESOLVED, FALSE_POSITIVE). |
| **Rules Catalog** | Sidebar "Rules Catalog" button | `apps/desktop/src/pages/RulesPage.tsx` | None | `GET /api/v1/detection/rules` | `api.test.ts` | **Fully Functional**.<br>Renders all 26 canonical detection rules with MITRE technique mappings. |
| **Threat Hunting** | Sidebar "Threat Hunting" button | `apps/desktop/src/pages/ThreatHuntingPage.tsx` | None | `POST /api/v1/investigations/threat-hunting/query`<br>`GET /investigations/process/{pid}` | `api.test.ts` | **Fully Functional**.<br>Standalone SQL hunting console with forensic process/socket inspector modal. |
| **Investigations / Cases** | Sidebar "Investigations" button | `apps/desktop/src/pages/CasesPage.tsx` | None | `GET /api/v1/cases`<br>`POST /api/v1/cases` | `navigation_and_integration.test.ts` | **Fully Functional**.<br>Browses 2,648 cases in `cases.db`; case search, creation, and modal opening. |
| **Multi-Host Analysis** | Sidebar "Multi-Host Analysis" button | `apps/desktop/src/pages/MultiHostPage.tsx` | Case Selection (or defaults to first active case) | `GET /api/v1/cases/{id}/hosts`<br>`GET .../lateral-traces`<br>`GET .../timeline`<br>`POST .../scope` | `multihost.test.ts` (23 tests) | **Fully Functional**.<br>Fleet investigation page with case dropdown, lateral traces, host timeline, and scope editor. |

---

### 2.2 Central Investigation Container (`IncidentWorkspaceModal`)

When an analyst clicks an incident from `IncidentsPage` or a case from `CasesPage`, `IncidentWorkspaceModal.tsx` mounts with the active `incidentId` and `initialCaseId`. It contains a tabbed workspace exposing **all 15 advanced forensic workbenches**:

| Workspace Tab | Sub-Workbench Component | Source File | Analyst Capability | Backend APIs Invoked | Functional Completeness |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1. Attack Graph** | `AttackGraphVisualizer` | `apps/desktop/src/features/AttackGraphVisualizer.tsx` | Interactive SVG node-edge graph of attack stages with zoom/pan | `GET /api/v1/incidents/{id}/attack-path` | **Fully Functional**.<br>Fallback layout prevents NaN coordinate crashes. |
| **2. Attack Path** | Inline Attack Path Cards | `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Linear chronological progression cards showing tactic phases | `GET /api/v1/incidents/{id}/attack-path` | **Fully Functional**.<br>Step-by-step kill-chain view. |
| **3. Timeline** | `InvestigationUnifiedTimeline` | `apps/desktop/src/features/InvestigationUnifiedTimeline.tsx` | Unified timeline with scrubber and VCR replay mode | `GET /cases/{id}/timeline/unified`<br>`GET .../timeline/replay` | **Fully Functional**.<br>M7.2 multi-source chronological stream. |
| **4. Alerts** | Inline Incident Alerts Table | `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Roster of all alerts correlated into this specific incident | `GET /api/v1/incidents/{id}` | **Fully Functional**.<br>Direct alert detail inspection links. |
| **5. Entities** | Inline Incident Entities Grid | `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Grid of observed IPs, hostnames, users with pivot links | `GET /api/v1/incidents/{id}` | **Fully Functional**.<br>Clicking entity opens `EntityPivotModal`. |
| **6. MITRE ATT&CK**| Inline Heatmap & Tactics List | `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Mapping of incident alerts to Enterprise ATT&CK matrix | `GET /api/v1/incidents/{id}/mitre` | **Fully Functional**.<br>Tactic coverage and technique badges. |
| **7. Notes** | Inline Notes & Audit Ledger | `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Markdown notes with append-only tamper-evident audit history | `POST /investigations/{id}/notes`<br>`GET .../notes/audit` | **Fully Functional**.<br>Stored in `logintel.db:investigation_notes`. |
| **8. Evidence** | `InvestigationEvidenceWorkbench` | `apps/desktop/src/features/InvestigationEvidenceWorkbench.tsx` | Evidence collections with cryptographic Blake2b-256 seal | `POST /cases/{id}/evidence/collections`<br>`POST .../collections/{col_id}/seal` | **Fully Functional**.<br>M7.3 evidentiary chain of custody. |
| **9. Findings** | `InvestigationFindingsWorkbench` | `apps/desktop/src/features/InvestigationFindingsWorkbench.tsx` | Structured findings and Analysis of Competing Hypotheses (ACH) | `POST /cases/{id}/findings`<br>`GET .../hypotheses` | **Fully Functional**.<br>M7.4 epistemic hypothesis evaluation matrix. |
| **10. Hunting** | `InvestigationThreatHuntWorkbench`| `apps/desktop/src/features/InvestigationThreatHuntWorkbench.tsx`| Governed hunting proposals, approval gates, bounded 72h window | `POST /cases/{id}/hunts/{id}/execute`<br>`GET .../hunts/history` | **Fully Functional**.<br>M7.5 governed query safety engine. |
| **11. Report** | `InvestigationReportWorkbench` | `apps/desktop/src/features/InvestigationReportWorkbench.tsx` | Formal report versioning, markdown export, Blake2b zip package | `POST /cases/{id}/reports`<br>`POST .../packages` | **Fully Functional**.<br>M7.6 / M7.9 multi-version report compiler. |
| **12. Comparison**| `InvestigationCaseComparisonWorkbench` | `apps/desktop/src/features/InvestigationCaseComparisonWorkbench.tsx` | Cross-case comparison analyzing overlapping entities and time | `POST /api/v1/cases/{id}/comparison` | **Fully Functional**.<br>M7.7 / M7.10 cross-case Jaccard similarity. |
| **13. Review** | `InvestigationQualityReviewWorkbench` | `apps/desktop/src/features/InvestigationQualityReviewWorkbench.tsx` | 12-point forensic closure gates, blocker acknowledgment | `GET /cases/{id}/review/status`<br>`POST .../close` | **Fully Functional**.<br>M7.8 / M7.11 strict closure gatekeeper. |
| **14. Multi-Host**| `InvestigationMultiHostWorkbench` | `apps/desktop/src/features/InvestigationMultiHostWorkbench.tsx` | In-case fleet dossier, lateral traces, host timeline, scope editor | `GET /cases/{id}/hosts`<br>`GET .../lateral-traces`<br>`POST .../scope` | **Fully Functional**.<br>M7.12 multi-host investigation engine. |
| **15. AI Copilot**| `InvestigationIntelligencePanel`| `apps/desktop/src/features/InvestigationIntelligencePanel.tsx` | Local epistemic AI Q&A, claim grounding, question generator | `POST /api/v1/ai/investigations/{id}/analyze` | **Fully Functional**.<br>M5 / M7.10 local offline AI assistant. |

---

### 2.3 Auxiliary Forensic Modals

| Modal Identifier | Trigger Mechanism | Source File | Purpose | APIs Invoked |
| :--- | :--- | :--- | :--- | :--- |
| **EventDetailModal** | Click any event row or ID badge | `apps/desktop/src/components/EventDetailModal.tsx` | Inspect raw JSON, normalized fields, parser, SHA-256 fingerprint | `GET /api/v1/events/{id}` |
| **AlertDetailModal** | Click any alert row or ID badge | `apps/desktop/src/components/AlertDetailModal.tsx` | Triage alert, transition status, view linked evidence | `GET /api/v1/alerts/{id}/evidence`<br>`PATCH /api/v1/alerts/{id}/status` |
| **EntityPivotModal** | Click any IP, host, or user pill | `apps/desktop/src/components/EntityPivotModal.tsx` | 360-degree pivot across all co-occurring alerts and events | `GET /api/v1/investigations/entities/pivot` |
| **TelemetryHealthModal**| Click header telemetry badge | `apps/desktop/src/components/TelemetryHealthModal.tsx` | Quick health summary of all 7 ingestion sources | `GET /api/v1/telemetry/health` |
| **EventForensicsModal** | Click "Forensics" in Threat Hunting | `apps/desktop/src/features/EventForensicsModal.tsx` | Deep Linux process ancestry tree and socket connections | `GET /investigations/process/{pid}`<br>`GET /investigations/network/sockets` |

---

## 3. Structural Gap Determination: Missing vs Unreachable vs Disconnected

The user reported that *only a small portion of expected functionality was visible in the installed app*. This audit evaluated whether features were:
1. **Genuinely absent?**  
   *No.* All 15 workbenches and all 9 top-level pages are fully authored in the repository source code.
2. **Implemented but unreachable?**  
   *In the prior installed binary (`/usr/bin/logintel-bin`), yes.* The top-level tabs for Investigations (`CasesPage`), Multi-Host Analysis (`MultiHostPage`), and System Diagnostics (`DiagnosticsPage`) were not present in the sidebar of that older compiled build. In the updated source, all 9 are reachable directly from the primary navigation bar.
3. **Reachable but disconnected?**  
   *No.* Every component is wired to a genuine backend API helper in `apps/desktop/src/lib/api.ts` which calls an authenticated endpoint on `http://127.0.0.1:41721/api/v1`. Zero endpoints return mock data.
4. **Connected but incomplete?**  
   *No.* Form submissions mutate real SQLite databases (`logintel.db` and `cases.db`), and responses update React state truthfully.
5. **Operational but lacking suitable data?**  
   *Yes, for Alerts and Incidents.* In the host database `~/.local/share/logintel/logintel.db`, there are 52,130 events and 26 rules, but 0 alerts and 0 incidents have been generated yet. This correctly produces a truthful empty state in `AlertsPage` and `IncidentsPage`.
6. **Already working but not discoverable?**  
   *Yes.* Advanced investigation workbenches (timeline replay, evidence sealing, competing hypotheses, report packaging, closure review) were housed inside `IncidentWorkspaceModal.tsx`. If an analyst did not open an incident, these workbenches were completely invisible. Providing dedicated top-level tabs for **Investigations** and **Multi-Host Analysis** solves this discoverability barrier.
