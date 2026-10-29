# LOGINTEL — PRODUCTION FEATURE INVENTORY (M1 THROUGH M7.12.2)
**Document Reference:** `docs/PRODUCTION_FEATURE_INVENTORY.md`  
**Audit Phase:** Phase 1: Read-Only Repository, Frontend, Backend & Installer Traceability  
**Execution Date:** 2026-10-22  
**Target Platform:** Ubuntu Linux 24.04 LTS x86_64  
**Safety Protocol:** Strict Read-Only Audit — Zero Code Modifications, Zero DB Writes, Zero Reinstalls.

---

## 1. Executive Context & Scope Definition

LogIntel has accumulated a rich body of engineering across Milestones M1 through M7.12.2. The core objective of this inventory is to comprehensively catalog every documented user capability, establish its authentic requirement source from milestone documentation, cite its current repository implementation evidence, and document any historical roadmap attribution shifts or ambiguities.

---

## 2. Milestone-by-Milestone Comprehensive Feature Inventory

### 2.1 Milestone M1 & M1.1: Desktop Foundation, Telemetry Ingestion & Storage
*Primary References:* `docs/architecture/M1_FOUNDATION_REPORT.md`, `docs/M1_1_FOUNDATION_HARDENING_REPORT.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M1-F01** | **Native Desktop Shell & Process Supervisor**<br>Tauri v2 desktop shell hosting WebKitGTK frontend and supervising the lifecycle of the local Python engine child process. | `docs/architecture/M1_FOUNDATION_REPORT.md:28` | Backend: `apps/desktop/src-tauri/src/lib.rs`<br>Frontend: `apps/desktop/src/main.tsx` | Core desktop host foundation. Child process lifecycle managed via POSIX signals (`SIGTERM`/`SIGKILL`). |
| **M1-F02** | **HTTP/IPC Engine Readiness Handshake**<br>Native shell waits for `GET /api/v1/handshake` to return `{"service": "logintel-engine"}` on port 41721 before releasing frontend. | `docs/M1_1_FOUNDATION_HARDENING_REPORT.md:45` | Backend: `apps/engine/src/logintel/api/routes.py:105`<br>Native: `apps/desktop/src-tauri/src/lib.rs:15` | Handshake timeout configured to 6.0s with 200ms poll intervals to eliminate startup race conditions. |
| **M1-F03** | **Token-Based IPC Authentication**<br>Cryptographically random 64-character token stored with `0600` permissions at `~/.local/share/logintel/.engine_token`. | `docs/M1_1_FOUNDATION_HARDENING_REPORT.md:82` | Backend: `apps/engine/src/logintel/api/routes.py:34`<br>Frontend: `apps/desktop/src/lib/api.ts:177` | All API routes except `/handshake` enforce HTTP `Authorization: Bearer <token>`. Exposed to frontend via Tauri IPC `get_engine_token`. |
| **M1-F04** | **Authoritative SQLite Telemetry Store (`logintel.db`)**<br>WAL-mode persistent SQLite database with strict foreign keys, storing raw and canonical events. | `docs/architecture/M1_FOUNDATION_REPORT.md:112` | Backend: `apps/engine/src/logintel/storage/db.py`<br>Storage: `~/.local/share/logintel/logintel.db` | Contains 52,130 real telemetry events on host. Integrity check: 0 errors. |
| **M1-F05** | **Canonical Telemetry Ingestion Pipeline**<br>Ingestion of local Linux logs (`/var/log/auth.log`, `syslog`, `kern.log`, systemd journal) into normalized schema. | `docs/architecture/M1_FOUNDATION_REPORT.md:154` | Backend: `apps/engine/src/logintel/telemetry/sources.py`, `logintel/parsers/`<br>Schema: `docs/schemas/CANONICAL_SCHEMA.md` | Tracks ingestion offsets and file fingerprints in `ingestion_state` table. |
| **M1-F06** | **Activity Page: Canonical Event Querying & Filtering**<br>Paginated event browser with full-text search, severity filters, source filters, and timestamp ranges. | `docs/architecture/M1_FOUNDATION_REPORT.md:210` | Route: `GET /api/v1/events`<br>Frontend: `apps/desktop/src/pages/ActivityPage.tsx` | Queries `logintel.db:events`. Supports auto-retry with exponential backoff on connection failure. |
| **M1-F07** | **Event Detail Forensics Modal**<br>Inspection modal displaying raw log lines, normalized canonical fields, parser metadata, and SHA-256 event fingerprint. | `docs/architecture/M1_FOUNDATION_REPORT.md:245` | Route: `GET /api/v1/events/{id}`<br>Frontend: `apps/desktop/src/components/EventDetailModal.tsx` | Triggered by clicking any row in `ActivityPage` or event timeline chips. |
| **M1-F08** | **System Diagnostics & Telemetry Health**<br>Live audit of ingestion source active/error states, read permissions, file paths, and manual sync execution. | `docs/M1_1_FOUNDATION_HARDENING_REPORT.md:120` | Route: `GET /api/v1/telemetry/health`<br>Frontend: `apps/desktop/src/pages/DiagnosticsPage.tsx` | Formerly only a modal; promoted to dedicated top-level page in full desktop redesign. |

---

### 2.2 Milestone M2: Detection Engine, Rules Catalog & Alert Lifecycle
*Primary References:* `docs/M2_1_RULE_SCHEMA.md` through `docs/M2_11_PACKAGING_VERIFICATION_REPORT.md`, `docs/audits/LOGINTEL_M2_FINAL_FORENSIC_CLOSURE_REPORT.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M2-F01** | **Deterministic YAML Detection Rules Engine**<br>Sliding event-time window evaluation of deterministic YAML rule specifications against ingested events. | `docs/M2_1_RULE_SCHEMA.md`<br>`docs/M2_8_DETECTION_API_REPORT.md` | Backend: `apps/engine/src/logintel/detection/engine.py`<br>Rules: `rules/` (26 canonical YAML rules) | Rules categorized into authentication, network, privilege, process, and security. Zero cloud dependency. |
| **M2-F02** | **Detection Rules Catalog View**<br>Browse, filter, and inspect YAML rules by family, severity, MITRE ATT&CK technique, and threshold criteria. | `docs/M2_9_DETECTION_GUI_REPORT.md:34` | Route: `GET /api/v1/detection/rules`<br>Frontend: `apps/desktop/src/pages/RulesPage.tsx` | Packaged to `/usr/share/logintel/rules` and `/usr/lib/logintel/engine/rules`. |
| **M2-F03** | **Alert Lifecycle State Machine**<br>Deterministic generation and state tracking of security alerts (`OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`). | `docs/M2_7_ALERT_LIFECYCLE_REPORT.md:15` | Route: `GET /api/v1/alerts`, `PATCH .../status`<br>Frontend: `apps/desktop/src/pages/AlertsPage.tsx` | Mutates `logintel.db:alerts`. Transitions require analyst comments and record audit timestamps. |
| **M2-F04** | **Alert Evidence Provenance Inspection**<br>Cryptographic linking of alerts to the underlying canonical event IDs and raw log records that triggered the rule. | `docs/M2_7_ALERT_LIFECYCLE_REPORT.md:68` | Route: `GET /api/v1/alerts/{id}/evidence`<br>Frontend: `apps/desktop/src/components/AlertDetailModal.tsx` | Queries `logintel.db:detection_evidence`. |
| **M2-F05** | **Historical Telemetry Replay Engine**<br>Re-evaluate detection rules against historical event spans without modifying original event timestamps. | `docs/M2_10_HISTORICAL_REPLAY_REPORT.md:20` | Script: `/usr/bin/logintel-replay`<br>Backend: `apps/engine/src/logintel/detection/replay.py` | CLI and backend service supporting retrospective detection against historical telemetry. |

---

### 2.3 Milestone M3: Incident Correlation, Attack Graphs & MITRE ATT&CK
*Primary References:* `docs/M3_1_INCIDENT_MODELS_REPORT.md` through `docs/M3_8_E2E_INCIDENT_VERIFICATION_REPORT.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M3-F01** | **Multi-Alert Incident Correlation Engine**<br>Deterministic aggregation of related alerts into high-context security incidents based on entity overlap and temporal windows. | `docs/M3_4_INCIDENT_CORRELATION_ENGINE_REPORT.md` | Route: `POST /api/v1/incidents/correlate`<br>Backend: `apps/engine/src/logintel/correlation/engine.py` | Populates `logintel.db:incidents`, `incident_alerts`, and `incident_entities`. |
| **M3-F02** | **Incidents Roster & Triage Management**<br>Filter incidents by status (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`), severity, and affected host. | `docs/M3_7_INCIDENT_GUI_WORKSPACE_REPORT.md:40` | Route: `GET /api/v1/incidents`<br>Frontend: `apps/desktop/src/pages/IncidentsPage.tsx` | Provides overview cards and "Correlate Alerts Now" manual trigger. |
| **M3-F03** | **Interactive Attack Path Reconstruction**<br>Directed graph reconstruction showing progression of attacks through initial access, privilege escalation, and lateral movement. | `docs/M3_5_INCIDENT_REST_API_REPORT.md:92` | Route: `GET /api/v1/incidents/{id}/attack-path`<br>Frontend: `apps/desktop/src/features/AttackGraphVisualizer.tsx` | Renders interactive SVG graph with zoom/pan and node inspection. |
| **M3-F04** | **MITRE ATT&CK Matrix Heatmap Mapping**<br>Tactic-and-technique breakdown of incident activity with confidence scoring and tactic coverage matrix. | `docs/M3_5_INCIDENT_REST_API_REPORT.md:140` | Route: `GET /api/v1/incidents/{id}/mitre`<br>Frontend: `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Maps observed rule firings to Enterprise ATT&CK matrix. |
| **M3-F05** | **Incident Status State Machine & Containment**<br>Formal lifecycle state transitions enforcing containment notes and audit tracking. | `docs/M3_1_INCIDENT_MODELS_REPORT.md:55` | Route: `PATCH /api/v1/incidents/{id}/status`<br>Frontend: `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Validates against `ALLOWED_INCIDENT_STATUS_TRANSITIONS`. |

---

### 2.4 Milestone M4: Investigation Workspace & Dossier Operations
*Primary References:* `docs/M4_IMPLEMENTATION_AND_FORENSIC_VERIFICATION_REPORT.md`, `docs/M4_CORRECTIVE_VERIFICATION_REPORT.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M4-F01** | **Dedicated Investigation Workspace Modal / Dossier**<br>Multi-tab analyst workspace containing attack graph, timeline, notes, evidence, and entity analysis. | `docs/M4_IMPLEMENTATION_AND_FORENSIC_VERIFICATION_REPORT.md:32` | Route: `GET /api/v1/investigations/{id}/dossier`<br>Frontend: `apps/desktop/src/features/IncidentWorkspaceModal.tsx` | Central orchestration container hosting 15 investigation workbench tabs. |
| **M4-F02** | **Analyst Investigation Notes & Tamper-Evident Audit**<br>Create, update, and soft-delete analyst notes with immutable append-only audit trail. | `docs/M4_IMPLEMENTATION_AND_FORENSIC_VERIFICATION_REPORT.md:95` | Route: `POST /api/v1/investigations/{id}/notes`, `GET .../audit`<br>Frontend: `IncidentWorkspaceModal.tsx` (Notes tab) | Stored in `logintel.db:investigation_notes` and `investigation_notes_audit`. |
| **M4-F03** | **360-Degree Entity Pivot Modal**<br>Pivot across any IP address, user account, or host to reveal all co-occurring events, alerts, and incidents across the system. | `docs/M4_IMPLEMENTATION_AND_FORENSIC_VERIFICATION_REPORT.md:150` | Route: `GET /api/v1/investigations/entities/pivot`<br>Frontend: `apps/desktop/src/components/EntityPivotModal.tsx` | Accessible by clicking any entity chip throughout the application. |

---

### 2.5 Milestone M5: Local AI Investigation Assistance
*Primary References:* `docs/M5_ARCHITECTURE_AUDIT_REPORT.md` through `docs/M5.12_FINAL_CLOSURE_REPORT.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M5-F01** | **Evidence-Grounded Local AI Advisory Engine**<br>Local natural-language Q&A generating structured hypotheses and answering investigation queries without cloud APIs. | `docs/M5.1_IMPLEMENTATION_AND_VERIFICATION_REPORT.md`<br>`docs/M5.12_FINAL_CLOSURE_REPORT.md` | Route: `POST /api/v1/ai/investigations/{id}/analyze`<br>Frontend: `apps/desktop/src/features/InvestigationIntelligencePanel.tsx` | Enforces 100% offline local inference boundary. Strictly separates AI advisory output from authoritative evidence. |
| **M5-F02** | **Claim-to-Evidence Grounding & Tracing**<br>Every assertion made by the local model must link to concrete canonical event IDs or alert IDs in the database. | `docs/M5.4_IMPLEMENTATION_AND_FORENSIC_VERIFICATION_REPORT.md` | Models: `ClaimTrace`, `AIInvestigationResponse`<br>Backend: `apps/engine/src/logintel/ai/workspace_service.py` | Visualized in `InvestigationIntelligencePanel` with clickable evidence citation badges. |
| **M5-F03** | **Investigative Questions & Gaps Suggestion**<br>Model suggests recommended next queries, potential blind spots, and competing hypothesis tests. | `docs/M5.6_IMPLEMENTATION_AND_FORENSIC_VERIFICATION_REPORT.md` | Route: `GET /api/v1/ai/investigations/{id}/questions`<br>Frontend: `InvestigationIntelligencePanel.tsx` | Persisted to `cases.db:case_investigation_questions`. |

---

### 2.6 Milestone M6: Host Intelligence & Deep Linux Telemetry
*Primary References:* `docs/M6.1_ADVANCED_LINUX_TELEMETRY_ARCHITECTURE_AUDIT.md` through `docs/M6.10_FINAL_FORENSIC_CERTIFICATION_AUDIT.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M6-F01** | **Deep Process Execution Forensics (Auditd)**<br>Reconstruct process ancestry, process tree, CLI args, PID/PPID hierarchy, namespace IDs, and cgroups. | `docs/M6.2_PROCESS_EXECUTION_TELEMETRY.md` | Route: `GET /api/v1/investigations/process/{pid}`<br>Frontend: `apps/desktop/src/features/EventForensicsModal.tsx` | Reconstructs execve/fork trees from auditd and kern.log telemetry. |
| **M6-F02** | **Identity & Session Continuity**<br>Track login sessions, user impersonation (`su`, `sudo`), TTY allocation, and UID/EUID transitions. | `docs/M6.3_IDENTITY_AND_SESSION_CONTINUITY.md` | Route: `GET /api/v1/investigations/identity/sessions`<br>Backend: `apps/engine/src/logintel/telemetry/identity.py` | Tracks privilege escalations and PAM session lifetimes. |
| **M6-F03** | **Network Socket & Connection Telemetry**<br>Track socket open/close events, IP/port endpoints, protocol, and associate connections with process IDs. | `docs/M6.4_NETWORK_SOCKET_TELEMETRY.md` | Route: `GET /api/v1/investigations/network/sockets`<br>Frontend: `EventForensicsModal.tsx` (Sockets tab) | Integrates `/proc/net` reader with canonical network events. |
| **M6-F04** | **Filesystem Persistence & Tampering Audits**<br>Detect modifications to persistence hooks (`cron`, `systemd`, `pam.d`, `authorized_keys`, kernel modules). | `docs/M6.5_FILESYSTEM_PERSISTENCE_TELEMETRY.md` | Rules: `rules/security/sec_cron_persistence_tamper.yaml`<br>Backend: `apps/engine/src/logintel/telemetry/filesystem.py` | Verified against canonical events. |
| **M6-F05** | **Systemd Unit & Kernel Module Tracking**<br>Audit service unit installations, transient service execution, and kernel module loadings (`insmod`/`modprobe`). | `docs/M6.6_SYSTEMD_KERNEL_TELEMETRY.md` | Backend: `apps/engine/src/logintel/telemetry/systemd.py`<br>Rules: `rules/security/sec_kernel_module_tampering.yaml` | Audited in M6.6 verification. |
| **M6-F06** | **Container & Namespace Isolation Inspection**<br>Inspect container boundaries, namespace escapes, mount namespaces, and Docker/crictl execution contexts. | `docs/M6.7_CONTAINER_NAMESPACE_TELEMETRY.md` | Backend: `apps/engine/src/logintel/telemetry/containers.py`<br>Rules: `rules/security/sec_container_escape_attempt.yaml` | Resolves container IDs from cgroup paths. |
| **M6-F07** | **Host Graph Topology & Threat Correlation**<br>Graph model representing host entities, socket bindings, process links, and host-level risk scoring. | `docs/M6.8_HOST_GRAPH_INTEGRATION.md`<br>`docs/M6.9_HOST_THREAT_CORRELATION.md` | Backend: `apps/engine/src/logintel/investigations/host_graph.py`<br>Tests: `apps/engine/tests/test_host_graph_builder_m68.py` | Provides foundation for M7.12 multi-host graph. |

---

### 2.7 Milestone M7: Advanced Investigation Workbenches (M7.1 – M7.8)
*Primary References:* `docs/M7.1_ANALYST_INVESTIGATION_ARCHITECTURE_AUDIT.md` through `docs/M7.8_FINAL_FORENSIC_VERIFICATION.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M7-F01** | **Dedicated Investigation Cases Page (`cases.db`)**<br>Top-level navigation and management for 2,648 investigation cases, case creation, and case switching. | `docs/M7.1_ANALYST_INVESTIGATION_ARCHITECTURE_AUDIT.md` | Routes: `GET /api/v1/cases`, `POST /cases`<br>Frontend: `apps/desktop/src/pages/CasesPage.tsx`<br>Storage: `cases.db:investigation_cases` | Prior to full redesign, Cases was only accessible inside modals. Now top-level tab. |
| **M7-F02** | **Unified Multi-Source Timeline**<br>Chronological timeline merging raw telemetry, alerts, analyst notes, and detection triggers into a single stream. | `docs/M7.2_UNIFIED_TIMELINE_REPLAY.md` | Route: `GET /api/v1/cases/{id}/timeline/unified`<br>Frontend: `apps/desktop/src/features/InvestigationUnifiedTimeline.tsx` | Filterable by event type, severity, time window, and text query. |
| **M7-F03** | **Interactive Step-by-Step Replay Scrubber**<br>VCR-style temporal playback controls (play, pause, step forward/backward, speed multiplier) across attack events. | `docs/M7.2_UNIFIED_TIMELINE_REPLAY.md:78` | Route: `GET /api/v1/cases/{id}/timeline/replay`<br>Frontend: `InvestigationUnifiedTimeline.tsx` (Replay Mode) | Reconstructs state at each discrete timestamp frame. |
| **M7-F04** | **Evidence Collections & Cryptographic Blake2b Sealing**<br>Group evidentiary events into named collections and seal them with an immutable Blake2b-256 digest. | `docs/M7.3_EVIDENCE_COLLECTIONS.md` | Routes: `POST /cases/{id}/evidence/collections`, `POST .../seal`<br>Frontend: `apps/desktop/src/features/InvestigationEvidenceWorkbench.tsx` | Stored in `cases.db:case_evidence_references`. Cryptographic seals prevent evidence tampering. |
| **M7-F05** | **Structured Findings & Competing Hypotheses (ACH)**<br>Epistemic finding authoring, hypothesis evaluation matrix, supporting/refuting evidence links. | `docs/M7.4_FINDINGS_HYPOTHESIS.md` | Routes: `POST /cases/{id}/findings`, `GET .../hypotheses`<br>Frontend: `apps/desktop/src/features/InvestigationFindingsWorkbench.tsx` | Stored in `cases.db:case_hypotheses` and `case_finding_reviews`. |
| **M7-F06** | **Governed Threat Hunting Workbench**<br>Structured hunting query authoring, governor safety gates (read-only validation, bounded 72h window), and execution history. | `docs/M7.5_FINAL_FORENSIC_VERIFICATION.md` | Routes: `POST /cases/{id}/hunts/{id}/execute`<br>Frontend: `apps/desktop/src/features/InvestigationThreatHuntWorkbench.tsx` | Stored in `cases.db:case_query_history`. Top-level page: `ThreatHuntingPage.tsx`. |
| **M7-F07** | **Formal Investigation Reports & Evidence Packages**<br>Multi-version report drafting, markdown/JSON export, and Blake2b-sealed zip packages with manifest. | `docs/M7.6_FINAL_FORENSIC_VERIFICATION.md`<br>*(Also historically cited as M7.9)* | Routes: `POST /cases/{id}/reports`, `POST .../packages`<br>Frontend: `apps/desktop/src/features/InvestigationReportWorkbench.tsx` | Stored in `cases.db:case_reports`. Generates downloadable ZIP package with SHA256 manifest. |
| **M7-F08** | **Cross-Case Comparison & Correlation**<br>Analyze overlapping indicators, shared entity sets, and temporal proximity across distinct investigation cases. | `docs/M7.7_FINAL_FORENSIC_VERIFICATION.md`<br>*(Also historically cited as M7.10)* | Route: `POST /api/v1/cases/{id}/comparison`<br>Frontend: `apps/desktop/src/features/InvestigationCaseComparisonWorkbench.tsx` | Computes Jaccard similarity across case entity sets in `cases.db`. |
| **M7-F09** | **Forensic Quality Review & 12 Closure Gates**<br>Automated audit checklist enforcing 12 closure gates (unreviewed findings, open hypotheses, evidence gaps) before closing case. | `docs/M7.8_FINAL_FORENSIC_VERIFICATION.md`<br>*(Also historically cited as M7.11)* | Routes: `GET /cases/{id}/review/status`, `POST .../close`<br>Frontend: `apps/desktop/src/features/InvestigationQualityReviewWorkbench.tsx` | Strict gate enforcement blocks closure unless all blockers acknowledged or resolved. |

---

### 2.8 Milestone M7.12: Multi-Host Fleet Investigation (M7.12.1 – M7.12.5)
*Primary References:* `docs/M7.12.1_BACKEND_FOUNDATION_REPORT.md` through `docs/M7.12.5_FINAL_VALIDATION_AND_CERTIFICATION_REPORT.md`

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **M7.12-F01**| **Fleet-Wide Multi-Host Dossier**<br>Observed vs scoped-unobserved host status, cross-host threat scores, and aggregate telemetry gap counts. | `docs/M7.12.1_BACKEND_FOUNDATION_REPORT.md`<br>`docs/M7.12.2_DESKTOP_WORKBENCH_IMPLEMENTATION_REPORT.md` | Route: `GET /api/v1/cases/{id}/hosts`<br>Frontend: `apps/desktop/src/pages/MultiHostPage.tsx`, `InvestigationMultiHostWorkbench.tsx` | Elevated to dedicated top-level desktop tab with case selector. |
| **M7.12-F02**| **Lateral Movement Trace Reconstruction**<br>Heuristic and deterministic reconstruction of multi-hop lateral movement across hosts (SSH, sudo, remote execution). | `docs/M7.12.3_CROSS_HOST_ENTITY_CORRELATION_REPORT.md` | Route: `GET /api/v1/cases/{id}/hosts/lateral-traces`<br>Frontend: `InvestigationMultiHostWorkbench.tsx` (Lateral Traces) | Renders source $\rightarrow$ target host hops with timestamps and auth mechanism. |
| **M7.12-F03**| **Comparative Per-Host Timelines**<br>Time-aligned comparative timelines across multiple target hosts showing concurrent event sequences. | `docs/M7.12.4_COMPARATIVE_TIMELINES_AND_TOPOLOGY_REPORT.md` | Route: `GET /api/v1/cases/{id}/hosts/{host}/timeline`<br>Frontend: `InvestigationMultiHostWorkbench.tsx` (Host Timeline) | Paginated event list filtered to specific selected host. |
| **M7.12-F04**| **Telemetry Visibility Gaps & Blind-Spot Detection**<br>Identify unscoped target hosts, missing telemetry sources, and ingestion dropouts during case window. | `docs/M7.12.1_BACKEND_FOUNDATION_REPORT.md:88` | Route: `GET /api/v1/cases/{id}/hosts` (gap payload)<br>Frontend: `InvestigationMultiHostWorkbench.tsx` (Visibility Gaps) | Highlights critical blind spots where host was targeted but unmonitored. |
| **M7.12-F05**| **Target-Host Scope Editor & Scope Persistence**<br>Authorize and update the target host scope for an active investigation case with audit log record. | `docs/M7.12.2_POST_IMPLEMENTATION_VERIFICATION_AUDIT.md` | Route: `POST /api/v1/cases/{id}/scope`<br>Frontend: `InvestigationMultiHostWorkbench.tsx` (Scope Editor) | Updates `cases.db:investigation_cases` JSON scope column; logs audit entry in `case_audit_log`. |
| **M7.12-F06**| **Deterministic Multi-Host Dossier Export**<br>Export fleet investigation dossier to JSON/Markdown with cryptographic Blake2b verification digest. | `docs/M7.12.5_FINAL_VALIDATION_AND_CERTIFICATION_REPORT.md` | Route: `GET /api/v1/cases/{id}/hosts/export`<br>Frontend: `InvestigationMultiHostWorkbench.tsx` (Export Dossier modal) | Generates downloadable file with reproducible cryptographic seal. |

---

### 2.9 Platform Quality, UX & Desktop Packaging Capabilities

| Feature ID | Capability & Requirement Description | Original Requirement Source | Current Implementation Evidence (Backend / Frontend) | Requirement Attribution & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **PLAT-F01**| **Persistent Light / Dark / System Theme Engine**<br>Persistent theme engine adhering to user preference with pre-render inline initialization to prevent theme flashes. | `apps/desktop/src/styles/theme.css`<br>`apps/desktop/src/lib/theme.ts` | Storage: `localStorage:logintel_theme`<br>Frontend: `Header.tsx` (Theme Toggle Button) | Supports `dark`, `light`, and `system` modes with curated HSL color tokens. |
| **PLAT-F02**| **Truthful Offline Connection State & Recovery**<br>Explicit red OFFLINE banner when engine is disconnected, separating connection loss from an empty database. | `apps/desktop/src/pages/OverviewPage.tsx`<br>`apps/desktop/src/pages/ActivityPage.tsx` | State: `backendConnected`, `backendError`<br>Frontend: Manual and exponential retry controls | Fixes prior defect where disconnected engine was disguised as "0 Events". |
| **PLAT-F03**| **Standard Debian (.deb) Packaging Pipeline**<br>Packaging script building desktop release binary, bundling rules, creating Python 3.12 dispatcher, and writing systemd unit. | `scripts/build_deb.sh`<br>`packaging/deb/logintel_0.1.0_production_amd64.deb` | Output: `packaging/deb/*.deb`<br>System: `/usr/bin/logintel`, `/usr/lib/logintel/engine` | Verified standalone installation on Ubuntu 24.04 LTS x86_64. |

---

## 3. Requirement Attribution Ambiguities & Roadmap Reconciliation

During the audit, three minor numbering shifts were identified between early planning documents and final milestone reports:
1. **Reporting & Evidence Packages:** Planned as M7.6 in some architecture notes; completed and certified under `docs/M7.6_FINAL_FORENSIC_VERIFICATION.md` (and occasionally referenced as M7.9 in retrospective roadmaps). Both refer to the identical codebase in `apps/engine/src/logintel/reports/` and `InvestigationReportWorkbench.tsx`.
2. **Cross-Case Comparison:** Planned as M7.7; verified under `docs/M7.7_FINAL_FORENSIC_VERIFICATION.md` (and historically labeled M7.10). Uses `apps/engine/src/logintel/comparison/` and `InvestigationCaseComparisonWorkbench.tsx`.
3. **Forensic Quality Review & Closure Gates:** Planned as M7.8; verified under `docs/M7.8_FINAL_FORENSIC_VERIFICATION.md` (and historically labeled M7.11). Uses `apps/engine/src/logintel/review/` and `InvestigationQualityReviewWorkbench.tsx`.
4. **Attribution Standard:** In this audit and all forward-looking documentation, the authoritative milestone attribution is strictly anchored to the existing verified reports: **M7.6 (Reporting)**, **M7.7 (Comparison)**, **M7.8 (Review Gates)**, and **M7.12 (Multi-Host)**.
