# LOGINTEL — PRODUCTION IMPLEMENTATION PLAN
**Document Reference:** `docs/PRODUCTION_IMPLEMENTATION_PLAN.md`  
**Audit Phase:** Phase 1: Read-Only Repository, Frontend, Backend & Installer Traceability  
**Execution Date:** 2026-10-22  
**Target Platform:** Ubuntu Linux 24.04 LTS x86_64  
**Implementation Constraint:** Pure Planning Document — No Code Changes Executed During Audit.

---

## 1. Plan Overview & Objectives

The primary objective of this implementation plan is to transition the LogIntel platform from its current state (where all 38 capabilities are fully implemented in repository source, but an older 6-tab binary is deployed to the system launcher) to a production-certified desktop application where:
1. Every implemented capability is discoverable from the primary desktop UI.
2. The installed binary (`/usr/bin/logintel-bin`) matches the verified 9-tab source tree.
3. Cold start readiness synchronization guarantees zero `Query Error: Load failed` events.
4. Offline backend states are prominently distinguished from empty databases.
5. All 52,130 real events in `logintel.db` and 2,648 cases in `cases.db` remain 100% intact.

---

## 2. Prioritized Implementation Phases

```
PHASE 1 (Pre-Flight Safety & Baseline Verification) [COMPLETE]
  ↓
PHASE 2 (Source Validation & Static Analysis)
  ↓
PHASE 3 (Automated Unit & Integration Test Execution)
  ↓
PHASE 4 (Debian Package Build & Checksum Verification)
  ↓
PHASE 5 (Controlled Package Installation in Isolated Test Context)
  ↓
PHASE 6 (End-to-End Packaged Desktop Runtime Acceptance)
  ↓
PHASE 7 (Final Production Sign-Off & Release Documentation)
```

---

### Phase 2: Source Validation & Static Analysis
**Dependencies:** Phase 1 completion  
**Objective:** Validate that all TypeScript, Rust, and Python codebases compile with zero warnings or errors.

1. **Frontend TypeScript Compilation:**
   - Execute: `cd apps/desktop && npx tsc --noEmit`
   - Acceptance Criteria: Exit code 0, 0 type errors.
2. **Frontend Production Vite Bundle:**
   - Execute: `cd apps/desktop && npm run build`
   - Acceptance Criteria: Clean build in `apps/desktop/dist/` with HTML, JS, CSS assets.
3. **Rust Cargo Compilation (Release):**
   - Execute: `cd apps/desktop/src-tauri && cargo check --release`
   - Acceptance Criteria: Exit code 0, 0 compiler errors.
4. **Python Backend Syntax & Import Checks:**
   - Execute: `/usr/lib/logintel/engine/.venv/bin/python -c "import fastapi, pydantic, uvicorn, logintel; print('OK')"`
   - Acceptance Criteria: Exit code 0, clean resolution of all core dependencies.

---

### Phase 3: Automated Test Execution
**Dependencies:** Phase 2 compilation success  
**Objective:** Run the full suite of frontend, backend, and lifecycle tests to verify regression safety.

1. **Vitest Frontend Suite (103 Tests):**
   - `src/__tests__/navigation_and_integration.test.ts` (9 tabs, case navigation, offline banner)
   - `src/__tests__/activity_recovery.test.ts` (exponential backoff & error recovery)
   - `src/__tests__/dashboard.test.ts` (truthful KPI states)
   - `src/__tests__/theme.test.ts` (theme persistence)
   - `src/__tests__/api.test.ts` (53 API integration tests)
   - `src/__tests__/multihost.test.ts` (23 multi-host tests)
   - Acceptance Criteria: 103/103 tests pass.
2. **Pytest Backend Engine Suite (95 Tests):**
   - `test_m712_multihost.py` (37 tests)
   - `test_m78_security.py` (22 tests)
   - `test_m72_timeline_replay.py` (8 tests)
   - `test_m75_threat_hunting.py` (12 tests)
   - `test_alert_lifecycle.py`, `test_detection_engine.py` (16 tests)
   - Acceptance Criteria: 95/95 tests pass.
3. **Packaging & Daemon Lifecycle Suite:**
   - `tests/test_packaging_and_lifecycle.py` (4 tests)
   - Acceptance Criteria: 4/4 tests pass (handshake verification within 3.5s, clean child process reap).

---

### Phase 4: Production Package Build
**Dependencies:** Phase 3 test pass  
**Objective:** Generate the standalone Debian installer with verified Python 3.12 dispatcher and release binary.

1. **Execute Builder Script:**
   - Command: `scripts/build_deb.sh`
   - Outputs: `packaging/deb/logintel_0.1.0_production_amd64.deb`
2. **Preserve Prior Package Archives:**
   - Preserve `logintel_0.1.0_amd64.deb` (`7b00e30a...`)
   - Preserve `logintel_0.1.0_redesign_amd64.deb` (`2eebe0eb...`)
   - Preserve `logintel_0.1.0_gate42_amd64.deb` (`a21394d0...`)
3. **Verify Package Payloads:**
   - Confirm `/usr/bin/logintel-bin` is stripped and executable (`0755`).
   - Confirm `/usr/share/logintel/rules/` contains all 26 YAML detection rules.
   - Confirm `/usr/lib/logintel/engine/.venv/bin/python` dispatcher script is present.
   - Record SHA-256 checksum of generated `.deb`.

---

### Phase 5: Controlled System Package Installation
**Dependencies:** Phase 4 package generation; explicit user approval  
**Objective:** Deploy the newly compiled package to the host system.

1. **Pre-Installation Safety Check:**
   - Verify `~/.local/share/logintel/logintel.db` and `cases.db` remain untouched.
   - Verify port 41721 is not occupied by an unkillable daemon.
2. **Execute dpkg Installation:**
   - Command: `sudo dpkg -i packaging/deb/logintel_0.1.0_production_amd64.deb`
3. **Verify Installed File Hashes:**
   - Verify `/usr/bin/logintel-bin` SHA-256 matches the newly generated package binary.
   - Verify desktop menu file `/usr/share/applications/logintel.desktop` exists and has `0644` permissions.

---

### Phase 6: Packaged Desktop Runtime Acceptance
**Dependencies:** Phase 5 deployment  
**Objective:** Execute interactive and API acceptance tests against the installed application.

1. **Application Launch & Handshake:**
   - Launch: `/usr/bin/logintel`
   - Check: Engine spawns, binds `127.0.0.1:41721`, and passes handshake within 3.5s.
2. **Verification of 9 Top-Level Navigation Tabs:**
   - **Overview:** Renders 52,130 events in database, uptime, active ingestion status.
   - **Activity:** Paginates 52,130 canonical events with zero connection errors.
   - **System Diagnostics:** Lists 7 sources (journald, auth.log, syslog, kern.log, etc.); triggers manual sync.
   - **Incidents:** Displays incident triage view.
   - **Alerts:** Displays alert triage view.
   - **Rules Catalog:** Lists 26 rules with severity and MITRE tags.
   - **Threat Hunting:** Executes read-only SQL queries against canonical telemetry.
   - **Investigations:** Displays 2,648 cases from `cases.db`; search and create case modal.
   - **Multi-Host Analysis:** Renders fleet dossier, lateral movement traces, per-host timeline, and scope editor.
3. **Investigation Workspace Verification:**
   - Open case #1; verify all 15 workbench tabs mount without console errors.
   - Test Evidence Workbench Blake2b sealing.
   - Test Competing Hypotheses matrix.
   - Test Forensic Closure review gates.
4. **Theme Persistence Check:**
   - Toggle theme to light, restart application; confirm light theme persists without white flash.
5. **Clean Termination Check:**
   - Close desktop window; verify `child.kill()` terminates engine process and frees port 41721.

---

## 3. Risks & Migration Assessment

1. **Database Schema Invariant:**
   - *Risk:* Accidental schema migration altering `logintel.db` or `cases.db`.
   - *Mitigation:* Zero migrations are executed. The application opens existing tables read-write using standard SQLite WAL connections.
2. **Python ABI Collision:**
   - *Risk:* Host running Python 3.14 breaks pre-compiled C-extensions in `.venv`.
   - *Mitigation:* Dispatcher script in `/usr/lib/logintel/engine/.venv/bin/python` strictly tests and selects Python 3.12.
3. **Rollback Strategy:**
   - If runtime verification fails in Phase 6, reinstall `packaging/deb/logintel_0.1.0_gate42_amd64.deb` via `dpkg -i`. User databases remain untouched in `~/.local/share/logintel/`.
