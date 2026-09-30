# LogIntel — M1 Foundation Forensic Product & Code Audit

**Audit Date**: September 29, 2026  
**Auditor**: Principal Software Architect & Forensic Code Auditor  
**Audit Scope**: READ-ONLY examination of source code, configurations, database, package artifacts, tests, and runtime behavior.  
**Repository**: `/home/khemendra-labs/LogIntel` (Commit `2bce806`)  
**Target Environment**: Ubuntu 24.04 LTS (x86_64)

---

## 1. Executive Summary

A comprehensive, read-only forensic audit of the **LogIntel M1 Foundation Layer** was conducted against the physical repository, local SQLite database, compiled binaries, Debian packaging, and active Linux system telemetry.

### Core Audit Takeaway
LogIntel M1 establishes a genuine, working, non-mocked foundational pipeline. It connects real Linux telemetry (`journald`, `/var/log/auth.log`, `/var/log/syslog`, `/var/log/kern.log`) to an extensible parsing framework, canonical event model, SQLite WAL repository, and a restrained React desktop GUI. It adheres strictly to the required enterprise security design system, avoiding banned AI-generated aesthetics, emojis, and third-party icon bloat.

However, forensic testing uncovered **two critical P0 blockers** and **two major P1 architectural defects** that must be resolved before proceeding to Milestone 2 (Detections & Analysis):
1. **P0 — Package Dependency Failure on Clean Machines**: The generated `.deb` package installs the application and raw Python scripts, but does not bundle the Python runtime virtual environment or declare Debian package dependencies for `fastapi`, `pydantic`, and `uvicorn`. On a clean Ubuntu machine, launching `logintel` crashes immediately with `ModuleNotFoundError: No module named 'fastapi'`.
2. **P0 — Event Duplication on Engine Restart**: The ingestion engine does not restore cursors or byte offsets from the `ingestion_state` table on startup. Consequently, every engine launch re-ingests historical logs and generates new random UUIDs for existing records, causing the database to duplicate thousands of records on every restart.
3. **P1 — Unauthenticated Local IPC Threat Model**: The Python API on `127.0.0.1:41721` has no authentication tokens or capability verification. Any local user on a multi-user Linux system can query the API and read privileged system telemetry without belonging to the `adm` group.
4. **P1 — Event Timestamp Provenance Overwrite**: `FileTailer` initializes `RawRecord.timestamp` to `datetime.now(timezone.utc)`, which causes the parser framework to favor ingestion time over the actual syslog line timestamp for historical file logs.

**Verdict**: **`M1 CONDITIONALLY VERIFIED — FIX LIST REQUIRED BEFORE M2`**

---

## 2. Repository Reality Audit

| Component | Target Location | Actual Reality | Verification Status | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Git Working Tree** | `/home/khemendra-labs/LogIntel` | Clean, 103 tracked files | **CONFIRMED** | Commit `2bce806` |
| **Desktop Shell** | `apps/desktop/` | Tauri v2 + React 18 + TS | **CONFIRMED** | Compiles cleanly via Vite & Cargo |
| **Analysis Engine** | `apps/engine/src/logintel/` | Python 3.12 package | **CONFIRMED** | 10 modular subpackages |
| **Storage Layer** | `apps/engine/src/logintel/storage/` | SQLite WAL + migrations | **CONFIRMED** | Database size: 13.4 MB |
| **Debian Packaging** | `packaging/deb/`, `scripts/build_deb.sh` | Staging + builder script | **CONFIRMED** | Artifact: `logintel_0.1.0_amd64.deb` |
| **Documentation** | `docs/` | Architecture, schema, dev, pkg | **CONFIRMED** | 5 detailed markdown documents |
| **Empty Directories** | `rules/` | Directories created | **PARTIAL** | Subdirectories present; rules reserved for M2 |
| **Hosts / Sources DB** | `hosts`, `sources` tables | Tables exist in schema | **PLACEHOLDER** | Tables have 0 rows in actual database |

---

## 3. Architecture Audit

```text
┌─────────────────────────────────────────────────────────────┐
│                 Tauri Desktop Shell                         │
│                                                             │
│          React + TypeScript Frontend (Vite)                 │
│  - Overview Screen (Distributions, Telemetry, Alerts)       │
│  - Activity Screen (Technical Table, Multidimensional Filter)│
│  - Event Detail Modal (Normalized Provenance & Raw Evidence)│
│  - Telemetry Health Modal (Source Diagnostics & Fix Hints)  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               │ Local HTTP/REST IPC (127.0.0.1:41721)
                               │
┌──────────────────────────────▼──────────────────────────────┐
│              Python Analysis Engine                         │
│                                                             │
│  - Collectors: journald, auth.log, syslog, kern.log         │
│  - Parser Registry: OpenSSH, Sudo, PAM, UserMgmt, Kernel    │
│  - Normalization: ANSI strip, 16KB bound, IOC extraction    │
│  - Storage Repo: SQLite WAL mode, compound indexes          │
│  - Health Diagnostics: File stats, permissions, offsets     │
└──────────────────────────────┬──────────────────────────────┘
                               │
            ┌──────────────────┴──────────────────┐
            │                                     │
    ┌───────▼────────┐                   ┌────────▼──────────┐
    │ Linux Sources  │                   │ SQLite Event DB   │
    │                │                   │                   │
    │ journald       │                   │ events (WAL mode) │
    │ auth.log       │                   │ ingestion_state   │
    │ syslog         │                   │ sources (empty)   │
    │ kern.log       │                   │ hosts (empty)     │
    └────────────────┘                   └───────────────────┘
```

### Architectural Findings:
1. **GUI / Engine Decoupling**: **CONFIRMED**. The React frontend contains zero security detection or normalization logic. It queries the engine strictly over HTTP.
2. **Collector / Storage Decoupling**: **CONFIRMED**. Collectors produce `RawRecord` instances and have no direct dependency on SQLite or database schemas.
3. **Database / API Decoupling**: **CONFIRMED**. API routes interact strictly through `EventsRepository` and `HealthService`.
4. **Defect — Unpopulated Metadata Tables**: The database schema defines `hosts` and `sources` tables with foreign key possibilities, but `IngestionEngine` only populates `events` and `ingestion_state`. `hosts` and `sources` remain at 0 rows.

---

## 4. Tauri & Python Engine Lifecycle Audit

### Thread Model & IPC Analysis (Port `127.0.0.1:41721`):
1. **Engine Spawning**: In `apps/desktop/src-tauri/src/lib.rs`, Tauri checks `TcpStream::connect_timeout("127.0.0.1:41721")`. If unresponsive, it attempts to spawn the Python engine from a list of candidate paths.
2. **Vulnerability — Port Occupation / Hijack**: If any local process (even an unrelated web server or malicious process) listens on port `41721`, `is_engine_running()` returns `true`. Tauri will not spawn the engine and will attempt to send requests to the foreign process. It does not verify the service identity (e.g. checking `GET /api/v1/system/status`).
3. **Vulnerability — Unauthenticated Local API**: The API binds to `127.0.0.1:41721` with no authentication tokens. On a shared Linux machine, any unprivileged local user or local script can read all system security logs, including sudo commands, usernames, and authentication attempts.
4. **Vulnerability — Cross-Origin POST via Browser**: While browsers enforce CORS for reading responses, a local user visiting a malicious webpage could allow that webpage to issue blind `POST http://127.0.0.1:41721/api/v1/ingestion/trigger` requests.
5. **Process Crash & Orphan Risk**: Tauri holds `Child` in an `Arc<Mutex<Option<Child>>>` and kills it on `ExitRequested`. However:
   - If Tauri crashes or receives `SIGKILL`, the child Python process is orphaned and remains running.
   - If the Python engine crashes while Tauri is running, Tauri has no health watchdog and does not respawn the engine.

---

## 5. Collector Audit

### 5.1 journald (`JournalCollector`)
- **Command Used**: `journalctl -o json -n <limit>` and `journalctl -o json --after-cursor <cursor>`.
- **Parsing**: Parses JSON output, extracts `__CURSOR`, `__REALTIME_TIMESTAMP`, and `MESSAGE`.
- **Finding (P0)**: On startup, `JournalCollector` initializes `self.cursor = None`. It does not load the previous cursor from `ingestion_state`. Consequently, on every engine restart, it queries `journalctl -o json -n 1000` without a cursor, re-ingesting the last 1,000 entries.

### 5.2 auth.log, syslog, kern.log (`FileTailer`)
- **Tailing & Offsets**: Tracks `current_offset` and `current_inode`. Detects log rotation when `stat.st_ino` changes or file size shrinks below `current_offset`.
- **Finding (P0)**: On restart, `FileTailer` initializes `current_offset = 0` and calls `read_historical(max_records=2000)`, re-ingesting up to 2,000 existing lines instead of resuming from the database byte offset.
- **Finding (P1)**: In `file_tailer.py` lines 77 and 123, `RawRecord` is constructed with `timestamp=datetime.now(timezone.utc)`. Because the parsers use `final_ts = record.timestamp or ts`, the parser ignores the actual timestamp from the log line header and stamps historical events with the current ingestion time.

---

## 6. Duplication Audit

Forensic inspection of the actual SQLite database (`logintel.db`) revealed:
- **Total Ingested Events**: 11,522 events.
- **Unique Raw Messages Duplicated**: 2,921 messages duplicated 2 to 4 times.

### Causes of Duplication:
1. **Cross-Source Dual-Reporting (Expected)**: Linux writes kernel messages to both `kern.log` and `syslog`, and authentication events to both `auth.log` and `journald`. Storing these with separate provenance (`source="auth.log"` vs `source="journald"`) is legitimate for evidentiary integrity.
2. **Engine Restart Duplication (Defect)**: Because `event.id` is generated as a random `uuid.uuid4()`, and because collectors do not restore their cursors/offsets from `ingestion_state`, every engine restart re-ingests the last 1,000–2,000 records from all sources as brand new events. `INSERT OR IGNORE` in `events_repo.py` cannot deduplicate them because the primary key (`id`) is a new UUID.

---

## 7. Parser Forensic Audit

| Parser | Supported Messages | Forensic Limitations & Edge Cases |
| :--- | :--- | :--- |
| **OpenSSH** (`SSHAuthParser`) | `Failed password`, `Accepted password/publickey`, `Invalid user`, `Connection closed [preauth]` | 1. `can_parse` matches any message containing `"sshd"`, hardcoding `executable="/usr/sbin/sshd"` and `dst_port=22` even for non-auth lines.<br>2. Does not parse `Accepted keyboard-interactive/pam`.<br>3. Invalid usernames with spaces break at first space. |
| **Sudo** (`SudoParser`) | `COMMAND=`, `incorrect password attempts`, `user NOT in sudoers` | 1. **Defect**: Regex `PWD=([^\s;]+)` fails to match any sudo command executed from a working directory containing spaces (e.g. `PWD=/home/user/my projects`). Verified empirically via regex test. |
| **PAM** (`PAMSessionParser`) | `session opened`, `session closed`, `authentication failure` | 1. Only matches `pam_unix`. Does not parse `pam_sss`, `pam_systemd`, or `pam_ldap`. |
| **Kernel** (`KernelParser`) | `[UFW BLOCK]`, `segfault at`, `Linux version` | 1. **Defect**: AppArmor security denial events (`apparmor="DENIED"`) are not specifically recognized; they fall through to `summary = "Kernel: audit..."`, `severity = INFORMATIONAL`, and `outcome = SUCCESS`. |
| **User Mgmt** (`UserManagementParser`) | `useradd`, `userdel`, `groupadd` | Standard syntax parsed accurately. |
| **Generic** (`GenericSyslogParser`) | RFC 5424 (ISO-8601) and RFC 3164 | Robust header parsing for timestamp, host, process, and PID. |

---

## 8. Canonical Event Model Audit

### Schema Verification:
- **Field Integrity**: Verified across `events` table:
  - `id`: 100% populated (UUIDv4)
  - `timestamp`: 100% populated (ISO 8601 UTC)
  - `host`, `source`, `event_type`, `severity`, `outcome`: 100% populated
  - `raw_message`: 100% populated, immutable
  - `parser`, `source_file`, `source_offset`: 99.98% populated
- **Field Rates in Live Data**:
  - `username`: 93.0% NULL (expected; kernel, systemd, and cron background tasks do not have user actors).
  - `src_ip`: 100.0% NULL on the local test machine (local Ubuntu workstation logs contain local events; network SSH events were only present in test fixtures).

---

## 9. Hostile Input & Sanitization Audit

1. **ANSI Control Sequences**: `ANSI_ESCAPE_PATTERN` in `sanitizer.py` correctly strips terminal escape sequences.
2. **Message Length Limiting**: Truncates at 16,384 characters and appends `[TRUNCATED_EXCESSIVE_LENGTH]`.
3. **SQL Injection**: **ZERO VULNERABILITIES**. All queries in `events_repo.py` use parameterized queries (`?` or `:named`). No string formatting or concatenation is used.
4. **Defect — Dead Code for IPv6 IOCs**: In `sanitizer.py`:
   - Line 18 defines `IPV6_PATTERN = re.compile(...)`.
   - Lines 57–63 only iterate over `IPV4_PATTERN.finditer(text)`.
   - `IPV6_PATTERN` is never used. IPv6 addresses in raw logs are never extracted into `iocs`.

---

## 10. Database & Storage Audit

### Database Metrics (`logintel.db`):
- **Path**: `~/.local/share/logintel/logintel.db`
- **File Size**: 13,455,360 bytes (13.4 MB)
- **WAL Mode**: Enabled (`PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;`).
- **Indexes**: 11 explicit indexes verified (`idx_events_timestamp`, `idx_events_compound_time_type`, `idx_events_severity`, `idx_events_source`, etc.).

### Query Plan Findings:
- Query for default paginated events: Uses `idx_events_compound_time_type` efficiently.
- **Defect — Temp B-Tree on Filtered Queries**: Querying `WHERE source = ? AND severity = ? ORDER BY timestamp DESC` triggers `USE TEMP B-TREE FOR ORDER BY` because the index on `severity` does not include `timestamp`.
- **Scalability Finding — Unindexed Search**: Text search executes an unindexed 4-column `LIKE '%...%'` scan across the table. SQLite FTS5 is not yet configured.

---

## 11. API / IPC Audit

Tested endpoints via `curl` against `127.0.0.1:41721`:
- `GET /api/v1/system/status`: Returns system status in 1.2 ms.
- `GET /api/v1/telemetry/health`: Returns 4-source audit in 14.6 ms.
- `GET /api/v1/events?limit=50`: Returns paginated events in 2.8 ms.
- `GET /api/v1/events/stats/summary`: Returns 24h aggregations in 37.2 ms.
- `GET /api/v1/events/{id}`: Returns single event detail in 1.1 ms.
- `POST /api/v1/ingestion/trigger`: Triggers single collection cycle in 48 ms.

### Findings:
1. Input validation with FastAPI / Pydantic (`limit` ge=1, le=500; `offset` ge=0; `sort_order` pattern) functions reliably.
2. `POST /api/v1/ingestion/trigger` has no rate limiting or authentication.

---

## 12. Telemetry Health Audit

- Health report accurately probes file existence, readability, file size in bytes, and octal permissions (`640` on `/var/log/auth.log`, `syslog`, `kern.log`).
- Accurate detection of `journalctl` binary and unprivileged execution.
- Action hints provide accurate commands (`sudo usermod -aG adm $USER`).

---

## 13. GUI & Design System Audit

### Visual Design Review against Prohibited Elements:
- Harsh gradients: **NONE**. (100% flat warm neutrals).
- Liquid glass / Glow / Neon: **NONE**.
- Rainbow / Cyberpunk colors: **NONE**.
- Pure white overall background: **NONE**. (App background is `--bg-app: #f4f3ee`).
- Lucide icons: **NONE**. (Zero Lucide imports; custom inline SVG geometry in `Icons.tsx`).
- Prohibited fonts (Inter, Geist, Space Grotesk): **NONE**. (Uses `IBM Plex Sans` and `IBM Plex Mono`).
- Generic AI sparkle / badges / emojis: **NONE**.
- Drop shadows / radial orbs / bento grids: **NONE**.
- Rounded corners: Restrained to `border-radius: 2px` throughout.

### Frontend Code Review:
- React 18 + TypeScript + Vite.
- Fast compile time (1.82s). Zero TypeScript compilation errors.
- Pages implemented: `OverviewPage`, `ActivityPage`, `EventDetailModal`, `TelemetryHealthModal`.
- Information architecture strictly limited to existing features.

---

## 14. Privilege Model Audit

1. **Non-Root Operation**: The GUI and engine run entirely under unprivileged UID 1000. No `sudo` commands are executed by the application.
2. **Linux Group Security**: Relies on standard Debian/Ubuntu group permissions (`adm` group membership).
3. **Limitation**: If a user is not in `adm`, the UI correctly reports `UNAVAILABLE` and shows the remediation command, but cannot read system logs until group membership is updated.

---

## 15. Packaging Audit (`logintel_0.1.0_amd64.deb`)

- **Package Artifact**: Generated at `packaging/deb/logintel_0.1.0_amd64.deb` (2.2 MB).
- **Control File**:
  ```text
  Package: logintel
  Version: 0.1.0
  Architecture: amd64
  Depends: libwebkit2gtk-4.1-0, libgtk-3-0t64 | libgtk-3-0, python3 (>= 3.10)
  ```
- **Contents**:
  - `/usr/bin/logintel`: Startup wrapper script
  - `/usr/bin/logintel-bin`: Compiled Tauri binary (11 MB)
  - `/usr/lib/logintel/engine/logintel`: Engine Python source files
  - `/usr/share/applications/logintel.desktop`: Desktop launcher
  - `/usr/share/icons/hicolor/128x128/apps/logintel.png`: 128x128 PNG icon

### Critical Packaging Flaw (P0):
The package copies raw Python files into `/usr/lib/logintel/engine`, but does **NOT** bundle a pre-built virtualenv with dependencies (`fastapi`, `pydantic`, `uvicorn`), nor does it declare Debian system packages for them in `Depends:`. On a clean Ubuntu machine, launching `/usr/bin/logintel` runs `/usr/bin/python3 -m logintel.main`, which crashes with:
```text
ModuleNotFoundError: No module named 'fastapi'
```

---

## 16. Test Quality Audit

### Coverage Matrix:

| Subsystem | Unit Tests? | Integration Tests? | Meaningful Coverage? | Major Gaps |
| :--- | :---: | :---: | :---: | :--- |
| **Collectors** | Yes | Yes | Partial | Does not test log rotation, truncation, or inode changes in automated tests. |
| **Parsers** | Yes | No | Good | 9 representative fixtures tested. Gaps: IPv6 SSH, sudo paths with spaces, AppArmor denials. |
| **Normalization** | Yes | No | Partial | IPv6 extraction not implemented in `extract_iocs()`. |
| **Storage / DB** | Yes | Yes | Good | Tests schema creation, event insertion, and restart persistence. |
| **REST API** | No | Yes | Good | 5 endpoints tested with `TestClient`. Gaps: unauthenticated client abuse, rate limits. |
| **Frontend GUI** | **NO** | **NO** | **NONE** | No test runner configured in `apps/desktop` (0 frontend tests). |
| **Packaging** | No | No | **NONE** | No automated install/uninstall smoke test on clean container/VM. |
| **Security** | No | No | Partial | Parameterized SQL verified; API capability tokens missing. |

---

## 17. Performance Audit

| Operation | Latency (7,998 Events) | Scaling Risk |
| :--- | :---: | :--- |
| **Paginated Query (50 items)** | 2.77 ms | Low (uses compound index) |
| **Filtered Query (`severity=ALERT`)** | 6.54 ms | Medium (temporary B-tree sorting in SQLite) |
| **Text Search (`search='kernel'`)** | 10.86 ms | High (unindexed table scan on 4 columns; needs FTS5) |
| **24h Statistics Aggregation** | 37.23 ms | Medium (5 separate SQL queries run sequentially) |
| **Telemetry Health Audit** | 14.63 ms | Low (4 filesystem stats) |

---

## 18. Findings Classification

### P0 — Blocking (Must Fix Before M2)
1. **P0-1: Debian Package Missing Engine Dependencies**: `logintel_0.1.0_amd64.deb` fails on clean Ubuntu installations because `pydantic`, `fastapi`, and `uvicorn` are neither bundled in `/usr/lib/logintel/engine/.venv` nor listed in `Depends:`.
2. **P0-2: Event Duplication on Engine Restart**: Collectors do not restore cursors/offsets from `ingestion_state` on startup, and `IngestionEngine._loop()` always runs historical collection on boot. Because random UUIDs are assigned to each event, restarting the engine creates thousands of duplicate events in SQLite.

### P1 — Must Fix Before M2
3. **P1-1: Unauthenticated Localhost API**: The API on `127.0.0.1:41721` lacks authentication. Any local user on the machine can read sensitive security logs or trigger ingestion cycles.
4. **P1-2: FileTailer Timestamp Overwrite**: `FileTailer` sets `RawRecord.timestamp = now()`, which causes parsers to overwrite historical syslog line timestamps with the current ingestion time.
5. **P1-3: Tauri Engine Lifecycle Blind Spot**: Tauri's `is_engine_running()` only checks if port 41721 accepts a TCP connection; it does not verify service identity. If the Python process dies, Tauri never detects or restarts it.

### P2 — Should Fix
6. **P2-1: Sudo Parser Fails on Paths with Spaces**: Regex `PWD=([^\s;]+)` fails to parse sudo logs when the working directory contains spaces.
7. **P2-2: AppArmor Denials Misclassified**: AppArmor security blocks in `kern.log` are parsed as generic kernel messages with `INFORMATIONAL` severity and `Outcome.SUCCESS`.
8. **P2-3: Dead IPv6 IOC Extraction**: `IPV6_PATTERN` is compiled in `sanitizer.py` but never iterated over in `extract_iocs()`.
9. **P2-4: Empty Metadata Tables**: Database tables `hosts` and `sources` exist in migrations but are never populated during ingestion.
10. **P2-5: Missing Composite Index for Filtered Sorting**: Filtering by severity or source requires an in-memory temporary B-tree for `ORDER BY timestamp DESC`.
11. **P2-6: Zero Frontend Automated Tests**: `apps/desktop` has no test framework (Vitest / RTL) configured.

### P3 — Future Improvements
12. **P3-1: Full-Text Search Optimization**: Replace `LIKE '%...%'` with SQLite FTS5 virtual tables for instant search across millions of records.
13. **P3-2: Cross-Source Deduplication Entity Mapping**: Correlate identical real-world events reported by both `journald` and `/var/log/syslog` under a unified event entity while preserving both source provenances.

---

## 19. M1 Completeness Matrix

| Area | Status | Evidence | Risk | Required Before M2? |
| :--- | :---: | :--- | :---: | :---: |
| **Architecture** | **IMPLEMENTED** | Clean layering (Tauri shell, React GUI, Python engine, SQLite store) | Low | No |
| **Tauri Shell** | **IMPLEMENTED** | `lib.rs` and `main.rs` compile; spawns and kills child engine | Med | P1-3 fix |
| **Python Engine** | **IMPLEMENTED** | FastAPI app with lifespan hooks, logging, and settings | Low | No |
| **IPC / API** | **PARTIAL** | REST API functional, but lacks auth token on `127.0.0.1:41721` | High | **Yes (P1-1)** |
| **journald Collector** | **PARTIAL** | Reads `journalctl -o json`, but cursor not restored on boot | High | **Yes (P0-2)** |
| **auth.log Collector** | **PARTIAL** | Tails and handles rotation, but offset not restored on boot; stamps `now()` | High | **Yes (P0-2, P1-2)** |
| **syslog Collector** | **PARTIAL** | Tails and handles rotation, but offset not restored on boot; stamps `now()` | High | **Yes (P0-2, P1-2)** |
| **kern.log Collector** | **PARTIAL** | Tails and handles rotation, but offset not restored on boot; stamps `now()` | High | **Yes (P0-2, P1-2)** |
| **Parsers** | **IMPLEMENTED** | 6 parsers operational with 9 passing tests; minor regex edge cases | Med | P2-1, P2-2 fixes |
| **Event Schema** | **IMPLEMENTED** | Canonical schema capturing actor, process, network, outcome, and evidence | Low | No |
| **Provenance** | **IMPLEMENTED** | Source file, cursor/offset, and immutable raw log preserved | Low | No |
| **SQLite Storage** | **IMPLEMENTED** | SQLite WAL mode, schema migrations, 11 indexes, 11,522 events persisted | Med | P2-5 fix |
| **Ingestion Engine** | **PARTIAL** | Live collection works, but loops historical on every start | High | **Yes (P0-2)** |
| **Health Diagnostics**| **IMPLEMENTED** | Real-time audit of source availability, file size, octal permissions | Low | No |
| **Overview Screen** | **IMPLEMENTED** | Operational metrics, source distributions, severity breakdown, alerts table | Low | No |
| **Activity Screen** | **IMPLEMENTED** | Technical event table, multi-filter toolbar, search, pagination | Low | No |
| **Design System** | **IMPLEMENTED** | IBM Plex fonts, warm neutral palette, sharp borders, zero banned elements | Low | No |
| **Security Model** | **PARTIAL** | Runs non-root via `adm` group, but localhost API exposed to other users | High | **Yes (P1-1)** |
| **Tests** | **PARTIAL** | 17 backend tests passing; zero frontend tests | Med | P2-6 fix |
| **Packaging** | **BROKEN (CLEAN)** | `.deb` builds, but missing Python wheel dependencies on clean machines | High | **Yes (P0-1)** |
| **Documentation** | **IMPLEMENTED** | Accurate architecture, schema, dev, and packaging documentation | Low | No |

---

## 20. Required Fix List (Before Starting M2)

To elevate M1 to production quality for M2:
1. **Debian Package Bundling**: Update `scripts/build_deb.sh` to bundle a self-contained Python virtual environment (with `pydantic`, `fastapi`, and `uvicorn` wheels) inside `/usr/lib/logintel/engine/.venv` within the `.deb` package.
2. **Ingestion State Restoration & Deterministic Deduplication**:
   - In `IngestionEngine._setup_collectors()`, restore `cursor` and `byte_offset` from `ingestion_state`.
   - On startup, do NOT unconditionally re-run historical ingestion if `ingestion_state` records exist for that source.
   - For file logs, use a deterministic content hash (`hashlib.sha256(source + offset + raw_message)`) or compound key to prevent duplicate insertion across restarts.
3. **API Local Token Authentication**:
   - Generate a cryptographically secure random session token when the engine starts and write it to `~/.local/share/logintel/.engine_token` with `0600` permissions.
   - Require `Authorization: Bearer <token>` on all `/api/v1/*` routes.
   - Have Tauri read this token and pass it in all frontend fetch headers.
4. **Fix Timestamp Extraction in FileTailer**:
   - Set `RawRecord.timestamp = None` in `FileTailer` so parsers extract the real event timestamp from the syslog header instead of stamping `datetime.now()`.
5. **Parser Fixes**:
   - Fix `SudoParser` regex to allow spaces in `PWD=`.
   - Classify AppArmor denials in `KernelParser` with `ALERT` severity and `Outcome.FAILURE`.
   - Iterate over both IPv4 and IPv6 in `extract_iocs()`.
6. **Query Plan Optimization**:
   - Add composite indexes: `(source, timestamp DESC)` and `(severity, timestamp DESC)`.

---

## 21. Final Verdict

```text
M1 CONDITIONALLY VERIFIED — FIX LIST REQUIRED BEFORE M2
```

**Verdict Rationale**:  
The foundation is physically real, architectural separation is strictly maintained, and live telemetry is genuinely processed and presented in a compliant enterprise GUI. However, proceeding directly to M2 (Detection rules & attack graphs) on top of an engine that duplicates events on restart, stamps current time onto historical logs, and fails to launch when installed from the `.deb` package on a clean machine would compromise detection accuracy and packaging integrity. Resolving the targeted P0 and P1 fix list above will make the foundation rock-solid for M2.
