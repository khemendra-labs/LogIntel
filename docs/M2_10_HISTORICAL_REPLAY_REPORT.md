# LogIntel — M2.10 Historical Replay Harness Forensic Verification Report

## 1. Executive Summary

Phase **M2.10: Historical Replay Harness** has undergone corrective forensic verification in accordance with the M2.10.1 prompt guidelines.

The historical replay harness delivers deterministic, isolated, side-effect-free historical telemetry evaluation. It replays events strictly in event-time order (`timestamp ASC, id ASC`), supports streaming chunking over large database collections, executes attack scenario fixtures covering all 16 canonical rules, and guarantees zero database mutations during dry-run evaluations.

```text
STATUS: M2.10 VERIFIED — READY FOR M2.11
SCHEMA VERSION: 3 (UNMODIFIED)
MIGRATION 4: NOT CREATED
DATABASE EVENTS: 22,460 PRESERVED (INTACT)
BACKEND TESTS: 180 PASSED (17 dedicated M2.10 replay tests)
FRONTEND TESTS: 9 PASSED
TYPESCRIPT: CLEAN (0 errors, 0 warnings)
API SCOPE: COMPLIANT (Unauthorized M2.10 endpoint removed)
DETERMINISM: VERIFIED (Functional fields bit-for-bit identical; runtime telemetry excluded)
BENIGN BASELINE: VERIFIED (0 detections on defined benign administrative fixture)
RULE COVERAGE: 16 / 16 CANONICAL RULES VERIFIED (Positive & Negative)
ZERO SIDE-EFFECTS: PROVEN SAFE (0 operational rows created in dry-run mode)
```

---

## 2. Baseline Snapshot

Before corrective verification:
- **Database Path**: `/home/khemendra-labs/.local/share/logintel/logintel.db`
- **Schema Version**: `3` (Migration 3: `m2_detection_and_alerts`, PRAGMA schema_version: 35)
- **Migrations Applied**: `(1, 'initial_canonical_schema'), (2, 'm1_1_hardening_fingerprint_and_indexes'), (3, 'm2_detection_and_alerts')`
- **Events Count**: 17,518 (prior to continuous collector ingestion growth)
- **Alerts Count**: 2
- **Detections Count**: 5
- **Detection Evidence Count**: 5
- **Detection Rules in Database**: 16
- **Foreign Key Violations**: 0
- **Journal Mode**: `wal`
- **Git Commit Baseline**: `2bce806` on branch `master`
- **Backend Tests**: 163 passing (pre-M2.10) -> 174 passing (initial M2.10)
- **Frontend Tests**: 9 passing

---

## 3. M2.10 Scope Verification

The authoritative LogIntel M2 roadmap defines M2.10 as:
```text
M2.10 Deterministic Replay & Test Fixtures / Historical Replay Harness
```
Scope boundaries:
- In-memory historical replay harness (`HistoricalReplayHarness`).
- Command-line interface (`python -m logintel.detection.replay_cli`).
- Attack scenario fixtures covering canonical threat classes.
- Zero database pollution in dry-run mode.
- Strict chronological sorting (`ORDER BY timestamp ASC, id ASC`).

---

## 4. Replay Architecture Verification

The replay architecture is implemented in [`apps/engine/src/logintel/detection/replay.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/detection/replay.py):
1. **Engine Isolation**: `HistoricalReplayHarness.replay_events()` instantiates a fresh `DetectionEngine` with its own isolated `RuleRegistry` and window state. Prior replay state does not bleed into subsequent runs.
2. **Database Streaming**: `stream_events_from_db()` fetches rows via `cur.fetchmany(config.batch_size)` deserializing through `CanonicalEvent.from_db_row(dict(row))`. Memory consumption is bounded regardless of total database size.
3. **Simulated Consolidation**: Deduplication keys (`dedup_key`) and cooldown windows are computed in memory using the exact same deterministic logic as `AlertsRepository`, populating `SimulatedAlert` records without issuing database writes.

---

## 5. REST API Scope Determination

### Forensic Finding
The initial M2.10 implementation introduced an unannounced REST API endpoint:
```text
POST /api/v1/detection/replay
```
Review of the original M2 specification and phase milestones confirms:
- **M2.8** was the dedicated REST API milestone (`/api/v1/detection/rules`, `/api/v1/alerts`).
- **M2.10** specified a historical replay harness and CLI runner for evaluation and regression testing.
- No REST API endpoint was authorized for M2.10.

### Corrective Action Taken
In strict compliance with Finding A:
1. `ReplayRequest` schema and `run_detection_replay` endpoint were **completely removed** from [`apps/engine/src/logintel/api/routes.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/api/routes.py).
2. Unauthorized API integration tests were removed from [`apps/engine/tests/test_historical_replay.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_historical_replay.py).
3. The core Python replay harness and standalone CLI runner were preserved intact.

---

## 6. Determinism Verification

### Finding & Clarification
The initial claim of "bit-for-bit identical results" was overbroad because runtime performance metrics (`duration_seconds`, `events_per_second`, `start_wall_time`, `end_wall_time`) inherently fluctuate with CPU scheduling and load.

### Verified Deterministic Invariants
Across repeated replay runs on identical event streams, the following functional properties are guaranteed and tested to be identical:
- `total_events_evaluated`
- `total_detections_count`
- `detections_by_rule` (exact rule hit counts)
- `detections_by_severity` (exact severity distributions)
- `rules_evaluated_count`
- `simulated_alerts_count`
- Simulated alert contents: `rule_id`, `dedup_key`, `title`, `severity`, `host`, `occurrence_count`, and `evidence_event_ids`.

**Corrective Statement**:
> Replay detection and output determinism is verified for identical input; runtime-dependent performance metrics (`duration_seconds`, `events_per_second`, wall-clock timestamps) are excluded from the deterministic comparison.

Verified via test: `test_replay_determinism_excluding_runtime_telemetry` in `apps/engine/tests/test_historical_replay.py`.

---

## 7. Benign Baseline Verification

### Corrective Qualification
The initial claim of "0 false positives" was overly broad for an entire detection system.

The empirical test establishes specifically:
> **No detections were produced for the defined benign administrative baseline fixture.**

Fixture details (`create_benign_administrative_scenario`):
- Event 1: Legitimate SSH public key login for `sysadmin` (`AUTH_LOGIN_SUCCESS`, `ssh_success`).
- Event 2: Standard non-shell sudo command `sudo /bin/systemctl restart nginx` (`SUDO_COMMAND`, `SUCCESS`, `sudo_command`).
- Event 3: PAM session closure (`SESSION_CLOSE`, `pam_session`).
- Evaluated: 3 canonical events across all 16 active detection rules.
- Result: **0 detections, 0 simulated alerts**.

Verified via test: `test_replay_benign_administrative_scenario_zero_false_positives` in `apps/engine/tests/test_historical_replay.py`.

---

## 8. Canonical Rule Coverage Matrix

All 16 canonical detection rules in the catalog are exercised by deterministic attack scenario fixtures in [`apps/engine/tests/fixtures/attack_scenarios.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/fixtures/attack_scenarios.py):

| Rule ID | Fixture Exercised | Positive Result | Negative Result |
| :--- | :--- | :---: | :---: |
| `auth.ssh_bruteforce` | `create_ssh_bruteforce_scenario` | Fired (threshold 5 hits in 60s) | Sub-threshold (2 failures) produces 0 hits |
| `auth.invalid_user` | `create_auth_attacks_scenario` | Fired (3 invalid user failures) | Valid username failures do not match |
| `auth.root_login` | `create_auth_attacks_scenario` | Fired (direct root SSH success) | Standard non-root user produces 0 hits |
| `auth.password_spray` | `create_auth_attacks_scenario` | Fired (10 failures from single IP) | Failures from disparate IPs do not aggregate |
| `auth.repeated_failures` | `create_auth_attacks_scenario` | Fired (5 failures for user alice) | Failures across different users do not meet threshold |
| `priv.sudo_failure` | `create_privilege_escalation_scenario` | Fired (3 consecutive sudo failures) | 1-2 failures (sub-threshold 3) produces 0 hits |
| `priv.unauthorized_sudo` | `create_privilege_escalation_scenario` | Fired ("user NOT in sudoers") | Authorized sudo attempts produce 0 hits |
| `priv.sudo_root_shell` | `create_privilege_escalation_scenario` | Fired (`sudo /bin/bash`) | Benign command `sudo systemctl` produces 0 hits |
| `proc.apparmor_denial` | `create_recon_and_segfault_scenario` | Fired (AppArmor access denied) | Allowed AppArmor events produce 0 hits |
| `proc.reconnaissance_tools` | `create_recon_and_segfault_scenario` | Fired (`sudo nmap -sS ...`) | Standard tools (e.g. `cat`, `ls`) produce 0 hits |
| `proc.segfault_burst` | `create_recon_and_segfault_scenario` | Fired (5 segfaults within 20s) | 2 segfaults (sub-threshold 3) produces 0 hits |
| `account.root_creation` | `create_account_tampering_scenario` | Fired (`useradd` with UID 0) | Standard user creation (UID 1001) produces 0 hits |
| `account.deletion_burst` | `create_account_tampering_scenario` | Fired (3 user deletions in 60s) | 1 deletion (sub-threshold 3) produces 0 hits |
| `network.firewall_scan_burst` | `create_network_intrusion_scenario` | Fired (5 UFW blocks from IP) | 2 UFW blocks (sub-threshold 5) produces 0 hits |
| `network.sensitive_port_probe` | `create_network_intrusion_scenario` | Fired (UFW blocked port 3389) | Probes on unlisted ports produce 0 hits |
| `network.threat_intel_ioc_match`| `create_network_intrusion_scenario` | Fired (matched IOC 198.51.100.66) | Events without malicious IOCs produce 0 hits |

**Total Canonical Rules**: 16  
**Rules with Verified Positive Coverage**: 16 (100%)  
**Rules with Verified Negative Coverage**: 16 (100%)

---

## 9. Replay Isolation Verification

Each replay invocation instantiates an isolated `DetectionEngine` with fresh window queues and local alert deduplication tables.

### Test Verification
Test `test_replay_engine_state_isolation` verifies that:
1. Replay Run A executes 6 SSH failures, satisfying `auth.ssh_bruteforce` (threshold 5).
2. Replay Run B immediately executes 2 SSH failures (sub-threshold 5).
3. Replay Run B produces **0 detections** and **0 simulated alerts**, proving that no queue state, counts, or cooldown records leaked from Run A.

---

## 10. Ordering Verification

Database replay uses explicit event-time ordering:
```sql
SELECT * FROM events WHERE 1=1 ORDER BY timestamp ASC, id ASC
```
### Stable Tie-Breaking
When multiple events share identical timestamps, `id ASC` guarantees a deterministic, reproducible execution sequence across platforms and database restarts. SQLite's arbitrary internal rowid order is never relied upon.

Verified via test: `test_replay_ordering_with_equal_timestamps_tiebreaker`.

---

## 11. Filtering Verification

All replay filters were verified independently:
1. **Rule Filter (`--rule-id <id>`)**: Replay isolates evaluation strictly to the specified rule (`test_replay_rule_ids_filtering`).
2. **Category Filter (`--category <cat>`)**: Replay evaluates only rules belonging to that category (`test_replay_category_filtering`).
3. **Host Filter (`--host <host>`)**: Replay evaluates only events belonging to the target host (`test_replay_host_filtering`).
4. **Max Events Limit (`--max-events <n>`)**: Replay halts immediately upon evaluating `n` events (`test_replay_max_events_limit`).
5. **Batch Size Invariance**: Replay results are invariant to streaming chunk size (`batch_size=1`, `batch_size=5`, `batch_size=100` produce identical detections and alerts, verified by `test_replay_batch_size_invariance`).

---

## 12. Database Side-Effect Verification

A dry-run replay was executed against the active production database (`~/.local/share/logintel/logintel.db`).

### Table Row Count Comparisons
| Table | Before Replay | After Replay | Difference |
| :--- | :---: | :---: | :---: |
| `alerts` | 2 | 2 | **0 (Unchanged)** |
| `detections` | 6 | 6 | **0 (Unchanged)** |
| `detection_evidence` | 6 | 6 | **0 (Unchanged)** |
| `detection_rules` | 16 | 16 | **0 (Unchanged)** |
| `schema_migrations` | 3 | 3 | **0 (Unchanged)** |

**Verified**: Dry-run replay is 100% read-only and causes zero side effects on operational database tables.

---

## 13. CLI Verification

The CLI runner [`logintel.detection.replay_cli`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/detection/replay_cli.py) was tested across all supported invocation modes:
- `--help`: Clean argument documentation, exit code 0.
- `--format text`: Formatted tabular output with summary, detections, and alerts, exit code 0.
- `--format json`: Valid JSON document with all report fields, exit code 0.
- `--category AUTH`: Correctly isolates rules to 5 AUTH rules, exit code 0.
- `--rule-id <id>`: Correctly isolates to single rule, exit code 0.
- Unrecognized arguments: Exits with code 2 and usage error.

---

## 14. Test Results

### Backend Pytest Suite
```text
======================== 180 passed, 1 warning in 6.99s ========================
```
- `test_historical_replay.py`: 17 passed
- `test_detection_api.py`: 10 passed
- `test_alert_lifecycle.py`: 10 passed
- `test_privilege_and_process_rules.py`: 16 passed
- `test_account_network_ioc_rules.py`: 18 passed
- `test_authentication_rules.py`: 15 passed
- `test_detection_rules.py`: 42 passed
- `test_detection_engine.py`: 15 passed
- `test_detection_storage.py`: 7 passed
- `test_parsers.py`: 13 passed
- `test_collectors_and_storage.py`: 14 passed
- `test_api.py`: 3 passed

### Frontend Vitest Suite
```text
Test Files  1 passed (1)
     Tests  9 passed (9)
  Duration  1.16s
```

### TypeScript & Python Compilation
- `npx tsc --noEmit`: 0 errors.
- `python3 -m compileall apps/engine/src`: 0 errors.

---

## 15. Database Integrity

- **Database Path**: `/home/khemendra-labs/.local/share/logintel/logintel.db`
- **Schema Version**: `3` (PRAGMA schema_version: 35)
- **Migrations Applied**: `1, 2, 3` (Migration 4 NOT created)
- **Foreign Key Check**: `PRAGMA foreign_key_check` -> `0 violations`
- **Journal Mode**: `wal`
- **Operational Data**: Preserved intact.

---

## 16. Scope Boundary Compliance

- **M2.11 Packaging**: NOT IMPLEMENTED.
- **Debian Packaging (`.deb`)**: Unmodified.
- **Desktop Packaging / Tauri Build**: Unmodified.
- **New Database Migrations**: 0 created.
- **Schema Modifications**: 0.

---

## 17. Remaining Limitations

1. **Replay Speed vs Live IO**: The replay harness operates synchronously in-process. On systems with multi-gigabyte log collections, database query batch size (`--batch-size`) should be tuned between 1,000 and 5,000 events to balance memory usage and cursor roundtrips.
2. **Synthetic Attack Timestamps**: Attack scenarios use synthetic UTC timestamps spaced evenly across event sequences. Real-world telemetry bursts with microsecond granularity rely on `id ASC` tie-breaking.
3. **Out-of-Order Handling**: Replay streams events in strictly sorted timestamp order (`ORDER BY timestamp ASC, id ASC`). Late-arriving events that were persisted with historical timestamps are replayed in their true chronological order.

---

## 18. Final Phase Gate

```text
======================================================
PHASE GATE: M2.10 COMPLETE

STATUS: M2.10 VERIFIED — READY FOR M2.11

NEXT AUTHORIZED PHASE:
M2.11 — PACKAGING VERIFICATION & FINAL M2 CLOSURE

WAITING FOR EXPLICIT APPROVAL TO CONTINUE.
======================================================
```
