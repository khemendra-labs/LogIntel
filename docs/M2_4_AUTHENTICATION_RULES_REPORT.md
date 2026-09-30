# LogIntel — M2.4 Authentication Detection Rules Implementation Report

## Executive Summary

Phase **M2.4: Authentication Detection Rules** has been successfully implemented and forensically verified in accordance with the LogIntel M2 roadmap.

All 5 canonical authentication detection rules are implemented as declarative YAML definitions adhering strictly to the M2.1 rule schema specification, loaded via `load_default_rules()` into the thread-safe `RuleRegistry`, and evaluated deterministically by the `DetectionEngine`.

```text
STATUS: M2.4 VERIFIED — READY FOR M2.5
SCHEMA VERSION: 3 (UNMODIFIED)
MIGRATION 4: NOT CREATED
DATABASE EVENTS: 17,169 PRESERVED
BACKEND TESTS: 112 PASSED (16 dedicated M2.4 tests)
FRONTEND TESTS: 4 PASSED
ZERO SCOPE CREEP: M2.5–M2.11 NOT IMPLEMENTED
```

---

## 1. Canonical Authentication Rules

The rules reside in `rules/authentication/` and are organized as follows:

| Rule ID | Rule Type | Severity | Category | Trigger Logic | Window / Threshold | Group By | Cooldown |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `auth.ssh_bruteforce` | `THRESHOLD` | `ALERT` | `AUTH` | `event_type == AUTH_LOGIN_FAILURE`, `outcome == FAILURE`, `src_ip` exists | 5 events in 300s | `[src_ip, host]` | 3600s |
| `auth.invalid_user` | `THRESHOLD` | `ALERT` | `AUTH` | `event_type == AUTH_LOGIN_FAILURE`, `outcome == FAILURE`, `summary contains "invalid user"`, `src_ip` exists | 3 events in 180s | `[src_ip, host]` | 3600s |
| `auth.root_login` | `ATOMIC` | `WARNING` | `AUTH` | `event_type == AUTH_LOGIN_SUCCESS`, `outcome == SUCCESS`, `username == "root"`, `parser == "openssh_auth"` | 1 event (immediate) | N/A | N/A |
| `auth.password_spray` | `THRESHOLD` | `CRITICAL` | `AUTH` | `event_type == AUTH_LOGIN_FAILURE`, `outcome == FAILURE`, `src_ip` exists | 10 events in 600s | `[src_ip]` | 7200s |
| `auth.repeated_failures` | `THRESHOLD` | `WARNING` | `AUTH` | `event_type == AUTH_LOGIN_FAILURE`, `outcome == FAILURE`, `username` exists | 5 events in 300s | `[username, host]` | 1800s |

### Rule Implementations

1. **`auth.ssh_bruteforce`** ([`rules/authentication/auth_ssh_bruteforce.yaml`](file:///home/khemendra-labs/LogIntel/rules/authentication/auth_ssh_bruteforce.yaml)):
   - Detects repeated failed SSH authentication attempts from a single source IP targeting a host.
   - Requires count $\ge 5$ within a 300-second window.

2. **`auth.invalid_user`** ([`rules/authentication/auth_invalid_user.yaml`](file:///home/khemendra-labs/LogIntel/rules/authentication/auth_invalid_user.yaml)):
   - Detects rapid authentication attempts targeting non-existent or invalid accounts, a common indicator of automated username enumeration.
   - Requires count $\ge 3$ within 180 seconds with `summary` containing `"invalid user"`.

3. **`auth.root_login`** ([`rules/authentication/auth_root_login.yaml`](file:///home/khemendra-labs/LogIntel/rules/authentication/auth_root_login.yaml)):
   - Detects direct interactive root authentication via SSH (`parser == "openssh_auth"`).
   - Atomic evaluation triggers immediately on successful root authentication.

4. **`auth.password_spray`** ([`rules/authentication/auth_password_spray.yaml`](file:///home/khemendra-labs/LogIntel/rules/authentication/auth_password_spray.yaml)):
   - Detects high-volume authentication failures originating from a single source IP across multiple accounts.
   - Requires count $\ge 10$ within 600 seconds, grouped strictly by `[src_ip]`.

5. **`auth.repeated_failures`** ([`rules/authentication/auth_repeated_failures.yaml`](file:///home/khemendra-labs/LogIntel/rules/authentication/auth_repeated_failures.yaml)):
   - Detects targeted account attacks where repeated failures occur against a specific username on a specific host, regardless of source IP rotation.
   - Requires count $\ge 5$ within 300 seconds, grouped by `[username, host]`.

---

## 2. Loader and Settings Integration

- **`rules_dir` Resolution** ([`apps/engine/src/logintel/config/settings.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/config/settings.py)):
  - Dynamically traverses directory parents to locate `rules/` in development and repository environments.
  - Supports `LOGINTEL_RULES_DIR` environment override and Debian package path `/usr/share/logintel/rules`.
- **`load_default_rules()`** ([`apps/engine/src/logintel/detection/loader.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/detection/loader.py)):
  - Loads, parses, and validates all `.yaml` rule files in `rules/` into typed `DetectionRule` objects.
  - Exported through `logintel.detection`.

---

## 3. Test Verification Metrics

### Dedicated M2.4 Test Suite
File: [`apps/engine/tests/test_authentication_rules.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_authentication_rules.py)
**16 tests passing, 0 failing:**

- `test_load_default_authentication_rules`: Confirms all 5 canonical rules load and pass Pydantic + semantic validation.
- `test_registry_registration_of_default_rules`: Confirms batch registration in `RuleRegistry` without duplicate ID collision.
- `test_auth_ssh_bruteforce_positive`: Verifies 5 failed logins trigger 1 detection with 5 evidence items (1 `TRIGGER`, 4 `AGGREGATE`).
- `test_auth_ssh_bruteforce_negative_below_threshold`: Verifies 4 failed logins produce 0 detections.
- `test_auth_ssh_bruteforce_negative_separated_ips`: Verifies failures from distinct IPs do not cross-accumulate.
- `test_auth_ssh_bruteforce_negative_outside_window`: Verifies events outside the 300s window expire from the sliding window.
- `test_auth_invalid_user_positive`: Verifies 3 invalid user failures trigger alert within 180s.
- `test_auth_invalid_user_negative_normal_failures`: Verifies normal valid user login failures do not trigger invalid user burst.
- `test_auth_root_login_positive`: Verifies successful root login via SSH triggers immediate atomic alert with `TRIGGER` evidence role.
- `test_auth_root_login_negative_non_root`: Verifies successful non-root SSH login produces 0 detections.
- `test_auth_root_login_negative_failed_login`: Verifies failed root login does not trigger successful root login rule.
- `test_auth_root_login_negative_different_parser`: Verifies local root elevation via sudo or pam does not trigger SSH root login rule.
- `test_auth_password_spray_positive`: Verifies 10 failures from single IP across accounts trigger `CRITICAL` spray detection.
- `test_auth_password_spray_negative_sub_threshold`: Verifies 9 spray attempts produce 0 detections.
- `test_auth_repeated_failures_positive`: Verifies 5 failures targeting single user on a host trigger detection.
- `test_auth_repeated_failures_negative_scattered_users`: Verifies failures distributed across different users do not trigger single account rule.

### Full Engine Test Suite
Command: `./apps/engine/.venv/bin/pytest apps/engine/tests/ -v`
**112 tests passing, 0 failing, 0 regressions.**

### Frontend Test Suite
Command: `npm test` in `apps/desktop`
**4 tests passing, 0 failing.**

---

## 4. Production Database Verification

```text
Database Path:        /home/khemendra-labs/.local/share/logintel/logintel.db
Schema Version:       3 (Migration 3: m2_detection_and_alerts)
Migration 4:          NOT CREATED
Events Table Count:   17,169 rows (INTACT)
Foreign Key Check:    0 violations
Journal Mode:         wal
```

---

## 5. Scope Boundary Compliance

| Milestone Phase | Status | Notes |
| :--- | :--- | :--- |
| **M2.1** Detection Core Specification | VERIFIED | Schema, validators, canonical registry |
| **M2.2** Detection DB Model / Migration 3 | VERIFIED | Tables, indexes, FK protections |
| **M2.3 / M2.3.1** In-Memory Engine | VERIFIED | Sliding window, ReDoS safety, deterministic |
| **M2.4** Authentication Rules | **VERIFIED** | **Completed & tested in this phase** |
| **M2.5** Privilege & Process Rules | DEFERRED | Explicitly forbidden during M2.4 |
| **M2.6** Account / Network / IOC Rules | DEFERRED | Explicitly forbidden during M2.4 |
| **M2.7** Alert Lifecycle / Deduplication | DEFERRED | Explicitly forbidden during M2.4 |
| **M2.8** REST API Detection Endpoints | DEFERRED | Explicitly forbidden during M2.4 |
| **M2.9** GUI Detection Interface | DEFERRED | Explicitly forbidden during M2.4 |
| **M2.10** Historical Replay Harness | DEFERRED | Explicitly forbidden during M2.4 |
| **M2.11** Debian Packaging & Production | DEFERRED | Explicitly forbidden during M2.4 |

---

## 6. Phase Gate Verdict

```text
==================================================================
PHASE GATE: M2.4 VERIFIED — READY FOR M2.5
All 5 canonical authentication detection rules are implemented,
validated, and covered by 16 passing unit/integration tests.
No schema migrations, zero database alterations, zero scope creep.
Awaiting user authorization to proceed to M2.5.
==================================================================
```
