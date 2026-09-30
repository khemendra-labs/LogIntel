# LogIntel — M2.6 Account, Network & IOC Detection Rules Implementation Report

## Executive Summary

Phase **M2.6: Account, Network & IOC Detection Rules** has been successfully implemented, validated, and forensically verified in accordance with the LogIntel M2 roadmap.

5 canonical detection rules covering root account creation, rapid account deletion bursts, UFW firewall port scanning bursts, sensitive infrastructure port probing, and threat intelligence IOC matching have been implemented as declarative YAML rules.

All 5 rules adhere strictly to the M2.1 rule schema specification, are loaded through `load_default_rules()`, and are evaluated deterministically by the `DetectionEngine`.

```text
STATUS: M2.6 VERIFIED — READY FOR M2.7
SCHEMA VERSION: 3 (UNMODIFIED)
MIGRATION 4: NOT CREATED
DATABASE EVENTS: 17,418 PRESERVED (INTACT)
BACKEND TESTS: 143 PASSED (15 dedicated M2.6 tests)
FRONTEND TESTS: 4 PASSED
ZERO SCOPE CREEP: M2.7–M2.11 NOT IMPLEMENTED
```

---

## 1. Canonical Account, Network & IOC Rules

The rules are organized into `rules/account/` and `rules/network/`:

| Rule ID | Rule Type | Severity | Category | Trigger Logic | Window / Threshold | Group By | Cooldown |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `account.root_creation` | `ATOMIC` | `CRITICAL` | `ACCOUNT` | `event_type == USER_CREATE`, `uid == 0` | 1 event (immediate) | N/A | 3600s |
| `account.deletion_burst` | `THRESHOLD` | `WARNING` | `ACCOUNT` | `event_type == USER_DELETE`, `outcome == SUCCESS` | 3 events in 180s | `[host]` | 1800s |
| `network.firewall_scan_burst` | `THRESHOLD` | `ALERT` | `NETWORK` | `summary contains "UFW Firewall blocked"`, `src_ip` exists | 5 events in 120s | `[src_ip, host]` | 1800s |
| `network.sensitive_port_probe` | `ATOMIC` | `WARNING` | `NETWORK` | `summary contains "UFW Firewall blocked"`, `dst_port in [22, 3389, 3306, 5432, 6379, 6443]` | 1 event (immediate) | N/A | 600s |
| `network.threat_intel_ioc_match` | `ATOMIC` | `CRITICAL` | `NETWORK` | `iocs in ["198.51.100.66", "203.0.113.199", "192.0.2.100"]` | 1 event (immediate) | N/A | 3600s |

### Rule Implementations

1. **`account.root_creation`** ([`rules/account/account_root_creation.yaml`](file:///home/khemendra-labs/LogIntel/rules/account/account_root_creation.yaml)):
   - Detects creation of a new local user account with UID 0 (root-equivalent privilege).
   - Atomic evaluation triggers an immediate `CRITICAL` alert with `TRIGGER` evidence role.

2. **`account.deletion_burst`** ([`rules/account/account_deletion_burst.yaml`](file:///home/khemendra-labs/LogIntel/rules/account/account_deletion_burst.yaml)):
   - Detects rapid deletion of multiple local accounts within a short window, which may indicate anti-forensic activity or malicious disruption.
   - Requires count $\ge 3$ within a 180-second window, grouped by `[host]`.

3. **`network.firewall_scan_burst`** ([`rules/network/net_firewall_scan_burst.yaml`](file:///home/khemendra-labs/LogIntel/rules/network/net_firewall_scan_burst.yaml)):
   - Detects inbound reconnaissance and port scanning activity blocked by the Linux UFW firewall.
   - Requires count $\ge 5$ blocked connection attempts from a single source IP within 120 seconds, grouped by `[src_ip, host]`.

4. **`network.sensitive_port_probe`** ([`rules/network/net_sensitive_port_probe.yaml`](file:///home/khemendra-labs/LogIntel/rules/network/net_sensitive_port_probe.yaml)):
   - Detects targeted blocked connection attempts probing sensitive administrative or database services (SSH: 22, RDP: 3389, MySQL: 3306, Postgres: 5432, Redis: 6379, Kubernetes API: 6443).
   - Atomic evaluation triggers immediately on packet drop.

5. **`network.threat_intel_ioc_match`** ([`rules/network/net_threat_feed_ioc_match.yaml`](file:///home/khemendra-labs/LogIntel/rules/network/net_threat_feed_ioc_match.yaml)):
   - Detects any canonical event exhibiting indicators of compromise (IOCs) matching known malicious threat infrastructure.
   - Uses list-intersection semantics via the `in` operator on the canonical `iocs` field.

---

## 2. Test Verification Metrics

### Dedicated M2.6 Test Suite
File: [`apps/engine/tests/test_account_network_ioc_rules.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_account_network_ioc_rules.py)
**15 tests passing, 0 failing:**

- `test_load_account_and_network_rules`: Confirms all 5 rules load cleanly and pass semantic validation.
- `test_registry_category_filtering_account_and_network`: Confirms registry filters by `ACCOUNT` and `NETWORK` categories.
- `test_account_root_creation_positive`: Verifies creation of UID 0 account triggers `CRITICAL` alert.
- `test_account_root_creation_negative_normal_uid`: Verifies creation of normal unprivileged UID account produces 0 detections.
- `test_account_root_creation_negative_different_event_type`: Verifies non-creation event does not trigger root creation rule.
- `test_account_deletion_burst_positive`: Verifies 3 account deletions trigger `WARNING` burst detection.
- `test_account_deletion_burst_negative_sub_threshold`: Verifies 2 account deletions produce 0 detections.
- `test_account_deletion_burst_negative_separated_hosts`: Verifies deletions across distinct hosts do not cross-accumulate.
- `test_network_firewall_scan_burst_positive`: Verifies 5 firewall drops trigger `ALERT` scan detection with 5 evidence items.
- `test_network_firewall_scan_burst_negative_sub_threshold`: Verifies 4 drops produce 0 detections.
- `test_network_firewall_scan_burst_negative_separated_ips`: Verifies drops from distinct IPs do not accumulate together.
- `test_network_sensitive_port_probe_positive`: Verifies probes targeting listed sensitive ports trigger `WARNING`.
- `test_network_sensitive_port_probe_negative_benign_port`: Verifies probes targeting unlisted ports do not trigger.
- `test_network_threat_intel_ioc_match_positive`: Verifies presence of threat IOC triggers `CRITICAL` alert.
- `test_network_threat_intel_ioc_match_negative`: Verifies benign IOCs do not match threat intel list.

### Full Engine Test Suite
Command: `./apps/engine/.venv/bin/pytest apps/engine/tests/ -v`
**143 tests passing, 0 failing, 0 regressions.**

### Frontend Test Suite
Command: `npm test` in `apps/desktop`
**4 tests passing, 0 failing.**

---

## 3. Production Database Verification

```text
Database Path:        /home/khemendra-labs/.local/share/logintel/logintel.db
Schema Version:       3 (Migration 3: m2_detection_and_alerts)
Migration 4:          NOT CREATED
Events Table Count:   17,418 rows (INTACT)
Foreign Key Check:    0 violations
Journal Mode:         wal
```

---

## 4. Scope Boundary Compliance

| Milestone Phase | Status | Notes |
| :--- | :--- | :--- |
| **M2.1** Detection Core Specification | VERIFIED | Schema, validators, canonical registry |
| **M2.2** Detection DB Model / Migration 3 | VERIFIED | Tables, indexes, FK protections |
| **M2.3 / M2.3.1** In-Memory Engine | VERIFIED | Sliding window, ReDoS safety, deterministic |
| **M2.4** Authentication Rules | VERIFIED | 5 canonical authentication rules |
| **M2.5** Privilege & Process Rules | VERIFIED | 6 canonical privilege & process rules |
| **M2.6** Account / Network / IOC Rules | **VERIFIED** | **Completed & tested in this phase** |
| **M2.7** Alert Lifecycle / Deduplication | DEFERRED | Explicitly forbidden during M2.6 |
| **M2.8** REST API Detection Endpoints | DEFERRED | Explicitly forbidden during M2.6 |
| **M2.9** GUI Detection Interface | DEFERRED | Explicitly forbidden during M2.6 |
| **M2.10** Historical Replay Harness | DEFERRED | Explicitly forbidden during M2.6 |
| **M2.11** Debian Packaging & Production | DEFERRED | Explicitly forbidden during M2.6 |

---

## 5. Phase Gate Verdict

```text
==================================================================
PHASE GATE: M2.6 VERIFIED — READY FOR M2.7
All 5 canonical account, network & IOC detection rules are implemented,
validated, and covered by 15 passing unit/integration tests.
Total canonical rules in engine catalog: 16 (across 5 categories).
No schema migrations, zero database alterations, zero scope creep.
Awaiting user authorization to proceed to M2.7.
==================================================================
```
