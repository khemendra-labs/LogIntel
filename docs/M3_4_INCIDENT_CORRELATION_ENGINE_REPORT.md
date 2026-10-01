# LOGINTEL — MILESTONE M3.4 FORENSIC REPORT

## Incident Correlation Engine, Attack Graph Synthesis & Multi-Stage Escalation

**Repository:** `/home/khemendra-labs/LogIntel`  
**Milestone:** M3.4  
**Previous Gate:** M3.3 VERIFIED — Incident Storage Repository  
**Package:** `apps/engine/src/logintel/correlation/`  
**Date:** 2026-09-30  
**Status:** M3.4 VERIFIED — READY FOR M3.5  

---

# 1. Executive Summary

Milestone M3.4 implements the **Incident Correlation Engine** ([`apps/engine/src/logintel/correlation/engine.py`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/correlation/engine.py)), establishing deterministic, offline, local-first correlation of discrete operational security alerts into high-level security incidents.

The engine achieves:
1. **Sliding Event-Time Window Aggregation:** Configurable correlation window (`window_seconds = 1800` / 30m) clustering alerts based on temporal proximity and incident lifespan boundaries (`max_incident_duration_seconds = 86400` / 24h).
2. **Entity Affinity & Pivot Matching:** Clusters alerts originating on the same primary host, target user account, or originating attacker IP address.
3. **Cross-Host Lateral Movement Detection:** Automatically correlates alerts across disparate hosts when triggered by a shared external IP or credential pivot, generating directed `LATERAL_MOVEMENT` graph edges.
4. **Multi-Stage Attack Escalation:** Aligns detection rule categories with canonical ATT&CK kill-chain stages (`INITIAL_ACCESS`, `EXECUTION`, `PRIVILEGE_ESCALATION`, `PERSISTENCE`, `DISCOVERY`, `DEFENSE_EVASION`), automatically elevating incident severity to `CRITICAL` upon multi-stage progression.
5. **Automated Attack Graph Synthesis:** Extracts nodes (`HOST`, `USER`, `IP`, `PROCESS`) and directed edges (`CONNECTED_TO`, `AUTHENTICATED_TO`, `EXECUTED`, `LATERAL_MOVEMENT`) directly from alert telemetry and evidence events.

---

# 2. Package Architecture & Modules

The correlation subsystem is structured in [`apps/engine/src/logintel/correlation/`](file:///home/khemendra-labs/LogIntel/apps/engine/src/logintel/correlation/):

### 2.1 `config.py` — `CorrelationConfig`
- `window_seconds: int = 1800` (30 minutes sliding window)
- `max_incident_duration_seconds: int = 86400` (24 hour rollover limit)
- `cross_host_correlation: bool = True` (Multi-host pivoting enabled)
- `multi_stage_escalation: bool = True` (Automatic severity bump on kill-chain progression)
- `min_alerts_for_multi_stage: int = 2`

### 2.2 `scenarios.py` — Kill Chain Taxonomy & Escalation Logic
- Maps detection rule categories (`AUTH`, `PROCESS`, `PRIVILEGE`, `ACCOUNT`, `NETWORK`, `SECURITY`) to `AttackStage` enum members.
- Identifies signature attack progressions:
  - `Initial Access -> Privilege Escalation` (e.g. SSH brute force followed by Sudo root shell -> `CRITICAL`)
  - `Network Reconnaissance -> Access Attempt` (Port scan followed by auth burst)
  - `Privilege Escalation -> Account Tampering` (Sudo elevation followed by root account creation)
  - `Execution -> Security Denial` (Segfault burst with AppArmor denial)

### 2.3 `engine.py` — `IncidentCorrelationEngine`
- **`correlate_alert(alert_id: int) -> Optional[Incident]`**:
  - Idempotently checks if alert is already correlated.
  - Retrieves alert details, detections, and underlying canonical events.
  - Extracts graph entities (`host:<host>`, `user:<user>`, `ip:<src_ip>`, `process:<proc>`).
  - Searches active (`OPEN`, `INVESTIGATING`) incidents overlapping the time window with entity affinity.
  - If a matching incident is found: merges alert, updates metrics, adds new entities/relationships, checks cross-host lateral movement, and evaluates multi-stage severity escalation.
  - If no candidate matches: generates a deterministic key (`inc:{host}:{user}:{window_bucket}:{alert_id}`) and creates a fresh incident.
- **`correlate_unassigned_alerts() -> List[Incident]`**:
  - Scans for all unlinked alerts (`WHERE ia.id IS NULL`), sorting chronologically and batch-correlating them.

---

# 3. Test Verification Suite

Test Suite: [`apps/engine/tests/test_incident_correlation_engine.py`](file:///home/khemendra-labs/LogIntel/apps/engine/tests/test_incident_correlation_engine.py)  
Total Suite Tests: **9 passed in 0.58s**

| Test Name | Focus | Result |
|---|---|---|
| `test_correlate_single_alert_creates_incident` | Baseline incident creation, entity extraction, directed relationships | **PASSED** |
| `test_correlate_subsequent_alert_same_host_within_window` | Alert merging into active incident within 30-min window | **PASSED** |
| `test_correlate_alert_outside_window_creates_new_incident` | Window expiry enforcement (45 min delta triggers new incident) | **PASSED** |
| `test_multi_stage_attack_escalation` | Progression from `AUTH` to `PRIVILEGE` escalates severity to `CRITICAL` | **PASSED** |
| `test_cross_host_correlation_via_attacker_ip` | Shared attacker IP across 2 hosts triggers `LATERAL_MOVEMENT` edge | **PASSED** |
| `test_correlate_unassigned_alerts_batch` | Batch clustering of unassigned alerts across multiple hosts | **PASSED** |
| `test_already_correlated_alert_idempotency` | Idempotent handling of already-correlated alerts | **PASSED** |
| `test_closed_incident_does_not_absorb_new_alert` | Terminal states (`RESOLVED`/`CLOSED`) do not absorb incoming alerts | **PASSED** |
| `test_attack_graph_nodes_and_edges_synthesis` | Graph schema validation: `HOST`, `USER`, `IP` nodes and directed edges | **PASSED** |

---

# 4. Regression Status

- **Engine Test Suite:** **217 passed** (0 failures, 1 warning)
- **Desktop Vitest Suite:** **10 passed** (0 failures)
- **Desktop TypeScript:** **0 errors**

---

# 5. Milestone Progress & Next Gate

- **M3.0 (Architecture Audit):** **VERIFIED**
- **M3.1 (Domain Models):** **VERIFIED**
- **M3.2 (Schema Migration 4):** **VERIFIED**
- **M3.3 (Incident Storage Repository):** **VERIFIED**
- **M3.4 (Incident Correlation Engine):** **VERIFIED**
- **M3.5 (Incident & Attack Graph REST API):** **NEXT** (Implement FastAPI endpoints for incident management, alert-to-incident inspection, attack graph payload querying, and timeline streaming).
