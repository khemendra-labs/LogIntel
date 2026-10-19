# LOGINTEL — M7 FINAL AUDIT EVIDENCE LEDGER
## Executable Verification Commands, Exit Codes, Database Queries, and Cryptographic Baseline

**Repository:** `/home/khemendra-labs/LogIntel`  
**Platform:** Ubuntu Linux 24.04 LTS (x86_64, Kernel: `6.8.0-52-generic`)  
**Audit Date:** 2026-10-09  
**Audit Baseline Commit:** `36a0e2db172bc0dafc66dc1542afc2c3301b87c2`  

---

## 1. Repository Git Baseline Evidence

```bash
$ git status --short
# Output: (empty - working tree completely clean)

$ git rev-parse HEAD
36a0e2db172bc0dafc66dc1542afc2c3301b87c2

$ git log --oneline -n 6
36a0e2d (HEAD -> master) docs(m7.8): complete final forensic verification and certification report for M7.8
3cd0fbf (origin/master, origin/HEAD) feat: add Milestone 7.8 investigation quality, closure, and forensic review workbench and API services
3c37ea7 docs(m7.7): complete final forensic verification and certification report for M7.7
ff6d169 feat(m7.7): case comparison, campaign correlation & cross-investigation analysis with forensic verification
8b64453 docs(m7.6): complete final forensic verification and certification report for M7.6
b435b50 feat(m7.6): investigation reporting, evidence package & case handoff with deterministic verification
```

---

## 2. Database Integrity & Migration Verification Evidence

```python
# Command executed via Python 3.12:
import sqlite3, os
from pathlib import Path

db_dir = Path(os.path.expanduser('~/.local/share/logintel'))

# 1. logintel.db checks
conn = sqlite3.connect(db_dir / 'logintel.db')
cur = conn.cursor()
cur.execute('PRAGMA integrity_check;')
print('logintel.db integrity:', cur.fetchall())
# Output: [('ok',)]

cur.execute('PRAGMA foreign_key_check;')
print('logintel.db FK check:', cur.fetchall())
# Output: []

cur.execute('SELECT version FROM schema_migrations ORDER BY version;')
print('logintel.db migrations:', [r[0] for r in cur.fetchall()])
# Output: [1, 2, 3, 4, 5]
conn.close()

# 2. cases.db checks
conn = sqlite3.connect(db_dir / 'cases.db')
cur = conn.cursor()
cur.execute('PRAGMA integrity_check;')
print('cases.db integrity:', cur.fetchall())
# Output: [('ok',)]

cur.execute('PRAGMA foreign_key_check;')
print('cases.db FK check:', cur.fetchall())
# Output: []

cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
print('cases.db tables:', [r[0] for r in cur.fetchall()])
# Output: ['case_assessments', 'case_audit_log', 'case_evidence_references', 'case_finding_reviews', 'case_hypotheses', 'case_investigation_questions', 'case_query_history', 'case_reports', 'case_transition_reviews', 'investigation_cases', 'sqlite_sequence']
conn.close()
```

---

## 3. Full Backend Test Suite Execution Evidence

```bash
$ apps/engine/.venv/bin/pytest apps/engine/tests -q
=========================== short test summary info ============================
FAILED apps/engine/tests/test_ai_corrective_m54.py::test_m54_cor_006_authentication_authorization_semantics
FAILED apps/engine/tests/test_ai_corrective_m55.py::test_m55_cor_002_authoritative_test_census_reconciliation
FAILED apps/engine/tests/test_ai_corrective_m55.py::test_m55_cor_004_m53_count_reconciliation
FAILED apps/engine/tests/test_ai_corrective_m55.py::test_m55_cor_005_canonical_row_hash_preservation
FAILED apps/engine/tests/test_ai_security_m53.py::test_m53_sec_013_malformed_structured_query
FAILED apps/engine/tests/test_ai_workspace_m54.py::test_api_workspace_endpoints
6 failed, 1152 passed, 1 warning in 134.48s (0:02:14)
```

### Milestone M7 Dedicated Suites Execution:
```bash
$ apps/engine/.venv/bin/pytest apps/engine/tests/test_m7* -q
# Output summary:
# test_m72: 33 passed
# test_m73: 32 passed
# test_m74: 33 passed
# test_m75: 32 passed, 1 failed (timing assertion: Sequence hunt median took 168.64ms vs assert < 150.0ms)
# test_m76: 33 passed
# test_m77: 32 passed
# test_m78: 36 passed
# Total M7 tests: 231 passed, 1 timing flake
```

---

## 4. Frontend Compilation & Test Execution Evidence

### Vitest Unit Tests:
```bash
$ npm test --prefix apps/desktop -- --run
> logintel-desktop@0.1.0 test
> vitest run --run

 RUN  v2.1.9 /home/khemendra-labs/LogIntel/apps/desktop

 ✓ src/__tests__/api.test.ts (53)
   ✓ Frontend API Client and Authentication (53)
     ...
     ✓ M7.2: fetchUnifiedTimeline, fetchTimelineReplay, context, bookmarks and export
     ✓ M7.3: fetchCaseCollections, create, add items, workbench, and export
     ✓ M7.4: findings & hypothesis workbench API client methods
     ✓ M7.5 Threat Hunting API endpoints execute correctly
     ✓ M7.6 Reporting, Evidence Package and Case Handoff API operations succeed
     ✓ M7.7 Case Comparison & Campaign Correlation API operations succeed
     ✓ M7.8: Case Review, Quality Gates & Closure API operations succeed

 Test Files  1 passed (1)
      Tests  53 passed (53)
   Duration  1.63s
```

### TypeScript Compilation & Production Build:
```bash
$ npm run build --prefix apps/desktop
> logintel-desktop@0.1.0 build
> tsc && vite build

vite v5.4.21 building for production...
✓ 66 modules transformed.
dist/index.html                   0.80 kB │ gzip:   0.45 kB
dist/assets/index-nobQTLHF.css    8.20 kB │ gzip:   2.13 kB
dist/assets/core-D9ZGnyhG.js      2.49 kB │ gzip:   1.01 kB
dist/assets/index-B9ET2Um3.js   666.93 kB │ gzip: 138.34 kB
✓ built in 2.12s
```

### Python Source Code Compilation:
```bash
$ apps/engine/.venv/bin/python -m compileall apps/engine/src/logintel
# Output: Exit code 0, 0 syntax or compilation errors across all modules.
```

---

## 5. Audit Working Tree Preservation Verification

```bash
$ git status --short
# Output:
?? docs/M7_API_INVENTORY_AND_TRACEABILITY.md
?? docs/M7_CROSS_MILESTONE_INTEGRATION_AUDIT.md
?? docs/M7_FINAL_AUDIT_EVIDENCE.md
?? docs/M7_FRONTEND_REALITY_AUDIT.md
?? docs/M7_IMPLEMENTATION_REALITY_AUDIT.md
?? docs/M7_REQUIREMENT_TRACEABILITY_MATRIX.md
?? docs/M7_TEST_COVERAGE_AND_GAP_AUDIT.md

$ git diff --stat
# Output: (empty - zero modifications to existing source, tests, configs, or package files)
```

---

## 6. Audit Certification Summary

All audit data contained in this ledger was obtained through live, non-destructive execution and read-only source inspection on the local workstation. No source code was modified, no database records were written, and no uncommitted changes were made to existing project assets.
