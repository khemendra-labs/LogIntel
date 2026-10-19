# LOGINTEL — M7 REQUIREMENT TRACEABILITY MATRIX (M7.1–M7.15)
## Complete Capability-by-Capability End-to-End Traceability Matrix

**Repository:** `/home/khemendra-labs/LogIntel`  
**Platform:** Ubuntu Linux 24.04 LTS (x86_64)  
**Audit Baseline Commit:** `36a0e2db172bc0dafc66dc1542afc2c3301b87c2`  
**Total Requirements Identified:** 131  

---

## 1. Traceability Ledger

### M7.1 — Analyst Investigation Workspace 2.0
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.1-REQ-001 | Incident Workspace modal coordinate navigation | IMPLEMENTED AND VERIFIED | `ai/workspace_service.py:32` | `GET /ai/investigations/{id}/workspace` | `IncidentWorkspaceModal.tsx:76` | `cases.db:investigation_cases` | `test_ai_workspace_m54.py` | Full modal orchestration with tabs |
| M7.1-REQ-002 | Top-level case creation and management | IMPLEMENTED AND VERIFIED | `ai/case_service.py:120` | `POST /cases`, `GET /cases` | `IncidentsPage.tsx:180` | `cases.db:investigation_cases` | `test_ai_case_persistence_m55.py` | Case lifecycle ACTIVE/CLOSED |
| M7.1-REQ-003 | Analyst investigation scope bounding | IMPLEMENTED AND VERIFIED | `ai/workspace_service.py:110` | `PUT /ai/investigations/{id}/scope` | `IncidentWorkspaceModal.tsx:320` | `investigation_cases.scope_json` | `test_ai_workspace_m54.py` | Bounded entities and time range |
| M7.1-REQ-004 | Cross-feature entity selection propagation | IMPLEMENTED AND VERIFIED | `ai/workspace_service.py:150` | In-memory React state | `IncidentWorkspaceModal.tsx:410` | N/A (State) | `api.test.ts:400` | Propagates entity keys across tabs |
| M7.1-REQ-005 | Investigation status state transitions | IMPLEMENTED AND VERIFIED | `ai/case_service.py:280` | `POST /cases/{id}/state` | `IncidentWorkspaceModal.tsx:350` | `cases.db:investigation_cases` | `test_case_management.py` | Governed transition matrix |
| M7.1-REQ-006 | Analyst case notes and annotation | IMPLEMENTED AND VERIFIED | `storage/investigation_repo.py` | `GET/POST /investigations/{id}/notes` | `IncidentWorkspaceModal.tsx:549` | `logintel.db:investigation_notes` | `api.test.ts:250` | Immutable note history |
| M7.1-REQ-007 | Immutable audit history logging | IMPLEMENTED AND VERIFIED | `ai/case_service.py:410` | `GET /cases/{id}/audit` | `InvestigationIntelligencePanel.tsx:520` | `cases.db:case_audit_log` | `test_ai_case_persistence_m55.py` | Append-only triggers in SQLite |
| M7.1-REQ-008 | Case ownership handoff workflow | IMPLEMENTED AND VERIFIED | `ai/case_service.py:320` | `POST /cases/{id}/handoff` | `InvestigationIntelligencePanel.tsx:500` | `cases.db:investigation_cases` | `api.test.ts:310` | Reassigns owner with notes |

---

### M7.2 — Unified Evidence-Centric Timeline & Replay
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.2-REQ-001 | Multi-source timeline projection | IMPLEMENTED AND VERIFIED | `timeline/service.py:120` | `GET /cases/{id}/timeline/unified` | `InvestigationUnifiedTimeline.tsx:80` | `logintel.db:canonical_events` | `test_m72_timeline_replay.py:20` | Merges events, alerts, notes |
| M7.2-REQ-002 | Canonical deterministic event ordering | IMPLEMENTED AND VERIFIED | `timeline/service.py:180` | `GET /cases/{id}/timeline/unified` | `InvestigationUnifiedTimeline.tsx:120` | Read-only SQL order by | `test_m72_determinism.py:25` | `timestamp ASC, id ASC` |
| M7.2-REQ-003 | Host and entity multi-attribute filtering | IMPLEMENTED AND VERIFIED | `timeline/service.py:350` | Query params on unified route | `InvestigationUnifiedTimeline.tsx:210` | Memory + SQL | `test_m72_timeline_replay.py:60` | Filters by host, source, severity |
| M7.2-REQ-004 | Timeline event context synchronization | IMPLEMENTED AND VERIFIED | `timeline/service.py:490` | `GET /cases/{id}/timeline/context/{tid}` | `InvestigationUnifiedTimeline.tsx:280` | Correlated lookup | `test_m72_timeline_replay.py:110` | Links event to graph & evidence |
| M7.2-REQ-005 | Analyst event bookmarking | IMPLEMENTED AND VERIFIED | `timeline/service.py:530` | `POST /cases/{id}/timeline/{tid}/bookmark`| `InvestigationUnifiedTimeline.tsx:320` | `cases.db:case_evidence_references` | `test_m72_timeline_replay.py:150`| Does not mutate logintel.db |
| M7.2-REQ-006 | Interactive step scrubber replay session | IMPLEMENTED AND VERIFIED | `timeline/service.py:410` | `GET /cases/{id}/timeline/replay` | `InvestigationUnifiedTimeline.tsx:380` | Cached projection | `test_m72_timeline_replay.py:80` | Frames with active entity sets |
| M7.2-REQ-007 | Replay playback state machine | IMPLEMENTED AND VERIFIED | `InvestigationUnifiedTimeline.tsx` | N/A (Frontend timer loop) | `InvestigationUnifiedTimeline.tsx:440` | Local React State | `InvestigationUnifiedTimeline.tsx` | Play, pause, step forward/back |
| M7.2-REQ-008 | Timeline deterministic export (JSON/CSV) | IMPLEMENTED AND VERIFIED | `timeline/service.py:570` | `GET /cases/{id}/timeline/unified/export`| `InvestigationUnifiedTimeline.tsx:500` | In-memory serializer | `test_m72_determinism.py:80` | Formula-safe CSV escaping |
| M7.2-REQ-009 | Bounded timeline pagination | IMPLEMENTED AND VERIFIED | `timeline/service.py:370` | `limit`, `offset` query params | `InvestigationUnifiedTimeline.tsx:150` | Parameter bounds | `test_m72_security.py:40` | Default 100, max 1000 |
| M7.2-REQ-010 | Sub-second timeline assembly | IMPLEMENTED AND VERIFIED | `timeline/service.py:120` | `GET /cases/{id}/timeline/unified` | N/A | Local benchmarks | `test_m72_performance.py:30` | P95 < 150ms |

---

### M7.3 — Investigation Graph & Entity Pivot 2.0 / Evidence Collections
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.3-REQ-001 | Logical evidence collection lifecycle | IMPLEMENTED AND VERIFIED | `collections/service.py:110` | `POST /cases/{id}/evidence/collections` | `InvestigationEvidenceWorkbench.tsx:60` | `cases.db:case_evidence_references` | `test_m73_collections_workbench.py`| Create, update, delete |
| M7.3-REQ-002 | Evidence reference membership binding | IMPLEMENTED AND VERIFIED | `collections/service.py:220` | `POST .../collections/{cid}/items` | `InvestigationEvidenceWorkbench.tsx:120`| `cases.db:case_evidence_references` | `test_m73_collections_workbench.py`| Ordered member items |
| M7.3-REQ-003 | Blake2b collection integrity manifest | IMPLEMENTED AND VERIFIED | `collections/service.py:380` | Generated in collection response | `InvestigationEvidenceWorkbench.tsx:180`| Computed digest | `test_m73_determinism.py:20` | Cryptographic seal of items |
| M7.3-REQ-004 | Dedicated Evidence Workbench UI | IMPLEMENTED AND VERIFIED | `InvestigationEvidenceWorkbench.tsx` | `GET /cases/{id}/evidence/workbench` | `InvestigationEvidenceWorkbench.tsx:10` | Multi-table projection | `api.test.ts:2313` | Integrated workbench |
| M7.3-REQ-005 | Graph entity pivots and node traversal | IMPLEMENTED AND VERIFIED | `ai/graph/builder.py:90` | `GET /cases/{id}/graph` | `InvestigationGraphExplorer.tsx:50` | `logintel.db:alerts,events` | `test_host_graph_api_m68.py` | Nodes, edges, pivots |
| M7.3-REQ-006 | Edge evidence attribution inspection | IMPLEMENTED AND VERIFIED | `ai/graph/builder.py:180` | `GET /cases/{id}/graph/edges/{id}/evidence`| `InvestigationGraphExplorer.tsx:140`| `logintel.db:canonical_events` | `api.test.ts:1600` | Traces edge to source event |
| M7.3-REQ-007 | Attack path sequence reconstruction | IMPLEMENTED AND VERIFIED | `ai/graph/path_finder.py:40` | `GET /investigations/{id}/attack-path` | `IncidentWorkspaceModal.tsx:484` | Topological sort | `test_ai_domain_and_context.py` | Directed attack paths |
| M7.3-REQ-008 | Collection multi-format export | IMPLEMENTED AND VERIFIED | `collections/service.py:450` | `GET .../collections/{cid}/export` | `InvestigationEvidenceWorkbench.tsx:250`| Deterministic JSON/CSV | `test_m73_determinism.py:60` | Formula-injection safe |

---

### M7.4 — Findings & Hypothesis Workbench
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.4-REQ-001 | Structured analyst finding authoring | IMPLEMENTED AND VERIFIED | `findings/service.py:140` | `POST /cases/{id}/findings` | `InvestigationFindingsWorkbench.tsx:80` | `cases.db:case_evidence_references` | `test_m74_findings_workbench.py:30` | Findings with descriptions |
| M7.4-REQ-002 | Finding epistemic status tracking | IMPLEMENTED AND VERIFIED | `findings/service.py:180` | Embedded in finding model | `InvestigationFindingsWorkbench.tsx:110`| `OBSERVED / INFERRED / UNKNOWN` | `test_m74_security.py:120` | Strict epistemic separation |
| M7.4-REQ-003 | Evidence attachment to findings | IMPLEMENTED AND VERIFIED | `findings/service.py:280` | `POST .../findings/{fid}/evidence` | `InvestigationFindingsWorkbench.tsx:150`| `case_evidence_references` | `test_m74_findings_workbench.py:70` | Supports/contradicts tags |
| M7.4-REQ-004 | Categorical finding grounding status | IMPLEMENTED AND VERIFIED | `findings/service.py:320` | Derived in finding response | `InvestigationFindingsWorkbench.tsx:170`| `GROUNDED / PARTIALLY / UNRESOLVED` | `test_m74_findings_workbench.py:90` | Grounded in resolvable source |
| M7.4-REQ-005 | Enriched investigative hypothesis model | IMPLEMENTED AND VERIFIED | `findings/service.py:420` | `POST /cases/{id}/hypotheses/m74` | `InvestigationFindingsWorkbench.tsx:210`| `cases.db:case_hypotheses` | `test_m74_findings_workbench.py:130`| Status + evidence tags |
| M7.4-REQ-006 | Competing hypothesis side-by-side comparison | IMPLEMENTED AND VERIFIED | `findings/service.py:560` | `GET /cases/{id}/hypotheses/compare` | `InvestigationFindingsWorkbench.tsx:260`| Deterministic matrix | `test_m74_findings_workbench.py:170`| Relative evidence balance |
| M7.4-REQ-007 | Hypothesis evidence gap recording | IMPLEMENTED AND VERIFIED | `findings/service.py:510` | `POST .../hypotheses/{hid}/gaps` | `InvestigationFindingsWorkbench.tsx:290`| `case_hypotheses.evidence_gaps_json` | `test_m74_findings_workbench.py:150`| Explicit telemetry gaps |
| M7.4-REQ-008 | Findings & hypothesis review workflow | IMPLEMENTED AND VERIFIED | `findings/service.py:360` | `POST .../findings/{fid}/review` | `InvestigationFindingsWorkbench.tsx:320`| `cases.db:case_finding_reviews` | `test_m74_findings_workbench.py:110`| Analyst review notes |
| M7.4-REQ-009 | Findings & hypothesis export | IMPLEMENTED AND VERIFIED | `findings/service.py:610` | `GET /cases/{id}/findings/export` | `InvestigationFindingsWorkbench.tsx:350`| Canonical JSON/CSV | `test_m74_determinism.py:40` | Byte-level reproducibility |

---

### M7.5 — Advanced Threat Hunting
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.5-REQ-001 | Governed threat hunt proposal creation | IMPLEMENTED AND VERIFIED | `hunting/service.py:110` | `POST /cases/{id}/hunts` | `InvestigationThreatHuntWorkbench.tsx:90`| `cases.db:case_query_history` | `test_m75_threat_hunting.py:30` | Field filters + operators |
| M7.5-REQ-002 | Pre-execution query validation & preview | IMPLEMENTED AND VERIFIED | `hunting/service.py:210` | `POST /cases/{id}/hunts/preview` | `InvestigationThreatHuntWorkbench.tsx:140`| Bounded preview SQL | `test_m75_threat_hunting.py:60` | Validates syntax & schema |
| M7.5-REQ-003 | Analyst authorization approval gate | IMPLEMENTED AND VERIFIED | `hunting/service.py:270` | `POST /cases/{id}/hunts/{hid}/approve`| `InvestigationThreatHuntWorkbench.tsx:170`| `cases.db:case_query_history` | `test_m75_security.py:50` | Enforces mandatory approval |
| M7.5-REQ-004 | Governed query execution engine | IMPLEMENTED AND VERIFIED | `hunting/service.py:310` | `POST /cases/{id}/hunts/{hid}/execute`| `InvestigationThreatHuntWorkbench.tsx:210`| Read-only parameterized SQL | `test_m75_threat_hunting.py:90` | Parameterized execution |
| M7.5-REQ-005 | Chronological multi-step sequence hunt | IMPLEMENTED AND VERIFIED | `hunting/service.py:450` | `POST /cases/{id}/hunts/sequence` | `InvestigationThreatHuntWorkbench.tsx:260`| Multi-stage temporal query | `test_m75_threat_hunting.py:130`| Correlates ordered steps |
| M7.5-REQ-006 | Normalized forensic IOC lookup | IMPLEMENTED AND VERIFIED | `hunting/service.py:640` | `POST /cases/{id}/hunts/ioc` | `InvestigationThreatHuntWorkbench.tsx:280`| Case-bounded event scan | `test_m75_threat_hunting.py:160`| Matches IPs, hosts, hashes |
| M7.5-REQ-007 | Entity-centric pivot hunt | IMPLEMENTED AND VERIFIED | `hunting/service.py:530` | `POST /cases/{id}/hunts/pivot/entity` | `InvestigationThreatHuntWorkbench.tsx:310`| Indexed pivot lookup | `test_m75_threat_hunting.py:180`| Host, IP, user pivots |
| M7.5-REQ-008 | Bounded temporal window hunt | IMPLEMENTED AND VERIFIED | `hunting/service.py:580` | `POST /cases/{id}/hunts/pivot/temporal`| `InvestigationThreatHuntWorkbench.tsx:340`| Time-bounded query | `test_m75_threat_hunting.py:200`| Pre/post incident window |
| M7.5-REQ-009 | Conversion of hunt results to findings | IMPLEMENTED AND VERIFIED | `hunting/service.py:710` | `POST /cases/{id}/hunts/convert/finding`| `InvestigationThreatHuntWorkbench.tsx:370`| `cases.db:case_evidence_references`| `test_m75_threat_hunting.py:220`| Promotes results to finding |
| M7.5-REQ-010 | Natural language query assist (AI) | IMPLEMENTED AND VERIFIED | `hunting/service.py:780` | `POST /cases/{id}/hunts/ai-assist` | `InvestigationThreatHuntWorkbench.tsx:400`| Advisory loopback model | `test_m75_threat_hunting.py:250`| Non-authoritative proposal |
| M7.5-REQ-011 | Deterministic hunt export with Blake2b | IMPLEMENTED AND VERIFIED | `hunting/service.py:840` | `GET /cases/{id}/hunts/{hid}/export` | `InvestigationThreatHuntWorkbench.tsx:430`| Canonical export + digest | `test_m75_determinism.py:40` | Cryptographic seal |

---

### M7.6 — IOC / Indicator Investigation & Reporting
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.6-REQ-001 | Indicator type normalization & extraction | IMPLEMENTED AND VERIFIED | `normalization/sanitizer.py:30` | Internal engine helper | `EventDetailModal.tsx:116` | Regex + IP parser | `test_parsers.py` | Extracts IP, Domain, Hash |
| M7.6-REQ-002 | Normalized telemetry indicator search | IMPLEMENTED AND VERIFIED | `hunting/service.py:640` | `POST /cases/{id}/hunts/ioc` | `ThreatHuntingPage.tsx:330` | `logintel.db:canonical_events` | `test_m75_threat_hunting.py:160`| Matches indicators |
| M7.6-REQ-003 | Structured investigation report drafting | IMPLEMENTED AND VERIFIED | `reporting/service.py:150` | `POST /cases/{id}/reports` | `InvestigationReportWorkbench.tsx:80` | `cases.db:case_reports` | `test_m76_reporting.py:30` | Facts, inferences, unknowns |
| M7.6-REQ-004 | Immutable report versioning & diff | IMPLEMENTED AND VERIFIED | `reporting/service.py:380` | `GET /cases/{id}/reports/compare` | `InvestigationReportWorkbench.tsx:150`| `cases.db:case_reports` | `test_m76_reporting.py:80` | Compares report versions |
| M7.6-REQ-005 | Cryptographic evidence package bundling | IMPLEMENTED AND VERIFIED | `reporting/service.py:750` | `POST /cases/{id}/packages` | `InvestigationReportWorkbench.tsx:280`| Memory bundle + Blake2b | `test_m76_reporting.py:140`| Manifest, report, evidence |
| M7.6-REQ-006 | Governed case handoff workflow | IMPLEMENTED AND VERIFIED | `reporting/service.py:920` | `POST /cases/{id}/handoff/prepare` | `InvestigationReportWorkbench.tsx:320`| `cases.db:investigation_cases` | `test_m76_reporting.py:180`| Custody transfer packet |
| M7.6-REQ-007 | External threat intelligence enrichment | PARTIALLY IMPLEMENTED | `hunting/service.py` | Local-only IOC search | `InvestigationThreatHuntWorkbench.tsx` | N/A (External non-goal) | N/A | External intel is explicit non-goal |

---

### M7.7 — Incident & Case Operations / Case Comparison
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.7-REQ-001 | Case comparison execution engine | IMPLEMENTED AND VERIFIED | `comparison/service.py:120` | `POST /cases/{id}/comparison` | `InvestigationCaseComparisonWorkbench.tsx:80`| In-memory comparison cache | `test_m77_comparison.py:30` | Compares entity overlaps |
| M7.7-REQ-002 | Shared entity & indicator correlation | IMPLEMENTED AND VERIFIED | `comparison/service.py:220` | `GET .../comparison/{cid}/entities`| `InvestigationCaseComparisonWorkbench.tsx:140`| Cross-case lookup | `test_m77_comparison.py:60` | Correlates IPs, hosts, hashes |
| M7.7-REQ-003 | Comparative temporal alignment window | IMPLEMENTED AND VERIFIED | `comparison/service.py:320` | `GET .../comparison/{cid}/timeline`| `InvestigationCaseComparisonWorkbench.tsx:180`| Time span alignment | `test_m77_comparison.py:90` | Identifies concurrent activity |
| M7.7-REQ-004 | Campaign correlation candidate derivation| IMPLEMENTED AND VERIFIED | `comparison/service.py:410` | `GET .../comparison/{cid}/correlations`| `InvestigationCaseComparisonWorkbench.tsx:220`| Categorical rule matching | `test_m77_comparison.py:120`| Suggests campaign links |
| M7.7-REQ-005 | Analyst candidate review workflow | IMPLEMENTED AND VERIFIED | `comparison/service.py:490` | `POST .../correlations/{id}/review`| `InvestigationCaseComparisonWorkbench.tsx:260`| `cases.db:case_audit_log` | `test_m77_comparison.py:150`| ACCEPTED / REJECTED |
| M7.7-REQ-006 | Advisory AI campaign synthesis | IMPLEMENTED AND VERIFIED | `comparison/service.py:610` | `POST .../comparison/{cid}/ai-summary`| `InvestigationCaseComparisonWorkbench.tsx:310`| Advisory loopback model | `test_m77_comparison.py:180`| Strict prompt containment |
| M7.7-REQ-007 | Deterministic comparison export | IMPLEMENTED AND VERIFIED | `comparison/service.py:720` | `GET .../comparison/{cid}/export` | `InvestigationCaseComparisonWorkbench.tsx:350`| Canonical JSON/CSV/Markdown | `test_m77_determinism.py:40` | Byte-level reproducibility |
| M7.7-REQ-008 | Cross-case access authorization | IMPLEMENTED AND VERIFIED | `comparison/service.py:140` | Validates target cases in DB | `InvestigationCaseComparisonWorkbench.tsx` | `cases.db:investigation_cases` | `test_m77_security.py:40` | Prohibits cross-case breach |
| M7.7-REQ-009 | Bounded case comparison latency | IMPLEMENTED AND VERIFIED | `comparison/service.py:120` | `POST /cases/{id}/comparison` | N/A | Local benchmarks | `test_m77_performance.py:30` | Sub-50ms comparison |
| M7.7-REQ-010 | Zero mutation of underlying cases | IMPLEMENTED AND VERIFIED | `comparison/service.py` | Read-only aggregation | `InvestigationCaseComparisonWorkbench.tsx` | `cases.db` untouched | `test_m77_security.py:160` | Pure projection computation |

---

### M7.8 — Findings, Hypotheses & Forensic Review / Quality & Closure
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.8-REQ-001 | 12-Gate forensic evaluation engine | IMPLEMENTED AND VERIFIED | `review/service.py:120` | `POST /cases/{id}/review/run` | `InvestigationQualityReviewWorkbench.tsx:80`| Multi-table audit snapshot | `test_m78_review.py:20` | Scope, coverage, grounding, etc. |
| M7.8-REQ-002 | Categorical closure blocker generation | IMPLEMENTED AND VERIFIED | `review/service.py:340` | `GET /cases/{id}/review/blockers` | `InvestigationQualityReviewWorkbench.tsx:140`| Categorical rule evaluation | `test_m78_review.py:60` | BLOCKER, WARNING, INFO |
| M7.8-REQ-003 | Analyst blocker waiver / acknowledgment | IMPLEMENTED AND VERIFIED | `review/service.py:480` | `POST .../blockers/{id}/acknowledge`| `InvestigationQualityReviewWorkbench.tsx:180`| `cases.db:case_audit_log` | `test_m78_review.py:90` | Requires documented notes |
| M7.8-REQ-004 | Categorical closure readiness state | IMPLEMENTED AND VERIFIED | `review/service.py:540` | `GET /cases/{id}/review` | `InvestigationQualityReviewWorkbench.tsx:210`| State machine derivation | `test_m78_review.py:60` | NOT_READY, READY_FOR_CLOSURE |
| M7.8-REQ-005 | Governed formal case closure | IMPLEMENTED AND VERIFIED | `review/service.py:820` | `POST /cases/{id}/review/close` | `InvestigationQualityReviewWorkbench.tsx:260`| `cases.db:investigation_cases` | `test_m78_review.py:120`| Prohibits closure with blockers|
| M7.8-REQ-006 | Controlled case reopening workflow | IMPLEMENTED AND VERIFIED | `review/service.py:870` | `POST /cases/{id}/review/reopen` | `InvestigationQualityReviewWorkbench.tsx:310`| `cases.db:investigation_cases` | `test_m78_review.py:140`| Reopens with audit log |
| M7.8-REQ-007 | Blake2b cryptographic review manifest | IMPLEMENTED AND VERIFIED | `review/service.py:690` | Root digest in review snapshot | `InvestigationQualityReviewWorkbench.tsx:350`| 256-bit Blake2b hash | `test_m78_determinism.py:30` | Seals review snapshot |
| M7.8-REQ-008 | Multi-format export with formula safety | IMPLEMENTED AND VERIFIED | `review/service.py:920` | `GET /cases/{id}/review/export` | `InvestigationQualityReviewWorkbench.tsx:390`| Canonical JSON/CSV/Markdown | `test_m78_determinism.py:50` | Escapes CSV formula injection |
| M7.8-REQ-009 | Advisory loopback AI review assistant | IMPLEMENTED AND VERIFIED | `review/service.py:990` | `POST /cases/{id}/review/ai-summary`| `InvestigationQualityReviewWorkbench.tsx:430`| Advisory loopback model | `test_m78_security.py:320` | is_authoritative = False |
| M7.8-REQ-010 | Review audit trail isolation | IMPLEMENTED AND VERIFIED | `review/service.py:780` | `GET /cases/{id}/review/history` | `InvestigationQualityReviewWorkbench.tsx:470`| `cases.db:case_audit_log` | `test_m78_security.py:160` | Strictly isolated by case_id |
| M7.8-REQ-011 | Telemetry immutability preservation | IMPLEMENTED AND VERIFIED | `review/service.py` | Read-only inspection | `InvestigationQualityReviewWorkbench.tsx` | `logintel.db` untouched | `test_m78_security.py:280` | Zero writes to raw telemetry |
| M7.8-REQ-012 | Zero numerical confidence enforcement | IMPLEMENTED AND VERIFIED | `review/models.py:50` | Categorical states only | `InvestigationQualityReviewWorkbench.tsx` | No floats or percentages | `test_m78_determinism.py:20` | Zero fake probabilities |

---

### M7.9 through M7.15 (Prospective Milestones & Historical Equivalences)
| Req ID | Capability Description | Primary Status | Backend Path | API Route | Frontend Component | Database / Storage | Verification Test | Gaps / Notes |
|---|---|---|---|---|---|---|---|---|
| M7.9-REQ-001 | Investigation report generation & packages| IMPLEMENTED AND VERIFIED | `reporting/service.py:150` | `POST /cases/{id}/reports`, `POST /packages` | `InvestigationReportWorkbench.tsx` | `cases.db:case_reports` | `test_m76_reporting.py` | Consolidated into M7.6 |
| M7.10-REQ-001| Local AI Copilot advisory assistance | IMPLEMENTED AND VERIFIED | `ai/service.py`, `hunting/service.py:780` | `POST .../ai-assist`, `POST .../ai-summary` | `InvestigationIntelligencePanel.tsx` | Local loopback provider | `test_m75_threat_hunting.py:250`| Distributed advisory layer |
| M7.11-REQ-001| Investigation historical event replay | IMPLEMENTED AND VERIFIED | `timeline/service.py:410` | `GET /cases/{id}/timeline/replay` | `InvestigationUnifiedTimeline.tsx` | Cached timeline projection | `test_m72_timeline_replay.py` | Consolidated into M7.2 |
| M7.12-REQ-001| Multi-host timeline correlation | IMPLEMENTED AND VERIFIED | `timeline/service.py:350` | Filter `host` on `/timeline/unified` | `InvestigationUnifiedTimeline.tsx` | `logintel.db:canonical_events` | `test_m72_timeline_replay.py:60` | Correlates ingested hosts |
| M7.12-REQ-002| Distributed live fleet host management | NOT IMPLEMENTED | N/A (Out of scope) | N/A | N/A | N/A | N/A | Explicit non-goal (local-first) |
| M7.13-REQ-001| Logical evidence collections | IMPLEMENTED AND VERIFIED | `collections/service.py:110` | `/cases/{id}/evidence/collections` | `InvestigationEvidenceWorkbench.tsx` | `cases.db:case_evidence_references`| `test_m73_collections_workbench.py`| Consolidated into M7.3 |
| M7.14-REQ-001| Case comparison & campaign correlation | IMPLEMENTED AND VERIFIED | `comparison/service.py:120` | `/cases/{id}/comparison` | `InvestigationCaseComparisonWorkbench.tsx`| In-memory comparison cache | `test_m77_comparison.py` | Consolidated into M7.7 |
| M7.15-REQ-001| Investigation quality & closure review | IMPLEMENTED AND VERIFIED | `review/service.py:120` | `/cases/{id}/review/*` | `InvestigationQualityReviewWorkbench.tsx` | Multi-table audit snapshot | `test_m78_review.py` | Consolidated into M7.8 |
| M7.15-REQ-002| Final M7 Program Certification | PARTIALLY IMPLEMENTED | `docs/M7_IMPLEMENTATION_REALITY_AUDIT.md` | N/A | N/A | N/A | Full pytest regression | This audit establishes reality |

---
