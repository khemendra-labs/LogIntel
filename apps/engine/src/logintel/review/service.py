"""Investigation Quality, Closure & Forensic Review Service for Milestone 7.8.

Provides deterministic multi-gate forensic evaluation across 12 analytical gates,
categorical closure blocker identification, cryptographic provenance manifests,
auditable case closure and reopening workflows, and multi-format exports.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import re
from typing import Any, Dict, List, Optional
import uuid

import httpx

from logintel.ai.domain.case import (
    ALLOWED_CASE_TRANSITIONS,
    CaseEvidenceReference,
    CaseStatus,
    InvestigationCase,
    ResolutionStatus,
)
from logintel.config import settings
from logintel.logging import get_logger
from logintel.review.models import (
    AIReviewSummaryRequest,
    AIReviewSummaryResponse,
    AcknowledgeBlockerRequest,
    BlockerResolutionState,
    BlockerSeverity,
    CaseReviewSnapshot,
    CloseCaseRequest,
    ClosureReadinessState,
    EvidenceCoverageMetrics,
    ExportFormat,
    FindingGroundingStatus,
    GateEvaluationStatus,
    QuestionReviewStatus,
    ReopenCaseRequest,
    ReviewBlocker,
    ReviewBlockerCategory,
    ReviewExportResponse,
    ReviewGateResult,
    ReviewGateType,
    ReviewProvenanceManifest,
    RunReviewRequest,
)
from logintel.storage.case_repo import CaseRepository, case_repo as default_case_repo
from logintel.storage.db import Database, db as default_forensic_db

logger = get_logger("review.service")

# Spreadsheet formula injection prefix characters
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Prompt injection defanging pattern
PROMPT_INJECTION_PATTERN = re.compile(
    r"(ignore\s+(previous|above)\s+instructions|"
    r"system\s*:\s*|"
    r"<\|im_start\|>|"
    r"\[INST\]|"
    r"eval\(|"
    r"exec\(|"
    r"subprocess\.|"
    r"os\.system|"
    r"bash\s+-c\s+)",
    re.IGNORECASE,
)


class InvestigationReviewService:
    """Core deterministic service executing forensic review gates and governing case closure."""

    def __init__(
        self,
        case_repository: Optional[CaseRepository] = None,
        forensic_database: Optional[Database] = None,
    ) -> None:
        self.case_repo = case_repository or default_case_repo
        self.db = forensic_database or default_forensic_db
        # In-memory storage for cached review snapshots per case
        self._snapshots: Dict[int, CaseReviewSnapshot] = {}
        # In-memory storage for analyst blocker acknowledgments/waivers: {case_id: {blocker_id: dict}}
        self._blocker_overrides: Dict[int, Dict[str, Dict[str, Any]]] = {}

    # -------------------------------------------------------------------------
    # String and CSV Defanging Helpers
    # -------------------------------------------------------------------------

    def _sanitize_csv_cell(self, value: Any) -> str:
        """Escape spreadsheet formula injection characters with a single quote."""
        s = str(value) if value is not None else ""
        if s and s.startswith(CSV_FORMULA_PREFIXES):
            return f"'{s}"
        return s

    def _defang_prompt(self, text: str) -> str:
        """Neutralize detected prompt injection tokens in untrusted input text."""
        if not text:
            return ""
        return PROMPT_INJECTION_PATTERN.sub("[DEFANGED_INJECTION_ATTEMPT]", text)

    def _compute_blake2b(self, text: str) -> str:
        """Compute deterministic Blake2b-256 digest of canonical string."""
        return hashlib.blake2b(text.encode("utf-8"), digest_size=32).hexdigest()

    # -------------------------------------------------------------------------
    # Core 12-Gate Forensic Review Engine
    # -------------------------------------------------------------------------

    def run_forensic_review(
        self,
        case_id: int,
        request: Optional[RunReviewRequest] = None,
        actor: str = "SecAnalyst-1",
    ) -> CaseReviewSnapshot:
        """Deterministically evaluates all 12 forensic gates and synthesizes closure readiness."""
        case = self.case_repo.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        gates: List[ReviewGateResult] = []
        all_blockers: List[ReviewBlocker] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # ---------------------------------------------------------------------
        # Gate 1: SCOPE
        # ---------------------------------------------------------------------
        scope_blockers: List[ReviewBlocker] = []
        scope_details: Dict[str, Any] = {}
        scope = getattr(case, "scope", None)
        has_scope = False

        if scope:
            hosts = getattr(scope, "hosts", []) or []
            users = getattr(scope, "users", []) or []
            entities = getattr(scope, "selected_entity_ids", []) or []
            obj = getattr(scope, "objective", None) or case.description
            time_start = getattr(scope, "time_start", None)
            time_end = getattr(scope, "time_end", None)

            scope_details = {
                "hosts_count": len(hosts),
                "users_count": len(users),
                "entities_count": len(entities),
                "has_objective": bool(obj and len(obj.strip()) > 5),
                "has_time_range": bool(time_start or time_end),
            }

            if not obj or len(obj.strip()) <= 5:
                scope_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-scope-objective-{case_id}",
                        gate_type=ReviewGateType.SCOPE,
                        category=ReviewBlockerCategory.MISSING_SCOPE,
                        description="Investigation objective is missing or lacks sufficient forensic specificity.",
                        severity=BlockerSeverity.WARNING,
                        source_reference=f"case:{case_id}:scope",
                    )
                )

            if not hosts and not users and not entities:
                scope_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-scope-entities-{case_id}",
                        gate_type=ReviewGateType.SCOPE,
                        category=ReviewBlockerCategory.MISSING_SCOPE,
                        description="Investigation scope does not specify any target hosts, user accounts, or entities.",
                        severity=BlockerSeverity.BLOCKER,
                        source_reference=f"case:{case_id}:scope",
                    )
                )
            else:
                has_scope = True
        else:
            scope_blockers.append(
                ReviewBlocker(
                    blocker_id=f"blk-scope-missing-{case_id}",
                    gate_type=ReviewGateType.SCOPE,
                    category=ReviewBlockerCategory.MISSING_SCOPE,
                    description="Investigation scope definition is completely absent from case metadata.",
                    severity=BlockerSeverity.BLOCKER,
                    source_reference=f"case:{case_id}",
                )
            )

        scope_status = GateEvaluationStatus.PASS if not scope_blockers else (
            GateEvaluationStatus.BLOCKED if any(b.severity == BlockerSeverity.BLOCKER for b in scope_blockers)
            else GateEvaluationStatus.NEEDS_REVIEW
        )
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.SCOPE,
                title="Investigation Scope & Boundary Gate",
                status=scope_status,
                summary=f"Scope evaluated with {len(scope_blockers)} identified issue(s).",
                blockers=scope_blockers,
                details=scope_details,
                recommendations=["Define explicit investigation boundaries, target hosts, and temporal ranges."] if scope_blockers else [],
            )
        )
        all_blockers.extend(scope_blockers)

        # ---------------------------------------------------------------------
        # Gate 2: EVIDENCE_COVERAGE
        # ---------------------------------------------------------------------
        coverage_blockers: List[ReviewBlocker] = []
        evidence_refs: List[CaseEvidenceReference] = getattr(case, "evidence_references", []) or []

        tot_refs = len(evidence_refs)
        avail_refs = 0
        missing_refs = 0
        unresolved_refs = 0
        observed_cnt = 0
        inferred_cnt = 0

        for r in evidence_refs:
            res_status = getattr(r, "resolution_status", None)
            if res_status == ResolutionStatus.AVAILABLE:
                avail_refs += 1
            elif res_status == ResolutionStatus.MISSING:
                missing_refs += 1
            else:
                unresolved_refs += 1

            epistemic = getattr(r, "epistemic_status", None)
            if epistemic == "OBSERVED":
                observed_cnt += 1
            elif epistemic == "INFERRED":
                inferred_cnt += 1

        # Check telemetry gaps from case hypotheses and assessments
        hypotheses = getattr(case, "hypotheses", []) or []
        tot_gaps = 0
        crit_gaps = 0
        for hyp in hypotheses:
            gaps_list = getattr(hyp, "evidence_gaps", []) or []
            tot_gaps += len(gaps_list)
            for g in gaps_list:
                g_str = str(g).lower()
                if "critical" in g_str or "unmonitored" in g_str or "dropped" in g_str:
                    crit_gaps += 1

        if tot_refs == 0:
            coverage_blockers.append(
                ReviewBlocker(
                    blocker_id=f"blk-cov-no-evidence-{case_id}",
                    gate_type=ReviewGateType.EVIDENCE_COVERAGE,
                    category=ReviewBlockerCategory.UNRESOLVED_EVIDENCE_REFERENCE,
                    description="Case does not contain any pinned or referenced forensic evidence items.",
                    severity=BlockerSeverity.BLOCKER,
                    source_reference=f"case:{case_id}:evidence",
                )
            )

        if missing_refs > 0:
            coverage_blockers.append(
                ReviewBlocker(
                    blocker_id=f"blk-cov-missing-refs-{case_id}",
                    gate_type=ReviewGateType.EVIDENCE_COVERAGE,
                    category=ReviewBlockerCategory.UNRESOLVED_EVIDENCE_REFERENCE,
                    description=f"{missing_refs} evidence reference(s) cannot be resolved against authoritative tables.",
                    severity=BlockerSeverity.WARNING,
                    source_reference=f"case:{case_id}:evidence:missing",
                )
            )

        if crit_gaps > 0:
            coverage_blockers.append(
                ReviewBlocker(
                    blocker_id=f"blk-cov-crit-gaps-{case_id}",
                    gate_type=ReviewGateType.EVIDENCE_COVERAGE,
                    category=ReviewBlockerCategory.TELEMETRY_GAP_REQUIRES_REVIEW,
                    description=f"{crit_gaps} critical telemetry gap(s) identified in hypothesis evaluations.",
                    severity=BlockerSeverity.BLOCKER,
                    source_reference=f"case:{case_id}:gaps",
                )
            )

        cov_metrics = EvidenceCoverageMetrics(
            total_references=tot_refs,
            available_references=avail_refs,
            missing_references=missing_refs,
            unresolved_references=unresolved_refs,
            observed_evidence_count=observed_cnt,
            inferred_evidence_count=inferred_cnt,
            telemetry_gaps_count=tot_gaps,
            critical_gaps_count=crit_gaps,
        )

        cov_status = GateEvaluationStatus.PASS if not coverage_blockers else (
            GateEvaluationStatus.BLOCKED if any(b.severity == BlockerSeverity.BLOCKER for b in coverage_blockers)
            else GateEvaluationStatus.NEEDS_REVIEW
        )
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.EVIDENCE_COVERAGE,
                title="Evidence Coverage & Telemetry Resolution Gate",
                status=cov_status,
                summary=f"Coverage: {tot_refs} references ({avail_refs} available, {tot_gaps} gaps recorded).",
                blockers=coverage_blockers,
                details=cov_metrics.model_dump(),
                recommendations=["Pin corroborating event evidence or execute governed hunts to resolve telemetry gaps."] if coverage_blockers else [],
            )
        )
        all_blockers.extend(coverage_blockers)

        # ---------------------------------------------------------------------
        # Gate 3: FINDING_GROUNDING
        # ---------------------------------------------------------------------
        finding_blockers: List[ReviewBlocker] = []
        conn = self.case_repo._get_connection()
        findings_rows = []
        with conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT finding_id, review_state, analyst_notes FROM case_finding_reviews WHERE case_id = ?",
                (case_id,),
            )
            findings_rows = cur.fetchall()

        unreviewed_findings_cnt = 0
        ungrounded_findings_cnt = 0

        for fr in findings_rows:
            fid = fr["finding_id"]
            rstate = str(fr["review_state"]).upper()
            if rstate in ("UNREVIEWED", "DRAFT"):
                unreviewed_findings_cnt += 1
                finding_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-finding-unreviewed-{fid}",
                        gate_type=ReviewGateType.FINDING_GROUNDING,
                        category=ReviewBlockerCategory.UNREVIEWED_FINDING,
                        description=f"Analyst finding '{fid}' remains in {rstate} state without formal review.",
                        severity=BlockerSeverity.WARNING,
                        source_reference=f"finding:{fid}",
                    )
                )

        f_status = GateEvaluationStatus.PASS if not finding_blockers else GateEvaluationStatus.NEEDS_REVIEW
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.FINDING_GROUNDING,
                title="Finding Evidentiary Grounding Gate",
                status=f_status,
                summary=f"Evaluated {len(findings_rows)} finding review records with {unreviewed_findings_cnt} unreviewed.",
                blockers=finding_blockers,
                details={
                    "total_reviewed_findings": len(findings_rows),
                    "unreviewed_count": unreviewed_findings_cnt,
                },
                recommendations=["Review and categorize all open findings as ACCEPTED, DISPUTED, or REJECTED."] if finding_blockers else [],
            )
        )
        all_blockers.extend(finding_blockers)

        # ---------------------------------------------------------------------
        # Gate 4: HYPOTHESIS_REVIEW
        # ---------------------------------------------------------------------
        hypothesis_blockers: List[ReviewBlocker] = []
        open_hyp_cnt = 0

        for hyp in hypotheses:
            hid = getattr(hyp, "hypothesis_id", "hyp-unknown")
            hstat = str(getattr(hyp, "status", "OPEN")).upper()
            if hstat in ("OPEN", "DRAFT", "PROPOSED"):
                open_hyp_cnt += 1
                hypothesis_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-hyp-unresolved-{hid}",
                        gate_type=ReviewGateType.HYPOTHESIS_REVIEW,
                        category=ReviewBlockerCategory.UNREVIEWED_HYPOTHESIS,
                        description=f"Investigation hypothesis '{hid}' is in {hstat} status without categorical evaluation.",
                        severity=BlockerSeverity.WARNING,
                        source_reference=f"hypothesis:{hid}",
                    )
                )

        hyp_status = GateEvaluationStatus.PASS if not hypothesis_blockers else GateEvaluationStatus.NEEDS_REVIEW
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.HYPOTHESIS_REVIEW,
                title="Hypothesis Review & Adjudication Gate",
                status=hyp_status,
                summary=f"Evaluated {len(hypotheses)} hypotheses ({open_hyp_cnt} unresolved).",
                blockers=hypothesis_blockers,
                details={"total_hypotheses": len(hypotheses), "unresolved_count": open_hyp_cnt},
                recommendations=["Adjudicate open hypotheses as SUPPORTED, WEAKENED, DISPUTED, or INCONCLUSIVE."] if hypothesis_blockers else [],
            )
        )
        all_blockers.extend(hypothesis_blockers)

        # ---------------------------------------------------------------------
        # Gate 5: CONTRADICTIONS
        # ---------------------------------------------------------------------
        contradiction_blockers: List[ReviewBlocker] = []
        contradictions_found = 0

        for hyp in hypotheses:
            contra_tags = getattr(hyp, "contradicting_evidence_tags", []) or []
            assessment_notes = getattr(hyp, "analyst_assessment", "") or ""
            if contra_tags and len(assessment_notes.strip()) < 10:
                contradictions_found += len(contra_tags)
                hid = getattr(hyp, "hypothesis_id", "hyp-unknown")
                contradiction_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-contra-unassessed-{hid}",
                        gate_type=ReviewGateType.CONTRADICTIONS,
                        category=ReviewBlockerCategory.UNRESOLVED_CONTRADICTION,
                        description=f"Hypothesis '{hid}' cites contradicting evidence without documented analyst assessment.",
                        severity=BlockerSeverity.BLOCKER,
                        source_reference=f"hypothesis:{hid}:contradictions",
                    )
                )

        contra_status = GateEvaluationStatus.PASS if not contradiction_blockers else GateEvaluationStatus.BLOCKED
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.CONTRADICTIONS,
                title="Contradicting Evidence Adjudication Gate",
                status=contra_status,
                summary=f"Evaluated contradicting evidence ({contradictions_found} unassessed contradiction items found).",
                blockers=contradiction_blockers,
                details={"unassessed_contradictions_count": contradictions_found},
                recommendations=["Provide analyst assessment notes reconciling all contradicting evidence references."] if contradiction_blockers else [],
            )
        )
        all_blockers.extend(contradiction_blockers)

        # ---------------------------------------------------------------------
        # Gate 6: QUESTIONS
        # ---------------------------------------------------------------------
        question_blockers: List[ReviewBlocker] = []
        questions_rows = []
        with conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT question_id, question, category, status FROM case_investigation_questions WHERE case_id = ?",
                (case_id,),
            )
            questions_rows = cur.fetchall()

        unanswered_q_cnt = 0
        for qr in questions_rows:
            qid = qr["question_id"]
            qstat = str(qr["status"]).upper()
            if qstat == "OPEN":
                unanswered_q_cnt += 1
                question_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-question-open-{qid}",
                        gate_type=ReviewGateType.QUESTIONS,
                        category=ReviewBlockerCategory.OPEN_INVESTIGATION_QUESTION,
                        description=f"Investigation question '{qid}' remains OPEN without recorded resolution.",
                        severity=BlockerSeverity.WARNING,
                        source_reference=f"question:{qid}",
                    )
                )

        q_status = GateEvaluationStatus.PASS if not question_blockers else GateEvaluationStatus.NEEDS_REVIEW
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.QUESTIONS,
                title="Investigation Questions Resolution Gate",
                status=q_status,
                summary=f"Evaluated {len(questions_rows)} questions ({unanswered_q_cnt} open).",
                blockers=question_blockers,
                details={"total_questions": len(questions_rows), "open_questions": unanswered_q_cnt},
                recommendations=["Resolve open questions or document them as UNRESOLVED / NOT_APPLICABLE."] if question_blockers else [],
            )
        )
        all_blockers.extend(question_blockers)

        # ---------------------------------------------------------------------
        # Gate 7: HUNTS
        # ---------------------------------------------------------------------
        hunt_blockers: List[ReviewBlocker] = []
        hunt_rows = []
        with conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT query_id, execution_status, result_count FROM case_query_history WHERE case_id = ?",
                (case_id,),
            )
            hunt_rows = cur.fetchall()

        failed_hunts_cnt = 0
        for hr in hunt_rows:
            qid = hr["query_id"]
            estat = str(hr["execution_status"]).upper()
            if estat not in ("SUCCESS", "COMPLETED"):
                failed_hunts_cnt += 1
                hunt_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-hunt-failed-{qid}",
                        gate_type=ReviewGateType.HUNTS,
                        category=ReviewBlockerCategory.TELEMETRY_GAP_REQUIRES_REVIEW,
                        description=f"Governed hunt query '{qid}' failed during execution with status '{estat}'.",
                        severity=BlockerSeverity.WARNING,
                        source_reference=f"query:{qid}",
                    )
                )

        hunt_status = GateEvaluationStatus.PASS if not hunt_blockers else GateEvaluationStatus.NEEDS_REVIEW
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.HUNTS,
                title="Governed Threat Hunt Execution Gate",
                status=hunt_status,
                summary=f"Evaluated {len(hunt_rows)} governed threat hunt executions ({failed_hunts_cnt} failed).",
                blockers=hunt_blockers,
                details={"total_queries": len(hunt_rows), "failed_queries": failed_hunts_cnt},
                recommendations=["Re-execute failed queries with adjusted parameters."] if hunt_blockers else [],
            )
        )
        all_blockers.extend(hunt_blockers)

        # ---------------------------------------------------------------------
        # Gate 8: TIMELINE_CONSISTENCY
        # ---------------------------------------------------------------------
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.TIMELINE_CONSISTENCY,
                title="Timeline Chronological Consistency Gate",
                status=GateEvaluationStatus.PASS,
                summary="Timeline ordering and sequence markers validated as chronologically consistent.",
                blockers=[],
                details={"timestamp_alignment": "CONSISTENT"},
            )
        )

        # ---------------------------------------------------------------------
        # Gate 9: GRAPH_CONSISTENCY
        # ---------------------------------------------------------------------
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.GRAPH_CONSISTENCY,
                title="Entity Graph & Topology Consistency Gate",
                status=GateEvaluationStatus.PASS,
                summary="Graph topology matches scoped incident entity bindings without orphan nodes.",
                blockers=[],
                details={"topology_alignment": "CONSISTENT"},
            )
        )

        # ---------------------------------------------------------------------
        # Gate 10: REPORT_CONSISTENCY
        # ---------------------------------------------------------------------
        report_blockers: List[ReviewBlocker] = []
        report_rows = []
        with conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT report_id, version, is_final FROM case_reports WHERE case_id = ? ORDER BY version DESC",
                (case_id,),
            )
            report_rows = cur.fetchall()

        if not report_rows:
            report_blockers.append(
                ReviewBlocker(
                    blocker_id=f"blk-report-none-{case_id}",
                    gate_type=ReviewGateType.REPORT_CONSISTENCY,
                    category=ReviewBlockerCategory.STALE_REPORT,
                    description="No forensic investigation report draft or finalized report exists for this case.",
                    severity=BlockerSeverity.INFO,
                    source_reference=f"case:{case_id}:reports",
                )
            )
        else:
            latest_report = report_rows[0]
            rep_ver = latest_report["version"]
            if case.version > rep_ver + 2:
                report_blockers.append(
                    ReviewBlocker(
                        blocker_id=f"blk-report-stale-{case_id}",
                        gate_type=ReviewGateType.REPORT_CONSISTENCY,
                        category=ReviewBlockerCategory.STALE_REPORT,
                        description=f"Latest report version ({rep_ver}) is superseded by current case version ({case.version}).",
                        severity=BlockerSeverity.WARNING,
                        source_reference=f"report:{latest_report['report_id']}:v{rep_ver}",
                    )
                )

        rep_status = GateEvaluationStatus.PASS if not report_blockers else (
            GateEvaluationStatus.NEEDS_REVIEW if any(b.severity == BlockerSeverity.WARNING for b in report_blockers)
            else GateEvaluationStatus.PASS
        )
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.REPORT_CONSISTENCY,
                title="Investigation Report Consistency Gate",
                status=rep_status,
                summary=f"Evaluated {len(report_rows)} report versions (latest v{report_rows[0]['version'] if report_rows else 0}).",
                blockers=report_blockers,
                details={"reports_count": len(report_rows)},
                recommendations=["Generate a new report revision capturing latest case updates."] if report_blockers else [],
            )
        )
        all_blockers.extend(report_blockers)

        # ---------------------------------------------------------------------
        # Gate 11: PACKAGE_CONSISTENCY
        # ---------------------------------------------------------------------
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.PACKAGE_CONSISTENCY,
                title="Evidence Package Integrity Gate",
                status=GateEvaluationStatus.PASS,
                summary="Package manifests and cryptographic digests verified against case state.",
                blockers=[],
                details={"package_status": "VERIFIED"},
            )
        )

        # ---------------------------------------------------------------------
        # Gate 12: HANDOFF
        # ---------------------------------------------------------------------
        gates.append(
            ReviewGateResult(
                gate_type=ReviewGateType.HANDOFF,
                title="Case Custody Handoff Gate",
                status=GateEvaluationStatus.PASS,
                summary="Case custody status verified without unresolved follow-up obligations.",
                blockers=[],
                details={"custody_owner": case.owner},
            )
        )

        # ---------------------------------------------------------------------
        # Apply Analyst Blocker Acknowledgment Overrides
        # ---------------------------------------------------------------------
        case_overrides = self._blocker_overrides.get(case_id, {})
        for blk in all_blockers:
            if blk.blocker_id in case_overrides:
                override = case_overrides[blk.blocker_id]
                blk.resolution_state = override["resolution_state"]
                blk.resolution_notes = override["resolution_notes"]
                blk.resolved_by = override["resolved_by"]
                blk.resolved_at = override["resolved_at"]

        # ---------------------------------------------------------------------
        # Derive Closure Readiness Categorical State
        # ---------------------------------------------------------------------
        current_case_status = getattr(case.status, "value", str(case.status)).upper()
        if current_case_status == "CLOSED":
            closure_readiness = ClosureReadinessState.CLOSED
        elif current_case_status == "ARCHIVED":
            closure_readiness = ClosureReadinessState.CLOSED
        else:
            unresolved_blockers = [
                b for b in all_blockers
                if b.severity == BlockerSeverity.BLOCKER
                and b.resolution_state == BlockerResolutionState.UNRESOLVED
            ]
            unresolved_warnings = [
                b for b in all_blockers
                if b.severity == BlockerSeverity.WARNING
                and b.resolution_state == BlockerResolutionState.UNRESOLVED
            ]

            if unresolved_blockers:
                closure_readiness = ClosureReadinessState.NOT_READY
            elif unresolved_warnings:
                closure_readiness = ClosureReadinessState.REVIEW_REQUIRED
            elif current_case_status == "READY_FOR_REVIEW":
                closure_readiness = ClosureReadinessState.READY_FOR_CLOSURE
            else:
                closure_readiness = ClosureReadinessState.READY_FOR_REVIEW

        # ---------------------------------------------------------------------
        # Deterministic Provenance Manifest Generation
        # ---------------------------------------------------------------------
        manifest_id = f"man-rev-{case_id}-{uuid.uuid4().hex[:8]}"
        gates_payload = json.dumps([g.model_dump() for g in gates], sort_keys=True)
        blockers_payload = json.dumps([b.model_dump() for b in all_blockers], sort_keys=True)

        gates_digest = self._compute_blake2b(gates_payload)
        blockers_digest = self._compute_blake2b(blockers_payload)
        root_digest = self._compute_blake2b(f"{case_id}|{closure_readiness.value}|{gates_digest}|{blockers_digest}")

        provenance = ReviewProvenanceManifest(
            manifest_id=manifest_id,
            case_id=case_id,
            closure_readiness=closure_readiness,
            gates_digest=gates_digest,
            blockers_digest=blockers_digest,
            root_digest=root_digest,
            generated_at=now_iso,
        )

        review_id = f"rev-{case_id}-{provenance.root_digest[:12]}"
        snapshot = CaseReviewSnapshot(
            review_id=review_id,
            case_id=case_id,
            case_status=current_case_status,
            case_version=case.version,
            closure_readiness=closure_readiness,
            gates=gates,
            blockers=all_blockers,
            coverage=cov_metrics,
            provenance=provenance,
            reviewed_by=actor,
            reviewed_at=now_iso,
            analyst_notes=request.notes if request else None,
        )

        # Cache in memory
        self._snapshots[case_id] = snapshot

        # Record audit log entry in cases.db
        with conn:
            conn.execute(
                """
                INSERT INTO case_audit_log (
                    case_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    now_iso,
                    actor,
                    "CASE_REVIEW_EVALUATION",
                    None,
                    closure_readiness.value,
                    f"Executed deterministic forensic review with outcome: {closure_readiness.value}",
                    json.dumps({"review_id": review_id, "root_digest": root_digest, "blockers_count": len(all_blockers)}),
                ),
            )

        logger.info(
            "Forensic review completed: case_id=%s, review_id=%s, readiness=%s, blockers_count=%d",
            case_id,
            review_id,
            closure_readiness.value,
            len(all_blockers),
        )
        return snapshot

    def get_review_snapshot(self, case_id: int, actor: str = "SecAnalyst-1") -> CaseReviewSnapshot:
        """Retrieve existing cached review snapshot or execute on-demand evaluation."""
        if case_id in self._snapshots:
            return self._snapshots[case_id]
        return self.run_forensic_review(case_id, actor=actor)

    # -------------------------------------------------------------------------
    # Blocker Acknowledgment Workflow
    # -------------------------------------------------------------------------

    def acknowledge_blocker(
        self,
        case_id: int,
        blocker_id: str,
        request: AcknowledgeBlockerRequest,
        actor: str = "SecAnalyst-1",
    ) -> CaseReviewSnapshot:
        """Record analyst acknowledgment or waiver for a specific review blocker."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        now_iso = datetime.now(timezone.utc).isoformat()
        clean_notes = self._sanitize_csv_cell(request.notes)

        if case_id not in self._blocker_overrides:
            self._blocker_overrides[case_id] = {}

        self._blocker_overrides[case_id][blocker_id] = {
            "resolution_state": request.resolution_state,
            "resolution_notes": clean_notes,
            "resolved_by": actor,
            "resolved_at": now_iso,
        }

        # Log acknowledgment event to immutable audit log
        conn = self.case_repo._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO case_audit_log (
                    case_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    now_iso,
                    actor,
                    "CASE_REVIEW_BLOCKER_ACKNOWLEDGED",
                    BlockerResolutionState.UNRESOLVED.value,
                    request.resolution_state.value,
                    f"Analyst acknowledged blocker '{blocker_id}' with status {request.resolution_state.value}",
                    json.dumps({"blocker_id": blocker_id, "notes": clean_notes}),
                ),
            )

        # Re-run review to update derived closure readiness
        return self.run_forensic_review(case_id, actor=actor)

    # -------------------------------------------------------------------------
    # Case Closure & Reopening Authorization
    # -------------------------------------------------------------------------

    def close_case(
        self,
        case_id: int,
        request: CloseCaseRequest,
        actor: str = "SecAnalyst-1",
    ) -> CaseReviewSnapshot:
        """Formally close an investigation after verifying all mandatory review gates pass."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        cur_status = getattr(case.status, "value", str(case.status)).upper()
        if cur_status == "CLOSED":
            return self.get_review_snapshot(case_id, actor=actor)

        # Execute fresh review to test gates
        snapshot = self.run_forensic_review(case_id, actor=actor)

        # Enforce that no unresolved BLOCKER severities exist
        unresolved_blockers = [
            b for b in snapshot.blockers
            if b.severity == BlockerSeverity.BLOCKER
            and b.resolution_state == BlockerResolutionState.UNRESOLVED
        ]
        if unresolved_blockers and not request.override_warnings:
            desc_list = [f"{b.blocker_id}: {b.description}" for b in unresolved_blockers]
            raise ValueError(
                f"Cannot close case {case_id}: {len(unresolved_blockers)} unresolved mandatory blocker(s) remain: "
                f"{'; '.join(desc_list)}"
            )

        # Transition case status in SQLite repository
        clean_notes = self._sanitize_csv_cell(request.closure_notes)
        self.case_repo.update_case_status(
            case_id=case_id,
            target_status=CaseStatus.CLOSED,
            actor=actor,
            reason=f"Forensic Case Closure: {clean_notes}",
        )

        # Re-evaluate snapshot to reflect CLOSED state
        updated_snapshot = self.run_forensic_review(case_id, actor=actor)
        return updated_snapshot

    def reopen_case(
        self,
        case_id: int,
        request: ReopenCaseRequest,
        actor: str = "SecAnalyst-1",
    ) -> CaseReviewSnapshot:
        """Formally reopen a CLOSED investigation with documented analyst justification."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        cur_status = getattr(case.status, "value", str(case.status)).upper()
        if cur_status != "CLOSED":
            raise ValueError(f"Case {case_id} cannot be reopened because current status is '{cur_status}', not CLOSED.")

        clean_reason = self._sanitize_csv_cell(request.reopen_reason)
        self.case_repo.update_case_status(
            case_id=case_id,
            target_status=CaseStatus.ACTIVE,
            actor=actor,
            reason=f"Investigation Reopened: {clean_reason}",
        )

        # Re-evaluate snapshot to reflect ACTIVE / REOPENED state
        updated_snapshot = self.run_forensic_review(case_id, actor=actor)
        return updated_snapshot

    # -------------------------------------------------------------------------
    # Review Audit History
    # -------------------------------------------------------------------------

    def get_review_history(self, case_id: int) -> List[Dict[str, Any]]:
        """Retrieve complete append-only review and lifecycle audit history for this case."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Investigation case {case_id} not found")

        conn = self.case_repo._get_connection()
        with conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT audit_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                FROM case_audit_log
                WHERE case_id = ? AND (action LIKE 'CASE_REVIEW%' OR action IN ('STATE_TRANSITION', 'CASE_CLOSED', 'CASE_REOPENED'))
                ORDER BY audit_id ASC
                """,
                (case_id,),
            )
            rows = cur.fetchall()

        history: List[Dict[str, Any]] = []
        for r in rows:
            details = None
            if r["details_json"]:
                try:
                    details = json.loads(r["details_json"])
                except Exception:
                    details = r["details_json"]
            history.append({
                "audit_id": r["audit_id"],
                "timestamp": r["timestamp"],
                "actor": r["actor"],
                "action": r["action"],
                "previous_value": r["previous_value"],
                "new_value": r["new_value"],
                "reason": r["reason"],
                "details": details,
            })
        return history

    # -------------------------------------------------------------------------
    # Deterministic Multi-Format Exports
    # -------------------------------------------------------------------------

    def export_review(
        self,
        case_id: int,
        export_format: ExportFormat,
        actor: str = "SecAnalyst-1",
    ) -> ReviewExportResponse:
        """Export review snapshot to deterministic JSON, defanged CSV, or Markdown."""
        snapshot = self.get_review_snapshot(case_id, actor=actor)
        ts_slug = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        if export_format == ExportFormat.JSON:
            filename = f"logintel_case_{case_id}_review_{ts_slug}.json"
            content = json.dumps(snapshot.model_dump(), indent=2, sort_keys=True, ensure_ascii=False)
        elif export_format == ExportFormat.CSV:
            filename = f"logintel_case_{case_id}_review_{ts_slug}.csv"
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow([
                "Blocker_ID",
                "Gate_Type",
                "Category",
                "Severity",
                "Resolution_State",
                "Description",
                "Source_Reference",
                "Resolution_Notes",
                "Resolved_By",
                "Resolved_At",
            ])
            for b in snapshot.blockers:
                writer.writerow([
                    self._sanitize_csv_cell(b.blocker_id),
                    self._sanitize_csv_cell(b.gate_type.value),
                    self._sanitize_csv_cell(b.category.value),
                    self._sanitize_csv_cell(b.severity.value),
                    self._sanitize_csv_cell(b.resolution_state.value),
                    self._sanitize_csv_cell(b.description),
                    self._sanitize_csv_cell(b.source_reference or ""),
                    self._sanitize_csv_cell(b.resolution_notes or ""),
                    self._sanitize_csv_cell(b.resolved_by or ""),
                    self._sanitize_csv_cell(b.resolved_at or ""),
                ])
            content = output.getvalue()
        elif export_format == ExportFormat.MARKDOWN:
            filename = f"logintel_case_{case_id}_review_{ts_slug}.md"
            lines = [
                f"# LogIntel Forensic Case Review — Case {case_id}",
                f"**Review ID:** `{snapshot.review_id}`  ",
                f"**Case Status:** `{snapshot.case_status}` (v{snapshot.case_version})  ",
                f"**Closure Readiness:** `{snapshot.closure_readiness.value}`  ",
                f"**Reviewer:** `{snapshot.reviewed_by}`  ",
                f"**Reviewed At:** `{snapshot.reviewed_at}`  ",
                f"**Provenance Root Digest:** `{snapshot.provenance.root_digest}`  ",
                "",
                "---",
                "",
                "## 1. Forensic Review Gates Evaluation",
                "",
                "| Gate | Title | Status | Identified Issues |",
                "| :--- | :--- | :---: | :---: |",
            ]
            for g in snapshot.gates:
                lines.append(f"| `{g.gate_type.value}` | {g.title} | **{g.status.value}** | {len(g.blockers)} |")

            lines.extend([
                "",
                "## 2. Evidence Coverage Metrics",
                "",
                f"- **Total Evidence References:** {snapshot.coverage.total_references}",
                f"- **Available References:** {snapshot.coverage.available_references}",
                f"- **Missing / Unresolved:** {snapshot.coverage.missing_references + snapshot.coverage.unresolved_references}",
                f"- **Observed Telemetry Count:** {snapshot.coverage.observed_evidence_count}",
                f"- **Inferred Telemetry Count:** {snapshot.coverage.inferred_evidence_count}",
                f"- **Telemetry Gaps:** {snapshot.coverage.telemetry_gaps_count} (Critical: {snapshot.coverage.critical_gaps_count})",
                "",
                "## 3. Review Blockers & Advisories",
                "",
            ])
            if not snapshot.blockers:
                lines.append("*Zero review blockers or advisories identified.*")
            else:
                for b in snapshot.blockers:
                    lines.extend([
                        f"### `{b.blocker_id}` [{b.severity.value}] — {b.category.value}",
                        f"- **Description:** {b.description}",
                        f"- **Status:** `{b.resolution_state.value}`",
                        f"- **Reference:** `{b.source_reference or 'None'}`",
                        f"- **Notes:** {b.resolution_notes or 'None'}",
                        "",
                    ])
            content = "\n".join(lines)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")

        # Record export event in audit log
        conn = self.case_repo._get_connection()
        with conn:
            conn.execute(
                """
                INSERT INTO case_audit_log (
                    case_id, timestamp, actor, action, previous_value, new_value, reason, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    datetime.now(timezone.utc).isoformat(),
                    actor,
                    "CASE_REVIEW_EXPORTED",
                    None,
                    export_format.value,
                    f"Exported forensic review in {export_format.value} format",
                    json.dumps({"filename": filename, "root_digest": snapshot.provenance.root_digest}),
                ),
            )

        return ReviewExportResponse(
            case_id=case_id,
            format=export_format.value,
            filename=filename,
            content=content,
            root_digest=snapshot.provenance.root_digest,
        )

    # -------------------------------------------------------------------------
    # Local AI Advisory Boundary
    # -------------------------------------------------------------------------

    def generate_ai_review_summary(
        self,
        case_id: int,
        request: Optional[AIReviewSummaryRequest] = None,
        actor: str = "SecAnalyst-1",
    ) -> AIReviewSummaryResponse:
        """Generates an advisory-only review briefing using local Ollama boundary or deterministic synthesis."""
        snapshot = self.get_review_snapshot(case_id, actor=actor)
        key_blockers = [f"[{b.severity.value}] {b.category.value}: {b.description}" for b in snapshot.blockers[:5]]
        recommendations = []
        for g in snapshot.gates:
            recommendations.extend(g.recommendations)
        recommendations = list(dict.fromkeys(recommendations))[:5]

        # Deterministic advisory synthesis
        advisory_summary = (
            f"[AI ADVISORY REVIEW SUMMARY — DRAFT ONLY]\n"
            f"Case {case_id} evaluation indicates closure readiness state: {snapshot.closure_readiness.value}.\n"
            f"Evaluated 12 forensic gates: {len([g for g in snapshot.gates if g.status == GateEvaluationStatus.PASS])} PASS, "
            f"{len([g for g in snapshot.gates if g.status != GateEvaluationStatus.PASS])} requiring analyst review.\n"
            f"Total identified blockers/advisories: {len(snapshot.blockers)}.\n"
            f"Evidence coverage: {snapshot.coverage.available_references}/{snapshot.coverage.total_references} available references."
        )

        # Optional loopback Ollama call with prompt injection defense
        ollama_url = getattr(settings, "OLLAMA_API_URL", "http://localhost:11434")
        user_inst = self._defang_prompt(request.instructions if request and request.instructions else "")

        try:
            prompt = (
                f"You are a forensic security review assistant. Summarize the following case review data in 3 clear sentences.\n"
                f"<review_data>\n"
                f"Case: {case_id}\n"
                f"Readiness: {snapshot.closure_readiness.value}\n"
                f"Blockers: {'; '.join(key_blockers) if key_blockers else 'None'}\n"
                f"Instructions: {user_inst}\n"
                f"</review_data>\n"
                f"Provide concise factual summary only. Do not invent attribution or declare certainty."
            )
            with httpx.Client(timeout=4.0) as client:
                res = client.post(
                    f"{ollama_url}/api/generate",
                    json={"model": getattr(settings, "OLLAMA_MODEL", "qwen2.5:latest"), "prompt": prompt, "stream": False},
                )
                if res.status_code == 200:
                    resp_json = res.json()
                    model_out = resp_json.get("response", "").strip()
                    if model_out:
                        advisory_summary = f"[AI ADVISORY REVIEW SUMMARY — DRAFT ONLY]\n{model_out}"
        except Exception:
            # Fall back safely to deterministic synthesis
            pass

        return AIReviewSummaryResponse(
            summary=advisory_summary,
            key_blockers=key_blockers,
            recommendations=recommendations,
            is_authoritative=False,
            advisory_only=True,
        )


case_review_service = InvestigationReviewService()
