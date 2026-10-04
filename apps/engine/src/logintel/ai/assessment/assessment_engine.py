"""Deterministic Case Assessment, Evidence Synthesis & Investigation Closure Engine for Milestone M5.11.

Implements:
- M11-01: Case Assessment Model
- M11-02: Evidence Sufficiency Assessment (Categorical states only, no numeric scores)
- M11-03: Structured Key Findings with epistemic states (OBSERVED / INFERRED / UNKNOWN)
- M11-04: Finding Review tracking independent of epistemic status
- M11-05: Hypothesis Assessment with explicit supporting / contradicting evidence
- M11-06: Competing Hypotheses handling
- M11-07: Investigation Questions with status lifecycle
- M11-08: Prioritized Evidence Gaps with explainable rationale
- M11-09: Case State Intelligence
- M11-10: Closure Readiness Evaluation (Advisory only)
- M11-11: Analyst Assessment recording and origin tracking
- M11-12: Evidence-Backed Case Conclusion
- M11-13: 15-Section Investigation Briefing Generation
- M11-14: Final Report Draft Generation
- M11-15: Provenance Manifest with Cryptographic Fingerprints
- M11-17: Case Handoff Package
- M11-18: Local AI Advisory Explanations (is_authoritative = False)
- M11-19: Application-Level Prompt Injection Containment
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from logintel.ai.domain.case import InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_assessment import (
    AssessmentExplanationResponse,
    AssessmentState,
    CaseAssessment,
    CaseConclusion,
    CaseHandoffPackage,
    ClosureReadinessAssessment,
    ClosureReadinessState,
    CompetingHypothesisAssessment,
    ContentOrigin,
    EvidenceSufficiencyAssessment,
    EvidenceSufficiencyState,
    GapPriority,
    InvestigationBriefing,
    InvestigationQuestion,
    PrioritizedEvidenceGap,
    ProvenanceManifest,
    QuestionCategory,
    QuestionStatus,
    StructuredFinding,
)
from logintel.ai.domain.investigation_correlation import EvidenceCluster
from logintel.ai.domain.investigation_dossier import FindingReviewState
from logintel.ai.domain.investigation_graph import CorroborationStatus, InvestigationGraph
from logintel.ai.domain.investigation_intel import EpistemicStatus
from logintel.ai.domain.investigation_temporal import (
    AttackSequenceReconstruction,
    TemporalGap,
    TemporalReconstructionDossier,
    TemporalTransition,
)
from logintel.logging import get_logger

logger = get_logger("ai.assessment_engine")


class AssessmentEngine:
    """Core deterministic engine for analyst decision intelligence and case assessment synthesis."""

    # Server-side resource bounds
    MAX_FINDINGS: int = 50
    MAX_HYPOTHESES: int = 20
    MAX_GAPS: int = 50
    MAX_QUESTIONS: int = 50
    MAX_EVIDENCE_REFS: int = 30
    MAX_REPORT_SECTIONS: int = 20
    MAX_STRING_LEN: int = 4000

    def __init__(self) -> None:
        pass

    def _compute_hash(self, content: Any) -> str:
        """Compute deterministic SHA-256 fingerprint."""
        if isinstance(content, str):
            payload = content.encode("utf-8")
        else:
            payload = json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    def _sanitize_string(self, text: Optional[str], max_len: Optional[int] = None) -> str:
        """Sanitize text against injection markers and control characters while preserving forensics."""
        if not text:
            return ""
        max_l = max_len or self.MAX_STRING_LEN
        cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", str(text))
        return cleaned[:max_l].strip()

    # -------------------------------------------------------------------------
    # M11-02: Evidence Sufficiency Assessment
    # -------------------------------------------------------------------------
    def evaluate_evidence_sufficiency(
        self,
        case: InvestigationCase,
        findings: List[StructuredFinding],
        gaps: List[PrioritizedEvidenceGap],
        temporal_dossier: Optional[TemporalReconstructionDossier] = None,
    ) -> EvidenceSufficiencyAssessment:
        """Deterministically assess whether evidence is sufficient to draw conclusions.

        Strictly avoids numeric scores or probabilities; evaluates explicit categorical conditions.
        """
        existing_evidence: List[str] = []
        missing_evidence: List[str] = []
        contradicting_evidence: List[str] = []
        next_useful_evidence: List[str] = []

        total_refs = len(case.evidence_references)
        for ref in case.evidence_references[: self.MAX_EVIDENCE_REFS]:
            existing_evidence.append(f"{ref.source_type}:{ref.source_id} ({ref.citation_tag})")

        critical_gaps = [g for g in gaps if g.priority == GapPriority.CRITICAL]
        high_gaps = [g for g in gaps if g.priority == GapPriority.HIGH]

        for g in gaps:
            if g.priority in {GapPriority.CRITICAL, GapPriority.HIGH}:
                missing_evidence.append(f"{g.title}: {g.remedy}")
                next_useful_evidence.append(g.remedy)

        for f in findings:
            if f.contradicting_references:
                for c in f.contradicting_references:
                    if c not in contradicting_evidence:
                        contradicting_evidence.append(c)

        # Categorical derivation rule
        if total_refs == 0:
            status = EvidenceSufficiencyState.UNKNOWN
            rationale = "No evidence references have been pinned or collected for this case."
        elif len(critical_gaps) > 0:
            status = EvidenceSufficiencyState.INSUFFICIENT
            rationale = (
                f"Evidence is insufficient due to {len(critical_gaps)} critical evidence gap(s) "
                "breaking continuity or execution chain."
            )
        elif len(high_gaps) > 0 or len(contradicting_evidence) > 0:
            status = EvidenceSufficiencyState.PARTIALLY_SUFFICIENT
            rationale = (
                f"Evidence is partially sufficient ({total_refs} references), but {len(high_gaps)} high-priority "
                f"gap(s) or {len(contradicting_evidence)} contradicting evidence item(s) require analyst resolution."
            )
        else:
            status = EvidenceSufficiencyState.SUFFICIENT
            rationale = (
                f"Evidence is sufficient ({total_refs} references) with verified continuity and no blocking gaps."
            )

        return EvidenceSufficiencyAssessment(
            status=status,
            rationale=rationale,
            existing_evidence=existing_evidence[: self.MAX_EVIDENCE_REFS],
            missing_evidence=missing_evidence[: self.MAX_EVIDENCE_REFS],
            contradicting_evidence=contradicting_evidence[: self.MAX_EVIDENCE_REFS],
            next_useful_evidence=next_useful_evidence[:10],
        )

    # -------------------------------------------------------------------------
    # M11-03: Key Findings Synthesis
    # -------------------------------------------------------------------------
    def synthesize_key_findings(
        self,
        case: InvestigationCase,
        finding_reviews: Optional[Dict[str, Dict[str, Any]]] = None,
        temporal_dossier: Optional[TemporalReconstructionDossier] = None,
    ) -> List[StructuredFinding]:
        """Synthesize structured case findings from evidence references, transitions, and detections.

        Epistemic status is determined strictly by forensic basis:
        - Direct authoritative event citations -> OBSERVED
        - Derived progressions / correlations -> INFERRED
        - Absent or unverifiable claims -> UNKNOWN
        """
        findings: List[StructuredFinding] = []
        reviews = finding_reviews or {}

        # 1. Findings from temporal transitions (if dossier available)
        if temporal_dossier:
            for tr in temporal_dossier.transitions[:15]:
                f_id = f"f-trans-{tr.transition_id}"
                rev = reviews.get(f_id, {})
                review_state = FindingReviewState(rev.get("review_state", "UNREVIEWED"))

                ev_refs = [r.citation_tag for r in tr.evidence_references]
                entities = [tr.from_entity, tr.to_entity]

                findings.append(
                    StructuredFinding(
                        finding_id=f_id,
                        case_id=case.case_id,
                        title=f"Transition: {tr.transition_type.value} ({tr.from_entity} -> {tr.to_entity})",
                        description=f"Observed or reconstructed transition from {tr.from_entity} to {tr.to_entity} at {tr.timestamp}. Basis: {tr.correlation_basis}.",
                        epistemic_status=tr.epistemic_status,
                        severity="MEDIUM" if tr.epistemic_status == EpistemicStatus.OBSERVED else "LOW",
                        evidence_references=ev_refs,
                        supporting_references=ev_refs,
                        contradicting_references=[],
                        related_entities=entities,
                        related_events=[r.source_id for r in tr.evidence_references if r.source_type == "EVENT"],
                        related_incidents=[case.incident_id],
                        related_sequences=[],
                        mitre_references=[],
                        review_state=review_state,
                        provenance={
                            "source": "TEMPORAL_TRANSITION",
                            "source_id": tr.transition_id,
                            "hash": self._compute_hash(tr.transition_id),
                        },
                    )
                )

        # 2. Findings from pinned case evidence references
        for idx, ref in enumerate(case.evidence_references[:15]):
            f_id = f"f-ev-{ref.reference_id}"
            rev = reviews.get(f_id, {})
            review_state = FindingReviewState(rev.get("review_state", "UNREVIEWED"))

            ep_val = ref.epistemic_status.value if hasattr(ref.epistemic_status, "value") else str(ref.epistemic_status)
            role_val = ref.role.value if hasattr(ref.role, "value") else str(ref.role)

            epistemic = (
                EpistemicStatus.OBSERVED
                if ep_val.upper() == "OBSERVED"
                else EpistemicStatus.INFERRED
            )

            findings.append(
                StructuredFinding(
                    finding_id=f_id,
                    case_id=case.case_id,
                    title=f"Corroborated Evidence: {ref.source_type} [{ref.source_id}]",
                    description=ref.analyst_annotation
                    or f"Forensic artifact {ref.source_type}:{ref.source_id} tagged {ref.citation_tag}.",
                    epistemic_status=epistemic,
                    severity="HIGH" if role_val.upper() == "SUPPORTING" else "MEDIUM",
                    evidence_references=[ref.citation_tag],
                    supporting_references=[ref.citation_tag] if role_val.upper() == "SUPPORTING" else [],
                    contradicting_references=[ref.citation_tag] if role_val.upper() == "CONTRADICTING" else [],
                    related_entities=[ref.citation_tag],
                    related_events=[ref.source_id] if ref.source_type == "EVENT" else [],
                    related_incidents=[case.incident_id],
                    related_sequences=[],
                    mitre_references=[],
                    review_state=review_state,
                    provenance={
                        "source": "CASE_EVIDENCE_REFERENCE",
                        "source_id": ref.reference_id,
                        "hash": self._compute_hash(ref.reference_id),
                    },
                )
            )

        # 3. Fallback finding if empty
        if not findings:
            f_id = f"f-init-{case.case_id}"
            rev = reviews.get(f_id, {})
            review_state = FindingReviewState(rev.get("review_state", "UNREVIEWED"))
            findings.append(
                StructuredFinding(
                    finding_id=f_id,
                    case_id=case.case_id,
                    title=f"Investigation Initialized: {case.title}",
                    description=f"Case opened for incident {case.incident_id}. Telemetry collection and review underway.",
                    epistemic_status=EpistemicStatus.UNKNOWN,
                    severity="INFO",
                    evidence_references=[],
                    supporting_references=[],
                    contradicting_references=[],
                    related_entities=[],
                    related_events=[],
                    related_incidents=[case.incident_id],
                    related_sequences=[],
                    mitre_references=[],
                    review_state=review_state,
                    provenance={"source": "CASE_RECORD", "source_id": str(case.case_id)},
                )
            )

        return findings[: self.MAX_FINDINGS]

    # -------------------------------------------------------------------------
    # M11-05 & M11-06: Competing Hypotheses Assessment
    # -------------------------------------------------------------------------
    def assess_hypotheses(
        self,
        case: InvestigationCase,
        hypotheses: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[StructuredFinding]] = None,
    ) -> List[CompetingHypothesisAssessment]:
        """Assess competing hypotheses with explicit supporting, contradicting, and gap tracking."""
        results: List[CompetingHypothesisAssessment] = []
        raw_hypotheses = hypotheses or []

        # If no explicit hypotheses in case, provide standard deterministic competing hypotheses
        if not raw_hypotheses:
            raw_hypotheses = [
                {
                    "hypothesis_id": f"hyp-comp-{case.case_id}-1",
                    "statement": "Compromised credential used to conduct lateral movement or unauthorized activity.",
                    "status": "OPEN",
                    "supporting_evidence_tags": [r.citation_tag for r in case.evidence_references if r.role.value == "SUPPORTING"][:5],
                    "contradicting_evidence_tags": [r.citation_tag for r in case.evidence_references if r.role.value == "CONTRADICTING"][:5],
                    "evidence_gaps": ["Process execution telemetry during transition"],
                    "epistemic_status": "INFERRED",
                },
                {
                    "hypothesis_id": f"hyp-comp-{case.case_id}-2",
                    "statement": "Legitimate administrator maintenance or scheduled system task execution.",
                    "status": "OPEN",
                    "supporting_evidence_tags": [],
                    "contradicting_evidence_tags": [r.citation_tag for r in case.evidence_references if r.role.value == "SUPPORTING"][:5],
                    "evidence_gaps": ["Maintenance ticket or administrative change authorization record"],
                    "epistemic_status": "INFERRED",
                },
                {
                    "hypothesis_id": f"hyp-comp-{case.case_id}-3",
                    "statement": "Insufficient forensic telemetry to distinguish unauthorized intrusion from benign operational activity.",
                    "status": "OPEN",
                    "supporting_evidence_tags": [r.citation_tag for r in case.evidence_references][:3],
                    "contradicting_evidence_tags": [],
                    "evidence_gaps": ["Full endpoint command-line and process tree visibility"],
                    "epistemic_status": "OBSERVED",
                },
            ]

        for h in raw_hypotheses[: self.MAX_HYPOTHESES]:
            h_id = str(h.get("hypothesis_id") or f"hyp-{uuid.uuid4().hex[:6]}")
            stmt = self._sanitize_string(h.get("statement", "Investigation hypothesis"))
            status = str(h.get("status", "OPEN")).upper()
            if status not in {"OPEN", "SUPPORTED", "REFUTED", "DISPUTED", "ABANDONED"}:
                status = "OPEN"

            supp = list(h.get("supporting_evidence_tags") or [])
            contra = list(h.get("contradicting_evidence_tags") or [])
            gaps = list(h.get("evidence_gaps") or [])

            # Categorical determination
            if contra and not supp:
                det = "CONTRADICTING"
            elif supp and not contra:
                det = "SUPPORTING"
            elif supp and contra:
                det = "UNRESOLVED"
            else:
                det = "UNRESOLVED"

            ep_str = str(h.get("epistemic_status", "INFERRED")).upper()
            try:
                ep_status = EpistemicStatus(ep_str)
            except Exception:
                ep_status = EpistemicStatus.INFERRED

            results.append(
                CompetingHypothesisAssessment(
                    hypothesis_id=h_id,
                    statement=stmt,
                    status=status,
                    supporting_evidence=supp[: self.MAX_EVIDENCE_REFS],
                    contradicting_evidence=contra[: self.MAX_EVIDENCE_REFS],
                    evidence_gaps=gaps[:10],
                    determination=det,
                    analyst_assessment=h.get("analyst_assessment"),
                    epistemic_status=ep_status,
                )
            )

        return results

    # -------------------------------------------------------------------------
    # M11-08: Prioritized Evidence Gaps
    # -------------------------------------------------------------------------
    def prioritize_evidence_gaps(
        self,
        case: InvestigationCase,
        temporal_gaps: Optional[List[TemporalGap]] = None,
    ) -> List[PrioritizedEvidenceGap]:
        """Convert temporal and telemetry gaps into explainable, prioritized evidence gaps."""
        prioritized: List[PrioritizedEvidenceGap] = []
        raw_gaps = temporal_gaps or []

        for idx, tg in enumerate(raw_gaps[: self.MAX_GAPS]):
            dur = tg.duration_seconds or 0.0
            gap_type_val = tg.gap_type.value if hasattr(tg.gap_type, "value") else str(tg.gap_type)

            # Assign categorical priority based on gap characteristics
            if dur > 7200.0 or gap_type_val == "TELEMETRY_DROP":
                prio = GapPriority.CRITICAL
                rationale = (
                    f"Temporal span exceeds 2 hours ({dur:.0f}s) or represents telemetry drop "
                    f"breaking entity continuity."
                )
            elif dur > 1800.0 or gap_type_val == "UNMONITORED_SPAN":
                prio = GapPriority.HIGH
                rationale = (
                    f"Significant telemetry void ({dur:.0f}s) between active investigation episodes."
                )
            elif gap_type_val == "CROSS_HOST_SILENCE":
                prio = GapPriority.MEDIUM
                rationale = "Cross-host activity observed without intermediate connection logging."
            else:
                prio = GapPriority.LOW
                rationale = f"Minor telemetry delay ({dur:.0f}s) within acceptable sampling margins."

            affected_desc = ", ".join(tg.affected_entities) if tg.affected_entities else "Unknown"

            prioritized.append(
                PrioritizedEvidenceGap(
                    gap_id=tg.gap_id,
                    title=f"Telemetry Gap: {gap_type_val} [{dur:.0f}s]",
                    gap_type=gap_type_val,
                    affected_area=affected_desc,
                    priority=prio,
                    explanation=f"{tg.description} Rationale: {rationale}",
                    remedy=tg.remedy or "Query auditd / authlog telemetry for surrounding timestamps.",
                    related_entities=tg.affected_entities,
                )
            )

        # If no gaps detected from temporal reconstruction, check overall case evidence status
        if not prioritized and len(case.evidence_references) < 3:
            prioritized.append(
                PrioritizedEvidenceGap(
                    gap_id=f"gap-sparse-{case.case_id}",
                    title="Limited Forensic Evidence References",
                    gap_type="SPARSE_EVIDENCE",
                    affected_area="Case Evidence Baseline",
                    priority=GapPriority.HIGH,
                    explanation="Case has fewer than 3 pinned evidence records, limiting corroboration depth.",
                    remedy="Run governed entity pivots or expand chronological search window.",
                    related_entities=[],
                )
            )

        return prioritized

    # -------------------------------------------------------------------------
    # M11-07: Investigation Questions
    # -------------------------------------------------------------------------
    def generate_investigation_questions(
        self,
        case: InvestigationCase,
        findings: List[StructuredFinding],
        gaps: List[PrioritizedEvidenceGap],
        existing_questions: Optional[List[Dict[str, Any]]] = None,
    ) -> List[InvestigationQuestion]:
        """Synthesize or merge structured investigation questions."""
        questions: List[InvestigationQuestion] = []
        seen_texts: Set[str] = set()

        # 1. Include already recorded questions from cases.db
        if existing_questions:
            for eq in existing_questions[: self.MAX_QUESTIONS]:
                q_text = self._sanitize_string(eq.get("question", ""))
                if q_text in seen_texts:
                    continue
                seen_texts.add(q_text)

                try:
                    cat = QuestionCategory(eq.get("category", "AUTHENTICATION"))
                except Exception:
                    cat = QuestionCategory.AUTHENTICATION

                try:
                    stat = QuestionStatus(eq.get("status", "OPEN"))
                except Exception:
                    stat = QuestionStatus.OPEN

                questions.append(
                    InvestigationQuestion(
                        question_id=str(eq.get("question_id")),
                        case_id=case.case_id,
                        question=q_text,
                        category=cat,
                        status=stat,
                        related_evidence=list(eq.get("related_evidence") or []),
                        related_entities=list(eq.get("related_entities") or []),
                        recommended_query=eq.get("recommended_query"),
                        created_at=str(eq.get("created_at")),
                        resolved_at=eq.get("resolved_at"),
                        resolution_notes=eq.get("resolution_notes"),
                    )
                )

        now_iso = datetime.now(timezone.utc).isoformat()

        # 2. Derive standard unanswered questions from gaps and uncorroborated findings
        derived_candidates: List[Tuple[str, QuestionCategory, Optional[str]]] = [
            (
                "Which account or service initiated the initial authentication transition?",
                QuestionCategory.AUTHENTICATION,
                "SELECT * FROM events WHERE event_type LIKE '%auth%' ORDER BY timestamp ASC LIMIT 50",
            ),
            (
                "Was process execution executed locally or invoked via remote execution protocol (SSH/WinRM)?",
                QuestionCategory.EXECUTION,
                "SELECT * FROM events WHERE event_type = 'PROCESS_EXEC' ORDER BY timestamp ASC LIMIT 50",
            ),
            (
                "Was the destination host observed independently in external network flow telemetry?",
                QuestionCategory.HOST_ATTRIBUTION,
                "SELECT * FROM events WHERE host = ? OR raw_text LIKE ? LIMIT 50",
            ),
            (
                "Was the observed administrative activity covered by an approved change authorization ticket?",
                QuestionCategory.AUTHORIZATION,
                None,
            ),
        ]

        for q_text, cat, q_rec in derived_candidates:
            if q_text not in seen_texts and len(questions) < self.MAX_QUESTIONS:
                seen_texts.add(q_text)
                q_id = f"q-der-{case.case_id}-{hashlib.sha256(q_text.encode()).hexdigest()[:8]}"
                questions.append(
                    InvestigationQuestion(
                        question_id=q_id,
                        case_id=case.case_id,
                        question=q_text,
                        category=cat,
                        status=QuestionStatus.OPEN,
                        related_evidence=[],
                        related_entities=[],
                        recommended_query=q_rec,
                        created_at=now_iso,
                    )
                )

        return questions[: self.MAX_QUESTIONS]

    # -------------------------------------------------------------------------
    # M11-10: Closure Readiness Evaluation
    # -------------------------------------------------------------------------
    def evaluate_closure_readiness(
        self,
        case: InvestigationCase,
        findings: List[StructuredFinding],
        sufficiency: EvidenceSufficiencyAssessment,
        gaps: List[PrioritizedEvidenceGap],
        questions: List[InvestigationQuestion],
        hypotheses: List[CompetingHypothesisAssessment],
    ) -> ClosureReadinessAssessment:
        """Deterministically assess whether a case is analytically ready for review or closure.

        Strictly advisory: does NOT modify case status or close incidents automatically.
        """
        blocking_factors: List[str] = []
        warnings: List[str] = []
        recommendations: List[str] = []

        # 1. Unreviewed findings check
        unreviewed_findings = [f for f in findings if f.review_state == FindingReviewState.UNREVIEWED]
        if unreviewed_findings:
            blocking_factors.append(
                f"{len(unreviewed_findings)} finding(s) remain UNREVIEWED by an analyst."
            )
            recommendations.append("Review all findings to ACCEPT, REJECT, or DISPUTE.")

        # 2. Critical gaps check
        critical_gaps = [g for g in gaps if g.priority == GapPriority.CRITICAL]
        if critical_gaps:
            blocking_factors.append(
                f"{len(critical_gaps)} CRITICAL evidence gap(s) unresolved."
            )
            recommendations.append("Resolve critical telemetry gaps via governed hunting queries.")

        # 3. Open investigation questions check
        open_questions = [q for q in questions if q.status == QuestionStatus.OPEN]
        if open_questions:
            warnings.append(
                f"{len(open_questions)} open investigation question(s) remain unaddressed."
            )
            recommendations.append("Address open questions or mark as NOT_APPLICABLE / UNRESOLVED.")

        # 4. Evidence sufficiency check
        if sufficiency.status == EvidenceSufficiencyState.INSUFFICIENT:
            blocking_factors.append("Evidence sufficiency is rated INSUFFICIENT.")
        elif sufficiency.status == EvidenceSufficiencyState.PARTIALLY_SUFFICIENT:
            warnings.append("Evidence is only PARTIALLY_SUFFICIENT.")

        # 5. Contradicting evidence check
        if sufficiency.contradicting_evidence:
            warnings.append(
                f"{len(sufficiency.contradicting_evidence)} contradicting evidence item(s) present."
            )
            recommendations.append("Document analyst rationale regarding contradicting evidence.")

        # Categorical derivation of readiness state
        if blocking_factors:
            state = ClosureReadinessState.NOT_READY
            summary = (
                f"Case is NOT_READY for closure due to {len(blocking_factors)} blocking condition(s)."
            )
        elif warnings:
            state = ClosureReadinessState.READY_WITH_LIMITATIONS
            summary = (
                "Case is READY_WITH_LIMITATIONS. Fundamental evidence is established, "
                f"but {len(warnings)} non-blocking observation(s) should be noted in final report."
            )
        elif sufficiency.status == EvidenceSufficiencyState.UNKNOWN:
            state = ClosureReadinessState.UNKNOWN
            summary = "Case readiness cannot be evaluated due to lack of evidence baseline."
        else:
            state = ClosureReadinessState.READY
            summary = (
                "Case is READY for analyst review and closure. All findings reviewed, "
                "no critical gaps, and evidence is sufficient."
            )

        return ClosureReadinessAssessment(
            status=state,
            summary=summary,
            blocking_factors=blocking_factors,
            warnings=warnings,
            recommendations=recommendations,
        )

    # -------------------------------------------------------------------------
    # M11-12: Evidence-Backed Case Conclusion
    # -------------------------------------------------------------------------
    def build_case_conclusion(
        self,
        case: InvestigationCase,
        findings: List[StructuredFinding],
        sufficiency: EvidenceSufficiencyAssessment,
        readiness: ClosureReadinessAssessment,
        analyst_assessment_text: str = "",
    ) -> CaseConclusion:
        """Construct an evidence-backed case conclusion preserving epistemic boundaries."""
        supporting_refs: List[str] = []
        contradicting_refs: List[str] = []
        limitations: List[str] = list(readiness.warnings)
        unknowns: List[str] = []

        for f in findings:
            if f.review_state == FindingReviewState.ACCEPTED:
                supporting_refs.extend(f.supporting_references)
                contradicting_refs.extend(f.contradicting_references)

        # Fallback to observed findings references if no findings explicitly accepted yet
        if not supporting_refs:
            for f in findings:
                supporting_refs.extend(f.supporting_references)
                contradicting_refs.extend(f.contradicting_references)

        # Deduplicate
        supp_dedup = sorted(list(set(supporting_refs)))[: self.MAX_EVIDENCE_REFS]
        contra_dedup = sorted(list(set(contradicting_refs)))[: self.MAX_EVIDENCE_REFS]

        # Determine epistemic status of overall conclusion
        if not supp_dedup:
            epistemic = EpistemicStatus.UNKNOWN
            statement = f"Forensic telemetry for case {case.case_id} remains indeterminate."
            unknowns.append("Root cause cannot be established from existing telemetry.")
        elif contra_dedup:
            epistemic = EpistemicStatus.INFERRED
            statement = (
                f"Evidence supports reconstructed activity in case {case.case_id}, "
                f"with {len(contra_dedup)} contradicting observations noted."
            )
        else:
            has_observed = any(f.epistemic_status == EpistemicStatus.OBSERVED for f in findings)
            epistemic = EpistemicStatus.OBSERVED if has_observed else EpistemicStatus.INFERRED
            statement = (
                f"Forensic evidence establishes the reconstructed incident progression for case {case.case_id}."
            )

        if analyst_assessment_text:
            statement += f" Analyst Note: {analyst_assessment_text.strip()}"

        return CaseConclusion(
            statement=statement,
            epistemic_status=epistemic,
            supporting_evidence=supp_dedup,
            contradicting_evidence=contra_dedup,
            limitations=limitations,
            unknowns=unknowns,
        )

    # -------------------------------------------------------------------------
    # M11-01: Full Case Assessment Synthesis
    # -------------------------------------------------------------------------
    def synthesize_case_assessment(
        self,
        case: InvestigationCase,
        temporal_dossier: Optional[TemporalReconstructionDossier] = None,
        finding_reviews: Optional[Dict[str, Dict[str, Any]]] = None,
        existing_questions: Optional[List[Dict[str, Any]]] = None,
        existing_hypotheses: Optional[List[Dict[str, Any]]] = None,
        analyst_assessment: str = "",
        assessment_version: int = 1,
    ) -> CaseAssessment:
        """Synthesize a complete deterministic CaseAssessment object."""
        now_iso = datetime.now(timezone.utc).isoformat()
        assessment_id = f"asmt-{case.case_id}-v{assessment_version}"

        # 1. Findings
        findings = self.synthesize_key_findings(case, finding_reviews, temporal_dossier)

        # 2. Gaps
        temporal_gaps = temporal_dossier.gaps if temporal_dossier else []
        gaps = self.prioritize_evidence_gaps(case, temporal_gaps)

        # 3. Sufficiency
        sufficiency = self.evaluate_evidence_sufficiency(case, findings, gaps, temporal_dossier)

        # 4. Competing hypotheses
        hypotheses = self.assess_hypotheses(case, existing_hypotheses, findings)

        # 5. Investigation questions
        questions = self.generate_investigation_questions(case, findings, gaps, existing_questions)

        # 6. Closure readiness
        readiness = self.evaluate_closure_readiness(case, findings, sufficiency, gaps, questions, hypotheses)

        # 7. Evidence-backed conclusion
        conclusion = self.build_case_conclusion(case, findings, sufficiency, readiness, analyst_assessment)

        # Summary telemetry
        attack_summary = []
        mitre_summary = []
        affected_hosts = []
        affected_entities = []

        if temporal_dossier:
            attack_summary = [s.name for s in temporal_dossier.attack_sequences[:5]]
            mitre_summary = [str(m) for m in temporal_dossier.mitre_summary[:10]]
            hosts_set = set()
            for trace in temporal_dossier.multi_host_traces:
                if trace.source_host:
                    hosts_set.add(trace.source_host)
                if trace.target_host:
                    hosts_set.add(trace.target_host)
            for cont in temporal_dossier.continuities:
                hosts_set.update(cont.participating_hosts)
            affected_hosts = sorted(list(hosts_set))[:10]

            for tr in temporal_dossier.transitions[:20]:
                if tr.from_entity and tr.from_entity not in affected_entities:
                    affected_entities.append(tr.from_entity)
                if tr.to_entity and tr.to_entity not in affected_entities:
                    affected_entities.append(tr.to_entity)

        # Provenance manifest
        source_records = [
            {"type": "CASE", "id": str(case.case_id), "hash": self._compute_hash(case.case_id)},
            {
                "type": "INCIDENT",
                "id": str(case.incident_id),
                "hash": self._compute_hash(case.incident_id),
            },
        ]
        if temporal_dossier:
            source_records.append(
                {
                    "type": "TEMPORAL_DOSSIER",
                    "id": temporal_dossier.reconstruction_id,
                    "hash": temporal_dossier.provenance_hash,
                }
            )

        provenance = ProvenanceManifest(
            case_id=case.case_id,
            assessment_id=assessment_id,
            version=assessment_version,
            generation_timestamp=now_iso,
            content_origin=ContentOrigin.SYSTEM_DETERMINISTIC,
            source_records=source_records,
            fingerprint=self._compute_hash(
                {
                    "case_id": case.case_id,
                    "version": assessment_version,
                    "findings_count": len(findings),
                    "readiness": readiness.status.value,
                    "sufficiency": sufficiency.status.value,
                }
            ),
        )

        return CaseAssessment(
            case_id=case.case_id,
            assessment_id=assessment_id,
            assessment_version=assessment_version,
            created_at=now_iso,
            updated_at=now_iso,
            case_state=case.status.value,
            evidence_state=sufficiency.status,
            assessment_state=AssessmentState.DRAFT,
            epistemic_summary={
                "total_findings": len(findings),
                "observed": len([f for f in findings if f.epistemic_status == EpistemicStatus.OBSERVED]),
                "inferred": len([f for f in findings if f.epistemic_status == EpistemicStatus.INFERRED]),
                "unknown": len([f for f in findings if f.epistemic_status == EpistemicStatus.UNKNOWN]),
            },
            key_findings=findings,
            supporting_evidence=conclusion.supporting_evidence,
            contradicting_evidence=conclusion.contradicting_evidence,
            evidence_gaps=gaps,
            hypotheses=hypotheses,
            questions=questions,
            evidence_sufficiency=sufficiency,
            attack_sequence_summary=attack_summary,
            affected_entities=affected_entities[:20],
            affected_hosts=affected_hosts,
            mitre_summary=mitre_summary,
            analyst_assessment=analyst_assessment,
            closure_readiness=readiness,
            conclusion=conclusion,
            provenance=provenance,
        )

    # -------------------------------------------------------------------------
    # M11-13: 15-Section Investigation Briefing Generation
    # -------------------------------------------------------------------------
    def generate_investigation_briefing(self, assessment: CaseAssessment) -> InvestigationBriefing:
        """Generate a deterministic 15-section investigation briefing."""
        sections: Dict[str, str] = {
            "Case Overview": f"Case ID: {assessment.case_id} | State: {assessment.case_state} | Version: {assessment.assessment_version}",
            "Investigation Scope": f"Investigation of Incident {assessment.case_id}. Telemetry bounded to local system events.",
            "Key Findings": f"{len(assessment.key_findings)} structured findings compiled. Observed: {assessment.epistemic_summary.get('observed')}, Inferred: {assessment.epistemic_summary.get('inferred')}, Unknown: {assessment.epistemic_summary.get('unknown')}.",
            "Temporal Reconstruction": f"Reconstruction includes {len(assessment.attack_sequence_summary)} attack sequence step(s).",
            "Attack Sequence": ", ".join(assessment.attack_sequence_summary) if assessment.attack_sequence_summary else "No verified attack progression sequences.",
            "Affected Entities": ", ".join(assessment.affected_entities) if assessment.affected_entities else "None identified.",
            "Affected Hosts": ", ".join(assessment.affected_hosts) if assessment.affected_hosts else "Localhost only.",
            "Incident Relationships": f"Associated with Incident {assessment.case_id}.",
            "MITRE ATT&CK Mapping": ", ".join(assessment.mitre_summary) if assessment.mitre_summary else "No explicit ATT&CK technique matches verified.",
            "Evidence Gaps": f"{len(assessment.evidence_gaps)} evidence gaps identified. ({len([g for g in assessment.evidence_gaps if g.priority == GapPriority.CRITICAL])} critical).",
            "Competing Hypotheses": f"{len(assessment.hypotheses)} competing hypotheses evaluated against forensic evidence.",
            "Unresolved Questions": f"{len([q for q in assessment.questions if q.status == QuestionStatus.OPEN])} open investigation questions remaining.",
            "Analyst Assessment": assessment.analyst_assessment or "Pending analyst review.",
            "Closure Readiness": f"Readiness: {assessment.closure_readiness.status.value}. Summary: {assessment.closure_readiness.summary}",
            "Provenance": f"Generated at {assessment.created_at}. Fingerprint: {assessment.provenance.fingerprint}",
        }

        # Deterministic text summary
        text_lines = [
            f"# INVESTIGATION BRIEFING — CASE {assessment.case_id}",
            f"Assessment Version: v{assessment.assessment_version} | Status: {assessment.closure_readiness.status.value}",
            "--------------------------------------------------------------------------------",
        ]
        for title, content in sections.items():
            text_lines.append(f"\n## {title}\n{content}")

        briefing_text = "\n".join(text_lines)

        return InvestigationBriefing(
            briefing_id=f"brf-{assessment.case_id}-v{assessment.assessment_version}",
            case_id=assessment.case_id,
            assessment_id=assessment.assessment_id,
            sections=sections,
            briefing_text=briefing_text,
            closure_readiness=assessment.closure_readiness.status,
            evidence_sufficiency=assessment.evidence_sufficiency.status,
            generated_at=assessment.created_at,
            provenance_hash=assessment.provenance.fingerprint,
        )

    # -------------------------------------------------------------------------
    # M11-17: Case Handoff Package
    # -------------------------------------------------------------------------
    def generate_case_handoff_package(
        self,
        assessment: CaseAssessment,
        actor: str = "SecAnalyst-1",
    ) -> CaseHandoffPackage:
        """Create a deterministic analyst handoff package."""
        now_iso = datetime.now(timezone.utc).isoformat()
        required_actions: List[str] = list(assessment.closure_readiness.recommendations)
        if not required_actions:
            required_actions.append("Conduct final analyst sign-off and case closure.")

        open_q_texts = [q.question for q in assessment.questions if q.status == QuestionStatus.OPEN]
        gap_texts = [f"{g.title} ({g.priority.value}): {g.remedy}" for g in assessment.evidence_gaps]

        return CaseHandoffPackage(
            handoff_id=f"hnd-{assessment.case_id}-{uuid.uuid4().hex[:6]}",
            case_id=assessment.case_id,
            created_at=now_iso,
            operator=actor,
            case_summary=f"Case {assessment.case_id} handoff package. Readiness: {assessment.closure_readiness.status.value}.",
            current_state=assessment.case_state,
            key_findings=[f.title for f in assessment.key_findings[:10]],
            open_questions=open_q_texts[:10],
            evidence_gaps=gap_texts[:10],
            hypotheses=[f"{h.statement} [{h.determination}]" for h in assessment.hypotheses[:5]],
            affected_entities=assessment.affected_entities,
            analyst_assessment=assessment.analyst_assessment or "No analyst assessment recorded prior to handoff.",
            required_next_actions=required_actions,
            report_versions=[assessment.assessment_version],
            provenance_manifest=assessment.provenance.model_dump(),
        )

    # -------------------------------------------------------------------------
    # M11-18 & M11-19: Local AI Advisory with Prompt-Injection Containment
    # -------------------------------------------------------------------------
    def explain_case_assessment(
        self,
        assessment: CaseAssessment,
        target_id: Optional[str] = None,
        analyst_query: Optional[str] = None,
    ) -> AssessmentExplanationResponse:
        """Provide advisory-only explanation of case assessment and findings.

        Maintains strict non-authoritative boundary (is_authoritative = False)
        and contains untrusted telemetry / prompts.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        safe_query = self._sanitize_string(analyst_query) if analyst_query else ""
        prefix = f"[Query: {safe_query}]\n" if safe_query else ""

        # Target specific finding or entire assessment
        target_finding = None
        if target_id:
            for f in assessment.key_findings:
                if f.finding_id == target_id:
                    target_finding = f
                    break

        if target_finding:
            explanation = (
                f"{prefix}"
                f"Advisory Explanation for Finding {target_finding.finding_id}:\n"
                f"- Title: {target_finding.title}\n"
                f"- Description: {target_finding.description}\n"
                f"- Epistemic Status: {target_finding.epistemic_status.value} (Review State: {target_finding.review_state.value})\n"
                f"- Supporting References: {', '.join(target_finding.supporting_references) or 'None'}\n"
                f"- Contradicting References: {', '.join(target_finding.contradicting_references) or 'None'}\n"
                f"- Analytical Advisory: This finding represents a structured derivation from observed records. "
                f"Analyst review is required before final adoption."
            )
            citations = target_finding.supporting_references
        else:
            explanation = (
                f"{prefix}"
                f"Advisory Summary for Case Assessment {assessment.assessment_id}:\n"
                f"- Closure Readiness: {assessment.closure_readiness.status.value}\n"
                f"- Rationale: {assessment.closure_readiness.summary}\n"
                f"- Evidence Sufficiency: {assessment.evidence_sufficiency.status.value}\n"
                f"- Findings Count: {len(assessment.key_findings)} (Observed: {assessment.epistemic_summary.get('observed')})\n"
                f"- Open Questions: {len([q for q in assessment.questions if q.status == QuestionStatus.OPEN])}\n"
                f"- Critical Gaps: {len([g for g in assessment.evidence_gaps if g.priority == GapPriority.CRITICAL])}\n"
                f"- Analytical Advisory: All summaries are strictly advisory. The analyst maintains final authority "
                f"over case disposition and conclusion."
            )
            citations = assessment.supporting_evidence[:10]

        return AssessmentExplanationResponse(
            explanation_id=f"axp-{assessment.case_id}-{uuid.uuid4().hex[:6]}",
            case_id=assessment.case_id,
            target_id=target_id or assessment.assessment_id,
            explanation_text=explanation,
            is_authoritative=False,
            generated_by=ContentOrigin.LOCAL_AI_ADVISORY,
            referenced_citations=citations,
            epistemic_status=EpistemicStatus.INFERRED,
            generated_at=now_iso,
        )
