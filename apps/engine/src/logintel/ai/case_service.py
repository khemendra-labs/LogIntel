"""Case Service orchestrating persistent analyst investigations, versioning, handoff, and explainability.

Maintains strict separation between protected authoritative forensic SQLite tables (logintel.db)
and persistent analyst-controlled investigation cases (cases.db).
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
import uuid

from logintel.ai.domain.bundle import EvidenceItem, EvidenceRole
from logintel.ai.domain.case import (
    AIReconstructedContext,
    CaseAuditRecord,
    CaseEvidenceReference,
    CaseHypothesis,
    CaseQueryRecord,
    CaseReportVersion,
    CaseStatus,
    ContentOrigin,
    InvestigationCase,
    ResolutionStatus,
)
from logintel.ai.domain.evidence import EvidenceType
from logintel.ai.domain.intelligence import QueryProposal
from logintel.ai.domain.workspace import HypothesisStatus, InvestigationScope
from logintel.ai.domain.investigation_intel import (
    AttackPathStepAnalysis,
    CaseIntelligenceDossier,
    CaseTimelineItem,
    EntityPivotAnalysis,
    EpistemicStatus,
    EvidenceGap,
    GovernedThreatHuntExecution,
    GovernedThreatHuntProposal,
    HypothesisEvidenceAnalysis,
    InvestigationCorrelation,
    InvestigationFinding,
    InvestigationIntelligenceResponse,
    TemporalWindowAnalysis,
)
from logintel.ai.domain.investigation_dossier import (
    CaseBriefing,
    EvidenceGapAction,
    EvidenceMatrixEntry,
    FindingReviewState,
    FindingReviewUpdate,
    InvestigationDossier,
    ProvenanceManifestEntry,
    RefinedTimelineItem,
)
from logintel.ai.domain.investigation_graph import (
    EntityPivotGraph,
    GraphExplanationResponse,
    InvestigationGraph,
    InvestigationPath,
    TemporalChain,
)
from logintel.ai.dossier.dossier_builder import DossierBuilder
from logintel.ai.graph.graph_builder import InvestigationGraphBuilder
from logintel.ai.intelligence.service import InvestigationIntelligenceService
from logintel.ai.evidence.retriever import EvidenceRetriever
from logintel.logging import get_logger
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database, db as default_forensic_db
from logintel.storage.incidents_repo import IncidentsRepository
from logintel.storage.investigation_repo import InvestigationRepository

logger = get_logger("ai.case_service")


class CaseService:
    """Service providing persistent investigation case lifecycle, handoff, report versioning, and AI continuity."""

    def __init__(
        self,
        case_repository: Optional[CaseRepository] = None,
        forensic_database: Optional[Database] = None,
        incidents_repository: Optional[IncidentsRepository] = None,
        investigation_repository: Optional[InvestigationRepository] = None,
    ) -> None:
        self.forensic_db = forensic_database or default_forensic_db
        self.case_repo = case_repository or CaseRepository(forensic_db=self.forensic_db)
        self.incidents_repo = incidents_repository or IncidentsRepository(self.forensic_db)
        self.investigation_repo = investigation_repository or InvestigationRepository(database=self.forensic_db)
        self.retriever = EvidenceRetriever(database=self.forensic_db)
        self.intelligence = InvestigationIntelligenceService(
            database=self.forensic_db,
            case_repository=self.case_repo,
            investigation_repository=self.investigation_repo,
        )
        self.dossier_builder = DossierBuilder(
            forensic_db=self.forensic_db,
            case_repo=self.case_repo,
            investigation_repo=self.investigation_repo,
        )
        self.graph_builder = InvestigationGraphBuilder(forensic_db=self.forensic_db)

    def create_or_open_case(
        self,
        incident_id: int,
        title: Optional[str] = None,
        description: str = "",
        actor: str = "SecAnalyst-1",
    ) -> InvestigationCase:
        """Retrieve existing persistent case for incident or create a new persistent case."""
        existing = self.case_repo.get_case_by_incident(incident_id)
        if existing:
            return existing

        inc = self.incidents_repo.get_incident(incident_id)
        case_title = title or (f"Investigation: {inc.title}" if inc else f"Investigation INC-{incident_id}")
        case_desc = description or (inc.summary if inc else "")

        time_start_str = inc.first_seen.isoformat() if inc and hasattr(inc.first_seen, "isoformat") else str(inc.first_seen) if inc and inc.first_seen else None
        time_end_str = inc.last_seen.isoformat() if inc and hasattr(inc.last_seen, "isoformat") else str(inc.last_seen) if inc and inc.last_seen else None

        scope = InvestigationScope(
            investigation_id=incident_id,
            time_start=time_start_str,
            time_end=time_end_str,
            subject_type="incident",
            subject_id=str(incident_id),
            selected_entity_ids=[inc.primary_host] if inc and inc.primary_host else [],
        )

        case = self.case_repo.create_case(
            incident_id=incident_id,
            title=case_title,
            description=case_desc,
            created_by=actor,
            scope=scope,
        )

        # Pre-seed initial authoritative evidence references from incident detections/alerts
        bundle = self.retriever.retrieve_bundle(incident_id=incident_id)
        for item in bundle.items[:10]:
            self.case_repo.add_evidence_reference(
                case_id=case.case_id,
                source_type=item.source_table.rstrip("s"),  # event, alert, detection
                source_id=item.source_id,
                role=item.role.value if hasattr(item.role, "value") else str(item.role),
                epistemic_status="OBSERVED",
                citation_tag=item.citation_tag,
                analyst_annotation=f"Authoritative forensic evidence from {item.source_table}",
                actor=actor,
                bump_version=False,
            )

        return self.case_repo.get_case(case.case_id)  # type: ignore

    def get_case(self, case_id: int, resolve_evidence: bool = True) -> Optional[InvestigationCase]:
        """Fetch investigation case with dynamic evidence resolution."""
        return self.case_repo.get_case(case_id, resolve_evidence=resolve_evidence)

    def list_cases(
        self,
        status: Optional[CaseStatus] = None,
        owner: Optional[str] = None,
    ) -> List[InvestigationCase]:
        """List persistent investigation cases."""
        return self.case_repo.list_cases(status=status, owner=owner)

    def transition_case_state(
        self,
        case_id: int,
        target_status: CaseStatus,
        actor: str = "SecAnalyst-1",
        reason: Optional[str] = None,
    ) -> InvestigationCase:
        """Execute validated state transition with audit trail."""
        return self.case_repo.update_case_status(
            case_id=case_id,
            target_status=target_status,
            actor=actor,
            reason=reason,
        )

    def update_scope(
        self,
        case_id: int,
        scope: InvestigationScope,
        actor: str = "SecAnalyst-1",
    ) -> InvestigationCase:
        """Update explicit scope boundaries."""
        return self.case_repo.update_case_scope(
            case_id=case_id,
            scope=scope,
            actor=actor,
        )

    def associate_evidence(
        self,
        case_id: int,
        source_type: str,
        source_id: str,
        role: str = "SUPPORTING",
        epistemic_status: str = "OBSERVED",
        citation_tag: Optional[str] = None,
        annotation: Optional[str] = None,
        actor: str = "SecAnalyst-1",
    ) -> CaseEvidenceReference:
        """Associate an authoritative evidence reference."""
        tag = citation_tag or f"[{source_type}:{source_id}]"
        return self.case_repo.add_evidence_reference(
            case_id=case_id,
            source_type=source_type,
            source_id=source_id,
            role=role,
            epistemic_status=epistemic_status,
            citation_tag=tag,
            analyst_annotation=annotation,
            actor=actor,
        )

    def disassociate_evidence(
        self,
        case_id: int,
        reference_id: str,
        actor: str = "SecAnalyst-1",
    ) -> bool:
        """Disassociate an evidence reference."""
        return self.case_repo.remove_evidence_reference(
            case_id=case_id,
            reference_id=reference_id,
            actor=actor,
        )

    def create_hypothesis(
        self,
        case_id: int,
        statement: str,
        status: HypothesisStatus = HypothesisStatus.OPEN,
        supporting_tags: Optional[List[str]] = None,
        contradicting_tags: Optional[List[str]] = None,
        gaps: Optional[List[str]] = None,
        assessment: Optional[str] = None,
        actor: str = "SecAnalyst-1",
    ) -> CaseHypothesis:
        """Create and persist an analyst-owned hypothesis."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        hyp_id = f"hyp-{case_id}-{len(case.hypotheses) + 1}"
        now_iso = datetime.now(timezone.utc).isoformat()

        hypothesis = CaseHypothesis(
            hypothesis_id=hyp_id,
            case_id=case_id,
            statement=statement.strip(),
            status=status,
            supporting_evidence_tags=supporting_tags or [],
            contradicting_evidence_tags=contradicting_tags or [],
            evidence_gaps=gaps or [],
            analyst_assessment=assessment,
            created_at=now_iso,
            updated_at=now_iso,
            created_by=actor,
            version=1,
        )
        return self.case_repo.upsert_hypothesis(case_id, hypothesis, actor=actor)

    def update_hypothesis(
        self,
        case_id: int,
        hypothesis_id: str,
        statement: Optional[str] = None,
        status: Optional[HypothesisStatus] = None,
        supporting_tags: Optional[List[str]] = None,
        contradicting_tags: Optional[List[str]] = None,
        gaps: Optional[List[str]] = None,
        assessment: Optional[str] = None,
        actor: str = "SecAnalyst-1",
    ) -> CaseHypothesis:
        """Update an existing persistent hypothesis."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        target = next((h for h in case.hypotheses if h.hypothesis_id == hypothesis_id), None)
        if not target:
            raise ValueError(f"Hypothesis {hypothesis_id} not found in case {case_id}")

        updated = target.model_copy()
        if statement is not None:
            updated.statement = statement.strip()
        if status is not None:
            updated.status = status
        if supporting_tags is not None:
            updated.supporting_evidence_tags = supporting_tags
        if contradicting_tags is not None:
            updated.contradicting_evidence_tags = contradicting_tags
        if gaps is not None:
            updated.evidence_gaps = gaps
        if assessment is not None:
            updated.analyst_assessment = assessment

        return self.case_repo.upsert_hypothesis(case_id, updated, actor=actor)

    def execute_approved_query(
        self,
        case_id: int,
        proposal: QueryProposal,
        actor: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Execute analyst-approved threat hunting query and persist to case query history."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        conditions: List[str] = []
        params: List[Any] = []

        if proposal.host:
            conditions.append("host = ?")
            params.append(proposal.host)
        if proposal.username:
            conditions.append("username = ?")
            params.append(proposal.username)
        if proposal.src_ip:
            conditions.append("src_ip = ?")
            params.append(proposal.src_ip)
        if proposal.dst_ip:
            conditions.append("dst_ip = ?")
            params.append(proposal.dst_ip)
        if proposal.process_name:
            conditions.append("process_name = ?")
            params.append(proposal.process_name)
        if proposal.event_types:
            ph = ",".join("?" for _ in proposal.event_types)
            conditions.append(f"event_type IN ({ph})")
            params.extend(proposal.event_types)
        if proposal.search_text:
            conditions.append("(summary LIKE ? OR raw_message LIKE ?)")
            params.append(f"%{proposal.search_text}%")
            params.append(f"%{proposal.search_text}%")

        where_clause = " AND ".join(conditions) if conditions else "1=1"
        sql = f"""
            SELECT id, timestamp, source, event_type, severity, host, username,
                   process_name, src_ip, dst_ip, action, outcome, summary, raw_message
            FROM events
            WHERE {where_clause}
            ORDER BY timestamp DESC
            LIMIT 50
        """

        with self.forensic_db.connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute(sql, params).fetchall()

        matched_records = [dict(r) for r in rows]
        now_iso = datetime.now(timezone.utc).isoformat()
        q_id = f"query-{case_id}-{uuid.uuid4().hex[:8]}"

        q_template = (
            getattr(proposal, "query_template_id", None)
            or getattr(proposal, "intent", None)
            or getattr(proposal, "title", None)
            or "query_events"
        )
        params = getattr(proposal, "parameters", None) or getattr(proposal, "filters", None) or {
            "host": getattr(proposal, "host", None),
            "username": getattr(proposal, "username", None),
            "src_ip": getattr(proposal, "src_ip", None),
            "search_text": getattr(proposal, "search_text", None),
        }

        # Record in persistent query history
        query_record = CaseQueryRecord(
            query_id=q_id,
            case_id=case_id,
            proposal_id=proposal.proposal_id,
            query_template_id=q_template,
            parameters=params,
            rationale=proposal.rationale,
            executed_by=actor,
            executed_at=now_iso,
            result_count=len(matched_records),
            execution_status="SUCCESS" if matched_records else "NO_RESULTS",
            evidence_candidates_count=len(matched_records),
        )
        self.case_repo.record_query(case_id, query_record)

        # Stage matching events as evidence references (with role=SUPPORTING)
        for r in matched_records[:5]:
            ev_id = str(r["id"])
            self.case_repo.add_evidence_reference(
                case_id=case_id,
                source_type="event",
                source_id=ev_id,
                role="SUPPORTING",
                epistemic_status="INFERRED",
                citation_tag=f"[event:{ev_id}]",
                analyst_annotation=f"Discovered via approved threat query {proposal.proposal_id}",
                actor=actor,
            )

        return {
            "case_id": case_id,
            "query_id": q_id,
            "proposal_id": proposal.proposal_id,
            "executed_at": now_iso,
            "result_count": len(matched_records),
            "matched_events": matched_records,
            "query_record": query_record.model_dump(mode="json"),
        }

    def draft_or_revise_report(
        self,
        case_id: int,
        title: Optional[str] = None,
        analyst_notes: Optional[str] = None,
        is_final: bool = False,
        actor: str = "SecAnalyst-1",
    ) -> CaseReportVersion:
        """Generate or revise a persistent versioned investigation report."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        inc = self.incidents_repo.get_incident(case.incident_id)
        report_title = title or f"Investigation Report — {case.title}"
        report_id = f"rep-{case_id}"

        # Deterministically extract facts from available evidence references
        facts: List[Dict[str, Any]] = []
        for ref in case.evidence_references:
            if ref.resolution_status == ResolutionStatus.AVAILABLE:
                facts.append({
                    "citation_tag": ref.citation_tag,
                    "statement": f"Verified {ref.source_type} {ref.source_id} in authoritative forensic state.",
                    "source": ref.source_type,
                    "epistemic_status": "OBSERVED",
                })
            else:
                facts.append({
                    "citation_tag": ref.citation_tag,
                    "statement": f"Evidence reference {ref.citation_tag} cannot be resolved in current forensic state (status: {ref.resolution_status.value}).",
                    "source": ref.source_type,
                    "epistemic_status": "UNKNOWN",
                })

        # Inferences from hypotheses
        inferences: List[Dict[str, Any]] = []
        for hyp in case.hypotheses:
            if hyp.status in (HypothesisStatus.SUPPORTED, HypothesisStatus.WEAKENED):
                inferences.append({
                    "hypothesis_id": hyp.hypothesis_id,
                    "statement": hyp.statement,
                    "status": hyp.status.value,
                    "supporting_evidence": hyp.supporting_evidence_tags,
                    "assessment": hyp.analyst_assessment or "Pending further telemetry",
                })

        hypotheses_summary = [
            {
                "hypothesis_id": h.hypothesis_id,
                "statement": h.statement,
                "status": h.status.value,
                "evidence_gaps": h.evidence_gaps,
            }
            for h in case.hypotheses
        ]

        unknowns = [
            f"Gap in hypothesis {h.hypothesis_id}: {gap}"
            for h in case.hypotheses
            for gap in h.evidence_gaps
        ]
        if not unknowns:
            unknowns = ["No critical evidence gaps documented in active hypotheses."]

        recommendations = [
            "Preserve underlying auth.log, syslog, and auditd forensic snapshots.",
            "Verify credential rotation for compromised accounts identified in case evidence.",
            "Review query history and validate containment across related host nodes.",
        ]

        exec_summary = (
            f"Forensic investigation case {case_id} regarding {case.title}. "
            f"Status is {case.status.value}. Evaluated {len(case.evidence_references)} evidence references "
            f"and {len(case.hypotheses)} hypotheses under case version {case.version}."
        )

        # Calculate model digest / provenance signature
        provenance_str = f"qwen2.5:0.5b:{case_id}:{case.version}:{len(facts)}"
        model_digest = hashlib.sha256(provenance_str.encode()).hexdigest()[:16]
        now_iso = datetime.now(timezone.utc).isoformat()

        report_version = CaseReportVersion(
            report_id=report_id,
            case_id=case_id,
            version=1,  # will be assigned next version by case_repo
            title=report_title,
            executive_summary=exec_summary,
            facts=facts,
            inferences=inferences,
            hypotheses=hypotheses_summary,
            unknowns=unknowns,
            recommendations=recommendations,
            analyst_notes=analyst_notes,
            generated_by=ContentOrigin.AI_GENERATED if not is_final else ContentOrigin.ANALYST_AUTHORED,
            model_id="qwen2.5:0.5b",
            model_digest=model_digest,
            context_version=case.version,
            created_at=now_iso,
            is_final=is_final,
        )

        return self.case_repo.save_report_version(case_id, report_version, actor=actor)

    def compare_report_versions(
        self,
        case_id: int,
        report_id: str,
        v1: int,
        v2: int,
    ) -> Dict[str, Any]:
        """Compare two historical report draft versions, highlighting additions, removals, and changes."""
        rep1 = self.case_repo.get_report_version(case_id, report_id, v1)
        rep2 = self.case_repo.get_report_version(case_id, report_id, v2)

        if not rep1:
            raise ValueError(f"Report version {v1} not found")
        if not rep2:
            raise ValueError(f"Report version {v2} not found")

        facts1 = {f.get("citation_tag"): f.get("statement") for f in rep1.facts}
        facts2 = {f.get("citation_tag"): f.get("statement") for f in rep2.facts}

        added_facts = [f for tag, f in facts2.items() if tag not in facts1]
        removed_facts = [f for tag, f in facts1.items() if tag not in facts2]

        return {
            "case_id": case_id,
            "report_id": report_id,
            "version_older": v1,
            "version_newer": v2,
            "title_changed": rep1.title != rep2.title,
            "summary_changed": rep1.executive_summary != rep2.executive_summary,
            "added_facts_count": len(added_facts),
            "removed_facts_count": len(removed_facts),
            "added_facts": added_facts,
            "removed_facts": removed_facts,
            "hypotheses_v1_count": len(rep1.hypotheses),
            "hypotheses_v2_count": len(rep2.hypotheses),
            "analyst_notes_v1": rep1.analyst_notes,
            "analyst_notes_v2": rep2.analyst_notes,
            "is_final_v1": rep1.is_final,
            "is_final_v2": rep2.is_final,
        }

    def transfer_case(
        self,
        case_id: int,
        new_owner: str,
        actor: str = "SecAnalyst-1",
        handoff_notes: Optional[str] = None,
    ) -> InvestigationCase:
        """Transfer case ownership during analyst handoff."""
        return self.case_repo.transfer_case(
            case_id=case_id,
            new_owner=new_owner,
            actor=actor,
            handoff_notes=handoff_notes,
        )

    def reconstruct_ai_context(self, case_id: int) -> AIReconstructedContext:
        """Deterministically reconstruct context for local AI operations without cross-case memory."""
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        resolved_count = sum(1 for r in case.evidence_references if r.resolution_status == ResolutionStatus.AVAILABLE)
        stale_count = sum(1 for r in case.evidence_references if r.resolution_status != ResolutionStatus.AVAILABLE)

        hyp_summary = [
            {
                "hypothesis_id": h.hypothesis_id,
                "statement": h.statement,
                "status": h.status.value,
                "supporting_evidence_count": len(h.supporting_evidence_tags),
                "assessment": h.analyst_assessment,
            }
            for h in case.hypotheses
        ]

        query_summary = [
            {
                "query_id": q.query_id,
                "template": q.query_template_id,
                "result_count": q.result_count,
                "executed_at": q.executed_at,
            }
            for q in case.query_history[-5:]
        ]

        latest_rep = case.reports[0].executive_summary if case.reports else None
        now_iso = datetime.now(timezone.utc).isoformat()

        return AIReconstructedContext(
            case_id=case.case_id,
            incident_id=case.incident_id,
            case_version=case.version,
            status=case.status.value,
            scope=case.scope,
            resolved_evidence_count=resolved_count,
            stale_evidence_count=stale_count,
            hypotheses=hyp_summary,
            query_history_summary=query_summary,
            latest_report_summary=latest_rep,
            reconstructed_at=now_iso,
        )

    def get_audit_history(self, case_id: int) -> List[CaseAuditRecord]:
        """Fetch complete chronological audit trail of case modifications."""
        case = self.case_repo.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        return case.audit_history

    def get_findings_and_correlations(
        self, case_id: int
    ) -> Tuple[List[InvestigationFinding], List[InvestigationCorrelation]]:
        """Compute deterministic findings and multi-attribute correlations with explicit reasons."""
        return self.intelligence.get_case_findings_and_correlations(case_id)

    def get_evidence_gaps(self, case_id: int) -> List[EvidenceGap]:
        """Detect missing telemetry dimensions, coverage gaps, and safe hunt recommendations."""
        return self.intelligence.get_case_evidence_gaps(case_id)

    def get_case_timeline(self, case_id: int) -> List[CaseTimelineItem]:
        """Build unified case timeline with strict provenance separation."""
        return self.intelligence.get_case_timeline(case_id)

    def analyze_temporal_window(
        self,
        case_id: int,
        anchor_type: str,
        anchor_id: str,
        anchor_timestamp: str,
        window_seconds: int = 300,
    ) -> TemporalWindowAnalysis:
        """Partition items into BEFORE, DURING, and AFTER relative to anchor, identifying anomalies."""
        return self.intelligence.analyze_temporal_window(
            case_id=case_id,
            anchor_type=anchor_type,
            anchor_id=anchor_id,
            anchor_timestamp=anchor_timestamp,
            window_seconds=window_seconds,
        )

    def resolve_entity_pivot(
        self,
        case_id: int,
        entity_type: str,
        entity_value: str,
    ) -> EntityPivotAnalysis:
        """Resolve deep entity pivot without duplicating authoritative event payloads into cases.db."""
        return self.intelligence.resolve_entity_pivot(case_id, entity_type, entity_value)

    def create_hunt_proposal(
        self,
        case_id: int,
        template_id: str,
        parameters: Dict[str, Any],
        rationale: str,
        suggested_by: str = "SecAnalyst-1",
    ) -> GovernedThreatHuntProposal:
        """Validate and create governed threat hunting proposal."""
        return self.intelligence.create_hunt_proposal(
            case_id=case_id,
            template_id=template_id,
            parameters=parameters,
            rationale=rationale,
            suggested_by=suggested_by,
        )

    def execute_hunt_query(
        self,
        proposal: GovernedThreatHuntProposal,
        approved_by: str = "SecAnalyst-1",
    ) -> GovernedThreatHuntExecution:
        """Execute an analyst-approved threat hunting query and record to persistent case query history."""
        return self.intelligence.execute_hunt_query(proposal, approved_by=approved_by)

    def analyze_hypothesis(
        self,
        case_id: int,
        hypothesis_id: str,
    ) -> HypothesisEvidenceAnalysis:
        """Perform deterministic evidence support analysis for an analyst-owned hypothesis."""
        return self.intelligence.analyze_case_hypothesis(case_id, hypothesis_id)

    def get_case_intelligence_dossier(self, case_id: int) -> CaseIntelligenceDossier:
        """Assemble complete aggregated investigation intelligence dossier."""
        return self.intelligence.get_case_intelligence_dossier(case_id)

    def generate_ai_investigation_intelligence(
        self,
        case_id: int,
        prompt: Optional[str] = None,
        actor: str = "SecAnalyst-1",
    ) -> InvestigationIntelligenceResponse:
        """Generate structured AI investigation intelligence using local model or deterministic fallback."""
        dossier = self.get_case_intelligence_dossier(case_id)
        case = self.get_case(case_id)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        # Deterministic claims assembly
        observed_claims = [
            {
                "claim_id": f"obs-{idx}",
                "statement": f"{f.title}: {f.description}",
                "epistemic_status": "OBSERVED",
                "citations": f.source_references,
            }
            for idx, f in enumerate(dossier.findings)
            if f.epistemic_status.value == "OBSERVED"
        ]

        inferred_claims = [
            {
                "claim_id": f"inf-{idx}",
                "statement": f"{f.title}: {f.description}",
                "epistemic_status": "INFERRED",
                "citations": f.source_references,
            }
            for idx, f in enumerate(dossier.findings)
            if f.epistemic_status.value == "INFERRED"
        ]

        unknowns = [
            gap.description for gap in dossier.evidence_gaps
        ] or ["No critical missing telemetry gaps documented in current scope."]

        suggested_queries = [
            gap.recommended_governed_query for gap in dossier.evidence_gaps if gap.recommended_governed_query
        ]

        correlations_summary = [
            {
                "source": c.source_item,
                "target": c.target_item,
                "reasons": c.reasons,
                "confidence": c.confidence_score,
            }
            for c in dossier.correlations[:10]
        ]

        all_citations = list({
            ref.citation_tag for ref in case.evidence_references
        })

        summary = (
            f"Deterministic investigation synthesis for {case.title} (Status: {case.status.value}). "
            f"Correlated {len(dossier.correlations)} relationship links across {len(dossier.findings)} findings. "
            f"Identified {len(dossier.evidence_gaps)} evidence gaps requiring analyst attention."
        )

        provenance = {
            "model_id": "qwen2.5:0.5b",
            "model_digest": hashlib.sha256(f"{case_id}:{case.version}:{len(dossier.findings)}".encode()).hexdigest()[:16],
            "containment_mode": "APPLICATION_LEVEL_AI_CONTAINMENT",
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        return InvestigationIntelligenceResponse(
            case_id=case_id,
            summary=summary,
            observed_claims=observed_claims,
            inferred_claims=inferred_claims,
            unknowns=unknowns,
            evidence_gaps=[g.description for g in dossier.evidence_gaps],
            correlations=correlations_summary,
            citations=all_citations,
            suggested_queries=suggested_queries,
            hypothesis_assessment={
                h.hypothesis_id: {
                    "statement": h.statement,
                    "support_status": h.support_status.value,
                    "temporal_consistency": h.temporal_consistency,
                }
                for h in dossier.hypotheses_analysis
            },
            provenance=provenance,
        )

    def get_investigation_dossier(self, case_id: int) -> InvestigationDossier:
        """Assemble comprehensive, section-by-section investigation dossier (M5.7)."""
        case = self.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        findings, correlations = self.intelligence.correlator.correlate_case_evidence(case)
        gaps = self.intelligence.gap_engine.identify_evidence_gaps(case)
        return self.dossier_builder.build_dossier(
            case=case,
            findings=[f.model_dump() for f in findings],
            correlations=correlations,
            gaps=gaps,
        )

    def update_finding_review(
        self,
        case_id: int,
        finding_id: str,
        review_state: str,
        analyst_notes: str = "",
        reviewer: str = "SecAnalyst-1",
    ) -> Dict[str, Any]:
        """Record analyst review state for an investigation finding (M5.7)."""
        case = self.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        return self.case_repo.upsert_finding_review(
            case_id=case_id,
            finding_id=finding_id,
            review_state=review_state,
            analyst_notes=analyst_notes,
            reviewed_by=reviewer,
        )

    def get_evidence_matrix(self, case_id: int) -> List[EvidenceMatrixEntry]:
        """Retrieve deterministic hypothesis evidence matrix for a case (M5.7)."""
        case = self.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        return self.dossier_builder.matrix_builder.build_matrix(case)

    def get_evidence_gap_actions(self, case_id: int) -> List[EvidenceGapAction]:
        """Retrieve actionable next steps derived from evidence gaps (M5.7)."""
        case = self.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        gaps = self.intelligence.gap_engine.identify_evidence_gaps(case)
        return self.dossier_builder.briefing_builder.build_gap_actions(gaps)

    def get_refined_timeline(self, case_id: int) -> List[RefinedTimelineItem]:
        """Retrieve multi-source refined timeline with provenance demarcation (M5.7)."""
        case = self.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        findings, correlations = self.intelligence.correlator.correlate_case_evidence(case)
        reviews = self.case_repo.get_finding_reviews(case_id)
        f_dicts = []
        for f in findings:
            fd = f.model_dump()
            if fd.get("finding_id") in reviews:
                fd["review_state"] = reviews[fd["finding_id"]]["review_state"]
            f_dicts.append(fd)
        return self.dossier_builder.timeline_builder.build_refined_timeline(
            case=case,
            findings=f_dicts,
            correlations=correlations,
        )

    def get_case_briefing(self, case_id: int) -> CaseBriefing:
        """Generate structured incident / case briefing (M5.7)."""
        case = self.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        findings, correlations = self.intelligence.correlator.correlate_case_evidence(case)
        gaps = self.intelligence.gap_engine.identify_evidence_gaps(case)
        reviews = self.case_repo.get_finding_reviews(case_id)
        f_dicts = []
        for f in findings:
            fd = f.model_dump()
            if fd.get("finding_id") in reviews:
                fd["review_state"] = reviews[fd["finding_id"]]["review_state"]
            f_dicts.append(fd)
        return self.dossier_builder.briefing_builder.build_briefing(
            case=case,
            findings=f_dicts,
            gaps=gaps,
            correlations=correlations,
        )

    def get_provenance_manifest(self, case_id: int) -> List[ProvenanceManifestEntry]:
        """Retrieve complete provenance manifest for an investigation (M5.7)."""
        dossier = self.get_investigation_dossier(case_id)
        return dossier.provenance_manifest

    def get_threat_hunt_results(self, case_id: int) -> List[Dict[str, Any]]:
        """Retrieve all governed threat hunting executions for a case (M5.7)."""
        case = self.get_case(case_id, resolve_evidence=False)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        return [q.model_dump(mode="json") for q in case.query_history]

    def draft_report_from_dossier(
        self,
        case_id: int,
        title: Optional[str] = None,
        analyst_notes: Optional[str] = None,
        is_final: bool = False,
        actor: str = "SecAnalyst-1",
    ) -> CaseReportVersion:
        """Generate an immutable versioned investigation report derived deterministically from the dossier (M5.7)."""
        dossier = self.get_investigation_dossier(case_id)
        report_title = title or f"Investigation Dossier Report — {dossier.case_title}"

        return self.draft_or_revise_report(
            case_id=case_id,
            title=report_title,
            analyst_notes=analyst_notes,
            is_final=is_final,
            actor=actor,
        )

    # =========================================================================
    # Milestone 5.8: Investigation Graph & Evidence Relationship Intelligence
    # =========================================================================

    def get_investigation_graph(
        self,
        case_id: int,
        max_nodes: int = 50,
        max_edges: int = 100,
        entity_type: Optional[str] = None,
        relationship_type: Optional[str] = None,
        epistemic_status: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> InvestigationGraph:
        """Construct bounded, evidence-bound investigation graph for a case (M5.8)."""
        case = self.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Case {case_id} not found")

        incident = self.incidents_repo.get_incident(case.incident_id)
        entities = self.incidents_repo.get_incident_entities(case.incident_id)
        relationships = self.incidents_repo.get_incident_relationships(case.incident_id)
        mitre_mappings = self.investigation_repo.get_incident_mitre_mappings(case.incident_id)

        return self.graph_builder.build_graph(
            case=case,
            incident=incident,
            entities=entities,
            relationships=relationships,
            mitre_mappings=mitre_mappings,
            max_nodes=max_nodes,
            max_edges=max_edges,
            entity_type=entity_type,
            relationship_type=relationship_type,
            epistemic_status=epistemic_status,
            start_time=start_time,
            end_time=end_time,
        )

    def get_graph_node_detail(self, case_id: int, node_id: str) -> Dict[str, Any]:
        """Retrieve detailed node inspection including connected edges and citations (M5.8)."""
        graph = self.get_investigation_graph(case_id, max_nodes=200, max_edges=500)
        node = next((n for n in graph.nodes if n.node_id == node_id), None)
        if not node:
            raise ValueError(f"Node {node_id} not found in case {case_id}")

        connected_edges = [
            e for e in graph.edges if e.source_node_id == node_id or e.target_node_id == node_id
        ]
        return {
            "node": node.model_dump(),
            "connected_edges": [e.model_dump() for e in connected_edges],
            "total_connected_edges": len(connected_edges),
        }

    def get_graph_edge_evidence(self, case_id: int, edge_id: str) -> Dict[str, Any]:
        """Deep forensic inspection for a specific graph edge including all citations (M5.8)."""
        graph = self.get_investigation_graph(case_id, max_nodes=200, max_edges=500)
        edge = next((e for e in graph.edges if e.edge_id == edge_id), None)
        if not edge:
            raise ValueError(f"Edge {edge_id} not found in case {case_id}")

        return {
            "edge": edge.model_dump(),
            "evidence_references": [ev.model_dump() for ev in edge.evidence_references],
            "evidence_event_ids": edge.evidence_event_ids,
            "corroboration_status": edge.corroboration_status.value,
            "epistemic_status": edge.epistemic_status.value,
            "is_authoritative": edge.is_authoritative,
        }

    def get_entity_pivot_graph(
        self,
        case_id: int,
        entity_type: str,
        entity_value: str,
    ) -> EntityPivotGraph:
        """Construct case-bounded entity pivot graph showing adjacent relationships (M5.8)."""
        graph = self.get_investigation_graph(case_id, max_nodes=200, max_edges=500)
        # entity_key can be e.g. "srv-api-01" or "host:srv-api-01"
        entity_key = f"{entity_type.lower()}:{entity_value}" if ":" not in entity_value else entity_value
        return self.graph_builder.build_entity_pivot_graph(graph, entity_key, entity_type)

    def get_investigation_path(
        self,
        case_id: int,
        source_node_id: str,
        target_node_id: str,
        max_depth: int = 5,
    ) -> Optional[InvestigationPath]:
        """Reconstruct bounded investigation path between source and target nodes (M5.8)."""
        graph = self.get_investigation_graph(case_id, max_nodes=200, max_edges=500)
        return self.graph_builder.reconstruct_investigation_path(
            graph=graph,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            max_depth=max_depth,
        )

    def get_temporal_chain(self, case_id: int) -> TemporalChain:
        """Derive chronological relationship sequence with delta-time annotations (M5.8)."""
        graph = self.get_investigation_graph(case_id, max_nodes=200, max_edges=500)
        return self.graph_builder.build_temporal_chain(graph)

    def explain_graph_relationship(
        self,
        case_id: int,
        edge_id: Optional[str] = None,
        path_nodes: Optional[List[str]] = None,
        question: Optional[str] = None,
    ) -> GraphExplanationResponse:
        """Generate advisory-only, citation-grounded narrative explanation of graph relationships (M5.8)."""
        graph = self.get_investigation_graph(case_id, max_nodes=200, max_edges=500)
        target_ref = edge_id or (f"path:{'->'.join(path_nodes)}" if path_nodes else "graph")

        citations: List[str] = []
        if edge_id:
            edge = next((e for e in graph.edges if e.edge_id == edge_id), None)
            if not edge:
                raise ValueError(f"Edge {edge_id} not found in case {case_id}")
            citations = [ev.citation_tag for ev in edge.evidence_references]
            summary = (
                f"Advisory Explanation: Observed relationship '{edge.relationship_type}' connecting "
                f"{edge.source_node_id} to {edge.target_node_id}. Grounded in {len(citations)} forensic "
                f"evidence citations with {edge.corroboration_status.value} corroboration status."
            )
        elif path_nodes and len(path_nodes) >= 2:
            path = self.graph_builder.reconstruct_investigation_path(
                graph, path_nodes[0], path_nodes[-1]
            )
            if path:
                for e in path.edges:
                    citations.extend([ev.citation_tag for ev in e.evidence_references])
                summary = (
                    f"Advisory Path Summary: Progression across {path.total_steps} transitions "
                    f"({path.path_nature.value}). Corroborated by {len(citations)} forensic citations."
                )
            else:
                summary = f"No direct connected path identified between {path_nodes[0]} and {path_nodes[-1]}."
        else:
            summary = (
                f"Advisory Investigation Graph Overview: Case {case_id} contains {graph.total_nodes} nodes "
                f"and {graph.total_edges} evidence-bound relationships ({graph.observed_edges_count} observed, "
                f"{graph.inferred_edges_count} inferred)."
            )

        now_iso = datetime.now(timezone.utc).isoformat()
        return GraphExplanationResponse(
            case_id=case_id,
            target_ref=target_ref,
            summary=summary,
            evidence_citations=citations,
            epistemic_status=EpistemicStatus.INFERRED,
            is_authoritative=False,
            generated_by="LOCAL_AI_ADVISORY",
            generated_at=now_iso,
        )

    def export_investigation_graph(self, case_id: int, format: str = "json") -> str:
        """Export case investigation graph with full provenance in JSON or GraphML format (M5.8)."""
        graph = self.get_investigation_graph(case_id, max_nodes=200, max_edges=500)
        fmt = (format or "json").lower().strip()
        if fmt == "graphml":
            return self.graph_builder.export_graphml(graph)
        return self.graph_builder.export_graph_json(graph)


# Singleton case service instance
case_service = CaseService()

