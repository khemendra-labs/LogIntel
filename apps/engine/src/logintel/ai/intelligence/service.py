"""Unified Investigation Intelligence Service for LogIntel M5.6.

Coordinates deterministic correlation, temporal analysis, evidence gap analysis,
governed threat hunting, entity pivots, unified timelines, hypothesis scoring,
attack path classification, and MITRE mapping traceability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
import uuid

from logintel.ai.domain.case import InvestigationCase
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
    TemporalWindowAnalysis,
)
from logintel.ai.intelligence.correlator import DeterministicCorrelator
from logintel.ai.intelligence.gaps import EvidenceGapEngine
from logintel.ai.intelligence.hunting import GovernedThreatHuntManager
from logintel.ai.intelligence.hypotheses_analyzer import HypothesisEvidenceAnalyzer
from logintel.ai.intelligence.pivots import EntityPivotResolver
from logintel.ai.intelligence.temporal import TemporalIntelligenceEngine
from logintel.ai.intelligence.timeline import CaseTimelineBuilder
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database, db as default_db
from logintel.storage.investigation_repo import InvestigationRepository


class InvestigationIntelligenceService:
    """Master service providing deterministic investigation intelligence."""

    def __init__(
        self,
        database: Optional[Database] = None,
        case_repository: Optional[CaseRepository] = None,
        investigation_repository: Optional[InvestigationRepository] = None,
    ) -> None:
        self.db = database or default_db
        self.case_repo = case_repository or CaseRepository(forensic_db=self.db)
        self.investigation_repo = investigation_repository or InvestigationRepository(database=self.db)

        self.correlator = DeterministicCorrelator()
        self.temporal_engine = TemporalIntelligenceEngine()
        self.gap_engine = EvidenceGapEngine()
        self.hunt_manager = GovernedThreatHuntManager(database=self.db)
        self.pivot_resolver = EntityPivotResolver(database=self.db, case_repository=self.case_repo)
        self.timeline_builder = CaseTimelineBuilder(database=self.db)
        self.hypothesis_analyzer = HypothesisEvidenceAnalyzer()

    def get_case_findings_and_correlations(
        self,
        case_id: int,
    ) -> Tuple[List[InvestigationFinding], List[InvestigationCorrelation]]:
        """Compute deterministic findings and correlations for a case."""
        case = self._require_case(case_id)
        return self.correlator.correlate_case_evidence(case)

    def get_case_evidence_gaps(self, case_id: int) -> List[EvidenceGap]:
        """Detect missing telemetry and evidence gaps for a case."""
        case = self._require_case(case_id)
        return self.gap_engine.identify_evidence_gaps(case)

    def get_case_timeline(self, case_id: int) -> List[CaseTimelineItem]:
        """Build unified case timeline with provenance classification."""
        case = self._require_case(case_id)
        _, corrs = self.correlator.correlate_case_evidence(case)
        return self.timeline_builder.build_case_timeline(case, correlations=corrs)

    def analyze_temporal_window(
        self,
        case_id: int,
        anchor_type: str,
        anchor_id: str,
        anchor_timestamp: str,
        window_seconds: int = 300,
    ) -> TemporalWindowAnalysis:
        """Analyze BEFORE, DURING, and AFTER time windows around an investigation anchor."""
        case = self._require_case(case_id)
        # Collect candidate items from case evidence and recent incident events
        items: List[Dict[str, Any]] = []
        for ref in case.evidence_references:
            if ref.resolved_record:
                items.append(dict(ref.resolved_record))

        return self.temporal_engine.analyze_temporal_window(
            case_id=case_id,
            anchor_type=anchor_type,
            anchor_id=anchor_id,
            anchor_timestamp=anchor_timestamp,
            items=items,
            window_seconds=window_seconds,
        )

    def resolve_entity_pivot(
        self,
        case_id: int,
        entity_type: str,
        entity_value: str,
    ) -> EntityPivotAnalysis:
        """Execute deep entity pivot without duplicating payloads in cases.db."""
        self._require_case(case_id)
        return self.pivot_resolver.resolve_entity_pivot(case_id, entity_type, entity_value)

    def create_hunt_proposal(
        self,
        case_id: int,
        template_id: str,
        parameters: Dict[str, Any],
        rationale: str,
        suggested_by: str = "SecAnalyst-1",
    ) -> GovernedThreatHuntProposal:
        """Validate and create governed threat hunt proposal."""
        self._require_case(case_id)
        return self.hunt_manager.create_proposal(
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
        """Execute analyst-approved threat hunting query and log to case query history."""
        self._require_case(proposal.case_id)
        execution = self.hunt_manager.execute_hunt(proposal, approved_by=approved_by)

        # Log query to persistent case query history
        from logintel.ai.domain.case import CaseQueryRecord
        now_iso = datetime.now(timezone.utc).isoformat()
        q_record = CaseQueryRecord(
            query_id=f"q-{proposal.case_id}-{uuid.uuid4().hex[:12]}",
            case_id=proposal.case_id,
            proposal_id=proposal.proposal_id,
            query_template_id=proposal.template_id,
            parameters=proposal.parameters,
            rationale=proposal.rationale,
            executed_by=approved_by,
            executed_at=now_iso,
            result_count=execution.result_count,
            execution_status=execution.result_status.value,
            evidence_candidates_count=len(execution.candidate_findings),
        )
        self.case_repo.record_query(proposal.case_id, q_record)

        return execution

    def analyze_case_hypothesis(
        self,
        case_id: int,
        hypothesis_id: str,
    ) -> HypothesisEvidenceAnalysis:
        """Evaluate deterministic evidence support for a hypothesis."""
        case = self._require_case(case_id)
        return self.hypothesis_analyzer.analyze_hypothesis(case, hypothesis_id)

    def get_attack_path_analysis(self, incident_id: int) -> List[AttackPathStepAnalysis]:
        """Integrate M4/M5 attack path reconstruction with explicit epistemic labels."""
        reconstruction = self.investigation_repo.reconstruct_attack_path(incident_id)
        steps: List[AttackPathStepAnalysis] = []

        for step in reconstruction.steps:
            # Differentiate observed steps vs inferred steps
            is_observed = getattr(step, "nature", None) == "OBSERVED" or bool(step.supporting_event_ids)
            epistemic = EpistemicStatus.OBSERVED if is_observed else EpistemicStatus.INFERRED
            supp = [f"[event:{eid}]" for eid in (step.supporting_event_ids or [])]

            steps.append(
                AttackPathStepAnalysis(
                    step_number=step.step_number,
                    stage=step.stage,
                    description=step.description,
                    epistemic_status=epistemic,
                    supporting_evidence=supp,
                    mitre_technique_id=getattr(step, "technique_id", None),
                    mitre_technique_name=getattr(step, "technique_name", None),
                )
            )

        return steps

    def get_case_intelligence_dossier(self, case_id: int) -> CaseIntelligenceDossier:
        """Assemble complete aggregated investigation intelligence dossier."""
        case = self._require_case(case_id)
        now_iso = datetime.now(timezone.utc).isoformat()

        findings, correlations = self.correlator.correlate_case_evidence(case)
        gaps = self.gap_engine.identify_evidence_gaps(case)
        timeline = self.timeline_builder.build_case_timeline(case, correlations=correlations)

        hyp_analyses = [
            self.hypothesis_analyzer.analyze_hypothesis(case, h.hypothesis_id)
            for h in case.hypotheses
        ]

        attack_steps = self.get_attack_path_analysis(case.incident_id)
        mitre_mappings = [
            m.model_dump() for m in self.investigation_repo.get_incident_mitre_mappings(case.incident_id)
        ]

        return CaseIntelligenceDossier(
            case_id=case.case_id,
            incident_id=case.incident_id,
            case_title=case.title,
            status=case.status.value,
            owner=case.owner,
            findings=findings,
            correlations=correlations,
            evidence_gaps=gaps,
            timeline=timeline,
            hypotheses_analysis=hyp_analyses,
            attack_path_steps=attack_steps,
            mitre_mappings=mitre_mappings,
            generated_at=now_iso,
        )

    def _require_case(self, case_id: int) -> InvestigationCase:
        case = self.case_repo.get_case(case_id, resolve_evidence=True)
        if not case:
            raise ValueError(f"Case {case_id} not found")
        return case
