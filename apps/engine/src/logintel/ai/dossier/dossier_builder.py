"""Investigation Dossier Builder for LogIntel Milestone 5.7.

Assembles comprehensive, section-by-section investigation dossiers from persistent case state,
authoritative forensic references, deterministic correlations, hypothesis evidence matrices,
and full provenance tracking.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from logintel.ai.domain.case import InvestigationCase
from logintel.ai.domain.investigation_dossier import (
    FindingReviewState,
    InvestigationDossier,
)
from logintel.ai.dossier.briefing_builder import BriefingBuilder
from logintel.ai.dossier.evidence_matrix_builder import EvidenceMatrixBuilder
from logintel.ai.dossier.provenance_tracker import ProvenanceTracker
from logintel.ai.dossier.refined_timeline_builder import RefinedTimelineBuilder
from logintel.storage.case_repo import CaseRepository
from logintel.storage.db import Database
from logintel.storage.investigation_repo import InvestigationRepository


class DossierBuilder:
    """Orchestrates assembly of the investigation dossier."""

    def __init__(
        self,
        forensic_db: Database,
        case_repo: CaseRepository,
        investigation_repo: Optional[InvestigationRepository] = None,
    ) -> None:
        self.forensic_db = forensic_db
        self.case_repo = case_repo
        self.investigation_repo = investigation_repo or InvestigationRepository(forensic_db)
        self.timeline_builder = RefinedTimelineBuilder(forensic_db)
        self.matrix_builder = EvidenceMatrixBuilder()
        self.briefing_builder = BriefingBuilder()
        self.provenance_tracker = ProvenanceTracker()

    def build_dossier(
        self,
        case: InvestigationCase,
        findings: List[Dict[str, Any]],
        correlations: List[Any],
        gaps: List[Any],
        ai_interpretation: Optional[Dict[str, Any]] = None,
    ) -> InvestigationDossier:
        """Assemble full investigation dossier with review states and provenance manifest."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Fetch persisted finding review states
        review_records = self.case_repo.get_finding_reviews(case.case_id)
        enriched_findings: List[Dict[str, Any]] = []
        review_summary: Dict[str, int] = {
            FindingReviewState.UNREVIEWED.value: 0,
            FindingReviewState.UNDER_REVIEW.value: 0,
            FindingReviewState.ACCEPTED.value: 0,
            FindingReviewState.REJECTED.value: 0,
            FindingReviewState.NEEDS_MORE_EVIDENCE.value: 0,
        }

        for f in findings:
            f_dict = dict(f) if isinstance(f, dict) else f.model_dump()
            f_id = f_dict.get("finding_id", "")
            rev = review_records.get(f_id)
            if rev:
                f_dict["review_state"] = rev["review_state"]
                f_dict["analyst_review_notes"] = rev["analyst_notes"]
                f_dict["reviewed_by"] = rev["reviewed_by"]
                f_dict["reviewed_at"] = rev["reviewed_at"]
            else:
                f_dict.setdefault("review_state", FindingReviewState.UNREVIEWED.value)
                f_dict.setdefault("analyst_review_notes", "")
                f_dict.setdefault("reviewed_by", None)
                f_dict.setdefault("reviewed_at", None)

            st = f_dict["review_state"]
            review_summary[st] = review_summary.get(st, 0) + 1
            enriched_findings.append(f_dict)

        # 2. Build Refined Timeline
        timeline = self.timeline_builder.build_refined_timeline(
            case=case,
            findings=enriched_findings,
            correlations=correlations,
            ai_interpretations=[ai_interpretation] if ai_interpretation else None,
        )

        # 3. Build Evidence Matrix
        matrix = self.matrix_builder.build_matrix(case)

        # 4. Build Evidence Gap Actions
        gap_actions = self.briefing_builder.build_gap_actions(gaps)

        # 5. Extract Entities from case references and incident entities
        entities: List[Dict[str, Any]] = []
        try:
            with self.forensic_db.connection() as conn:
                ent_rows = conn.execute(
                    "SELECT entity_type, entity_key, display_name FROM incident_entities WHERE incident_id = ?",
                    (case.incident_id,),
                ).fetchall()
                entities = [dict(r) for r in ent_rows]
        except Exception:
            pass

        # 6. Extract Threat Hunting Results from case query history
        hunting_results: List[Dict[str, Any]] = [
            q.model_dump(mode="json") for q in case.query_history
        ]

        # 7. Extract Attack Path Steps and MITRE Techniques
        attack_steps: List[Any] = []
        mitre_techniques: List[Dict[str, Any]] = []
        try:
            mappings = self.investigation_repo.get_incident_mitre_mappings(case.incident_id)
            mitre_techniques = [m.model_dump() for m in mappings]
        except Exception:
            pass

        # 8. Analyst Notes from persistent evidence or case reports
        analyst_notes: List[Dict[str, Any]] = []
        for ref in case.evidence_references:
            if ref.analyst_annotation:
                analyst_notes.append({
                    "citation_tag": ref.citation_tag,
                    "source_id": ref.source_id,
                    "annotation": ref.analyst_annotation,
                    "created_at": ref.created_at,
                })

        # 9. Build Comprehensive Provenance Manifest
        manifest = self.provenance_tracker.build_manifest(
            case=case,
            findings=enriched_findings,
            timeline=timeline,
            matrix=matrix,
            correlations=correlations,
        )

        # Evidence Summary Metrics
        evidence_summary = {
            "total_references": len(case.evidence_references),
            "events_count": sum(1 for r in case.evidence_references if r.source_type == "event"),
            "alerts_count": sum(1 for r in case.evidence_references if r.source_type == "alert"),
            "detections_count": sum(1 for r in case.evidence_references if r.source_type == "detection"),
            "hypotheses_count": len(case.hypotheses),
            "executed_hunts_count": len(case.query_history),
        }

        return InvestigationDossier(
            case_id=case.case_id,
            incident_id=case.incident_id,
            case_title=case.title,
            status=case.status.value,
            owner=case.owner,
            created_at=case.created_at,
            scope={
                "time_start": case.scope.time_start if case.scope else None,
                "time_end": case.scope.time_end if case.scope else None,
                "subject_type": case.scope.subject_type if case.scope else "incident",
                "subject_id": case.scope.subject_id if case.scope else str(case.incident_id),
                "selected_entity_ids": case.scope.selected_entity_ids if case.scope else [],
            },
            findings=enriched_findings,
            evidence_summary=evidence_summary,
            timeline=timeline,
            entities=entities,
            correlations=correlations,
            evidence_gaps=gap_actions,
            evidence_matrix=matrix,
            threat_hunting_results=hunting_results,
            attack_path_steps=attack_steps,
            mitre_mappings=mitre_techniques,
            analyst_notes=analyst_notes,
            ai_interpretation=ai_interpretation,
            review_state_summary=review_summary,
            provenance_manifest=manifest,
            generated_at=now_iso,
        )
