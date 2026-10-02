"""Hypothesis Evidence Support Analysis Engine for LogIntel M5.6.

Provides deterministic analysis of evidence support, contradictions, and gaps for
analyst-owned hypotheses without automatically altering analyst-decided statuses.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from logintel.ai.domain.case import CaseHypothesis, InvestigationCase, ResolutionStatus
from logintel.ai.domain.intelligence import QueryProposal
from logintel.ai.domain.investigation_intel import (
    HypothesisEvidenceAnalysis,
    HypothesisSupportStatus,
)


class HypothesisEvidenceAnalyzer:
    """Analyzes evidence corroboration for analyst hypotheses."""

    def analyze_hypothesis(
        self,
        case: InvestigationCase,
        hypothesis_id: str,
    ) -> HypothesisEvidenceAnalysis:
        """Evaluate deterministic evidence support for a specific hypothesis."""
        hyp = next((h for h in case.hypotheses if h.hypothesis_id == hypothesis_id), None)
        if not hyp:
            raise ValueError(f"Hypothesis '{hypothesis_id}' not found in case {case.case_id}")

        # Resolve supporting evidence references
        supporting_items: List[Dict[str, Any]] = []
        for tag in hyp.supporting_evidence_tags:
            ref = next((r for r in case.evidence_references if r.citation_tag == tag), None)
            if ref and ref.resolution_status == ResolutionStatus.AVAILABLE:
                supporting_items.append({
                    "citation_tag": tag,
                    "source_type": ref.source_type,
                    "source_id": ref.source_id,
                    "status": "AVAILABLE",
                    "summary": (ref.resolved_record or {}).get("summary", "Resolved record"),
                })
            elif ref:
                supporting_items.append({
                    "citation_tag": tag,
                    "source_type": ref.source_type,
                    "source_id": ref.source_id,
                    "status": ref.resolution_status.value,
                    "summary": "Evidence record unavailable or missing from forensic store",
                })
            else:
                supporting_items.append({
                    "citation_tag": tag,
                    "status": "UNRESOLVED_REFERENCE",
                    "summary": f"Tag {tag} has no matching case evidence reference",
                })

        # Resolve contradicting evidence references
        contradicting_items: List[Dict[str, Any]] = []
        for tag in hyp.contradicting_evidence_tags:
            ref = next((r for r in case.evidence_references if r.citation_tag == tag), None)
            if ref and ref.resolution_status == ResolutionStatus.AVAILABLE:
                contradicting_items.append({
                    "citation_tag": tag,
                    "source_type": ref.source_type,
                    "source_id": ref.source_id,
                    "status": "AVAILABLE",
                    "summary": (ref.resolved_record or {}).get("summary", "Contradicting record"),
                })
            elif ref:
                contradicting_items.append({
                    "citation_tag": tag,
                    "source_type": ref.source_type,
                    "source_id": ref.source_id,
                    "status": ref.resolution_status.value,
                    "summary": "Contradicting record unresolved",
                })
            else:
                contradicting_items.append({
                    "citation_tag": tag,
                    "status": "UNRESOLVED_REFERENCE",
                    "summary": f"Tag {tag} has no matching case evidence reference",
                })

        # Determine evidence-backed support status
        available_supporting = len([s for s in supporting_items if s.get("status") == "AVAILABLE"])
        available_contradicting = len([c for c in contradicting_items if c.get("status") == "AVAILABLE"])

        if available_contradicting > 0:
            support_status = HypothesisSupportStatus.CONTRADICTED
        elif available_supporting >= 2 and not hyp.evidence_gaps:
            support_status = HypothesisSupportStatus.SUPPORTED_BY_CURRENT_EVIDENCE
        elif available_supporting >= 1:
            support_status = HypothesisSupportStatus.WEAKLY_SUPPORTED
        elif available_supporting == 0 and not hyp.contradicting_evidence_tags:
            support_status = HypothesisSupportStatus.INSUFFICIENT_EVIDENCE
        else:
            support_status = HypothesisSupportStatus.UNRESOLVED

        # Check temporal & entity consistency
        temporal_cons = "Consistent with case temporal range" if supporting_items else "No temporal evidence linked"
        entity_cons = f"Addresses declared entities in case scope" if case.scope.selected_entity_ids else "Scope unassigned"

        # Generate targeted query recommendations if gaps exist
        recs: List[QueryProposal] = []
        for gap in hyp.evidence_gaps:
            recs.append(
                QueryProposal(
                    title=f"Investigate: {gap[:30]}",
                    intent="HYPOTHESIS_GAP_ANALYSIS",
                    rationale=f"Search forensic telemetry to resolve hypothesis gap '{gap}'",
                    search_text=gap.split()[-1] if gap.split() else "security",
                    limit=25,
                )
            )

        return HypothesisEvidenceAnalysis(
            hypothesis_id=hyp.hypothesis_id,
            case_id=case.case_id,
            statement=hyp.statement,
            support_status=support_status,
            supporting_evidence_items=supporting_items,
            contradicting_evidence_items=contradicting_items,
            evidence_gaps=hyp.evidence_gaps,
            temporal_consistency=temporal_cons,
            entity_consistency=entity_cons,
            recommended_queries=recs,
            analyst_action_required=False,  # strictly preserves analyst autonomy
        )
