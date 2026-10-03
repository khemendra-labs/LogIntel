"""Deterministic Evidence Matrix Builder for LogIntel Milestone 5.7.

Evaluates hypotheses against structured case evidence references and authoritative forensic records,
producing deterministic support statuses (SUPPORTED, WEAKLY_SUPPORTED, CONTRADICTED, INSUFFICIENT, UNRESOLVED)
and resolving individual evidence references without AI hallucination.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from logintel.ai.domain.case import InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_dossier import (
    EvidenceItemResolution,
    EvidenceMatrixEntry,
    EvidenceMatrixStatus,
)


class EvidenceMatrixBuilder:
    """Builds deterministic evidence matrices for case hypotheses."""

    def build_matrix(self, case: InvestigationCase) -> List[EvidenceMatrixEntry]:
        """Evaluate all hypotheses for the given case into a structured evidence matrix."""
        entries: List[EvidenceMatrixEntry] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # Map citation tags to evidence references
        ref_map: Dict[str, Any] = {}
        for r in case.evidence_references:
            tag = r.citation_tag or f"[{r.source_type}:{r.source_id}]"
            ref_map[tag] = r
            ref_map[r.source_id] = r

        for hyp in case.hypotheses:
            supporting_items: List[Dict[str, Any]] = []
            contradicting_items: List[Dict[str, Any]] = []

            # 1. Resolve supporting evidence tags
            for tag in hyp.supporting_evidence_tags:
                ref = ref_map.get(tag)
                if ref:
                    res_status = (
                        EvidenceItemResolution.RESOLVED
                        if ref.resolution_status == ResolutionStatus.AVAILABLE
                        else EvidenceItemResolution.MISSING
                        if ref.resolution_status == ResolutionStatus.MISSING
                        else EvidenceItemResolution.UNAVAILABLE
                    )
                    supporting_items.append({
                        "citation_tag": tag,
                        "source_type": ref.source_type,
                        "source_id": ref.source_id,
                        "role": ref.role,
                        "epistemic_status": ref.epistemic_status.value if hasattr(ref.epistemic_status, "value") else str(ref.epistemic_status),
                        "resolution": res_status.value,
                        "statement": ref.analyst_annotation or f"Supporting {ref.source_type} {ref.source_id}",
                    })
                else:
                    supporting_items.append({
                        "citation_tag": tag,
                        "source_type": "unknown",
                        "source_id": tag,
                        "role": "SUPPORTING",
                        "epistemic_status": "UNKNOWN",
                        "resolution": EvidenceItemResolution.UNRESOLVED.value,
                        "statement": f"Unlinked evidence citation: {tag}",
                    })

            # 2. Resolve contradicting evidence tags
            for tag in hyp.contradicting_evidence_tags:
                ref = ref_map.get(tag)
                if ref:
                    res_status = (
                        EvidenceItemResolution.RESOLVED
                        if ref.resolution_status == ResolutionStatus.AVAILABLE
                        else EvidenceItemResolution.MISSING
                    )
                    contradicting_items.append({
                        "citation_tag": tag,
                        "source_type": ref.source_type,
                        "source_id": ref.source_id,
                        "role": ref.role,
                        "epistemic_status": ref.epistemic_status.value if hasattr(ref.epistemic_status, "value") else str(ref.epistemic_status),
                        "resolution": res_status.value,
                        "statement": ref.analyst_annotation or f"Contradicting {ref.source_type} {ref.source_id}",
                    })
                else:
                    contradicting_items.append({
                        "citation_tag": tag,
                        "source_type": "unknown",
                        "source_id": tag,
                        "role": "CONTRADICTING",
                        "epistemic_status": "UNKNOWN",
                        "resolution": EvidenceItemResolution.UNRESOLVED.value,
                        "statement": f"Unlinked contradicting citation: {tag}",
                    })

            # 3. Determine deterministic status
            resolved_support_count = sum(
                1 for item in supporting_items if item["resolution"] == EvidenceItemResolution.RESOLVED.value
            )
            resolved_contradiction_count = sum(
                1 for item in contradicting_items if item["resolution"] == EvidenceItemResolution.RESOLVED.value
            )
            unresolved_count = sum(
                1 for item in (supporting_items + contradicting_items)
                if item["resolution"] in (
                    EvidenceItemResolution.UNRESOLVED.value,
                    EvidenceItemResolution.MISSING.value,
                    EvidenceItemResolution.UNAVAILABLE.value,
                )
            )

            # Deterministic Mutual-Exclusivity Precedence Hierarchy:
            # 1. Refutation Precedence: Any resolved contradiction refutes the hypothesis (Cases C, H)
            # 2. Epistemic Gate Precedence: Unresolved references prevent resolution of support (Cases D, E, F)
            # 3. Insufficient Evidence: No references cited or 0 resolved support (Case G)
            # 4. Corroborated Support: >= 2 resolved support, 0 unresolved, 0 gaps (Case A)
            # 5. Weakly Supported: 1 resolved support, OR >= 2 resolved support with open evidence gaps (Case B)
            if resolved_contradiction_count >= 1:
                status = EvidenceMatrixStatus.CONTRADICTED
            elif unresolved_count >= 1:
                status = EvidenceMatrixStatus.UNRESOLVED
            elif not supporting_items and not contradicting_items:
                status = EvidenceMatrixStatus.INSUFFICIENT
            elif resolved_support_count >= 2 and not hyp.evidence_gaps:
                status = EvidenceMatrixStatus.SUPPORTED
            elif resolved_support_count >= 1:
                status = EvidenceMatrixStatus.WEAKLY_SUPPORTED
            else:
                status = EvidenceMatrixStatus.INSUFFICIENT

            entries.append(
                EvidenceMatrixEntry(
                    hypothesis_id=hyp.hypothesis_id,
                    case_id=case.case_id,
                    statement=hyp.statement,
                    status=status,
                    supporting_evidence=supporting_items,
                    contradicting_evidence=contradicting_items,
                    evidence_gaps=list(hyp.evidence_gaps),
                    temporal_consistency="CONSISTENT",
                    entity_consistency="CONSISTENT",
                    last_evaluated_at=now_iso,
                )
            )

        return entries
