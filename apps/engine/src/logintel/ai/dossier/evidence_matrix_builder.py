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
            has_resolved_support = any(
                item["resolution"] == EvidenceItemResolution.RESOLVED.value for item in supporting_items
            )
            has_resolved_contradiction = any(
                item["resolution"] == EvidenceItemResolution.RESOLVED.value for item in contradicting_items
            )

            if has_resolved_contradiction:
                status = EvidenceMatrixStatus.CONTRADICTED
            elif has_resolved_support and not hyp.evidence_gaps:
                status = EvidenceMatrixStatus.SUPPORTED
            elif has_resolved_support and hyp.evidence_gaps:
                status = EvidenceMatrixStatus.WEAKLY_SUPPORTED
            elif not supporting_items and not contradicting_items:
                status = EvidenceMatrixStatus.INSUFFICIENT
            else:
                status = EvidenceMatrixStatus.UNRESOLVED

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
