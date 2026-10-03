"""Provenance Manifest Tracker for LogIntel Milestone 5.7.

Generates comprehensive, verifiable provenance records answering:
'Where did this statement / finding / timeline item come from?'
without relying on probabilistic AI memory.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List

from logintel.ai.domain.case import InvestigationCase
from logintel.ai.domain.investigation_dossier import (
    EvidenceMatrixEntry,
    ProvenanceManifestEntry,
    RefinedTimelineItem,
)
from logintel.ai.domain.investigation_intel import (
    EpistemicStatus,
    InvestigationCorrelation,
    InvestigationFinding,
)


class ProvenanceTracker:
    """Builds cryptographic and reference-grounded provenance manifests."""

    def build_manifest(
        self,
        case: InvestigationCase,
        findings: List[Dict[str, Any]],
        timeline: List[RefinedTimelineItem],
        matrix: List[EvidenceMatrixEntry],
        correlations: List[InvestigationCorrelation],
    ) -> List[ProvenanceManifestEntry]:
        """Construct full provenance manifest for a case dossier."""
        entries: List[ProvenanceManifestEntry] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Evidence References
        for ref in case.evidence_references:
            payload = json.dumps(ref.resolved_record or {"source_id": ref.source_id}, sort_keys=True)
            sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            entries.append(
                ProvenanceManifestEntry(
                    case_id=case.case_id,
                    item_type="evidence_reference",
                    item_id=ref.citation_tag,
                    source_type=ref.source_type,
                    source_id=ref.source_id,
                    source_hash_or_ref=f"sha256:{sha}",
                    epistemic_status=EpistemicStatus(ref.epistemic_status.value if hasattr(ref.epistemic_status, "value") else str(ref.epistemic_status)),
                    generated_by=f"forensic_db.{ref.source_type}s",
                    generated_at=ref.created_at,
                )
            )

        # 2. Findings
        for f in findings:
            f_id = f.get("finding_id", "unknown")
            sources = f.get("source_references") or f.get("related_events") or []
            src_str = ",".join(str(s) for s in sources)
            sha = hashlib.sha256(src_str.encode("utf-8")).hexdigest()
            entries.append(
                ProvenanceManifestEntry(
                    case_id=case.case_id,
                    item_type="finding",
                    item_id=f_id,
                    source_type="evidence_cluster",
                    source_id=src_str or "case_scope",
                    source_hash_or_ref=f"src_hash:{sha}",
                    epistemic_status=EpistemicStatus(f.get("epistemic_status", "INFERRED")),
                    generated_by=f.get("generated_by", "DETERMINISTIC_CORRELATOR"),
                    generated_at=f.get("created_at", now_iso),
                )
            )

        # 3. Timeline Items
        for item in timeline:
            entries.append(
                ProvenanceManifestEntry(
                    case_id=case.case_id,
                    item_type="timeline_item",
                    item_id=item.item_id,
                    source_type=item.source_type.value,
                    source_id=item.source_id,
                    source_hash_or_ref=f"ref:{item.citation_tag or item.source_id}",
                    epistemic_status=item.epistemic_status,
                    generated_by=item.provenance,
                    generated_at=item.timestamp,
                )
            )

        # 4. Evidence Matrix Entries
        for mat in matrix:
            entries.append(
                ProvenanceManifestEntry(
                    case_id=case.case_id,
                    item_type="evidence_matrix_entry",
                    item_id=f"matrix-{mat.hypothesis_id}",
                    source_type="hypothesis",
                    source_id=mat.hypothesis_id,
                    source_hash_or_ref=f"status:{mat.status.value}",
                    epistemic_status=EpistemicStatus.INFERRED,
                    generated_by="DETERMINISTIC_EVIDENCE_MATRIX_BUILDER",
                    generated_at=mat.last_evaluated_at,
                )
            )

        # 5. Correlations
        for corr in correlations:
            entries.append(
                ProvenanceManifestEntry(
                    case_id=case.case_id,
                    item_type="correlation",
                    item_id=corr.correlation_id,
                    source_type="bipartite_evidence_pair",
                    source_id=f"{corr.source_item}<->{corr.target_item}",
                    source_hash_or_ref=f"type:{corr.correlation_type}",
                    epistemic_status=EpistemicStatus.INFERRED,
                    generated_by="DETERMINISTIC_CORRELATOR",
                    generated_at=now_iso,
                )
            )

        return entries
