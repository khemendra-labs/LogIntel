"""Investigation Timeline Intelligence Engine for LogIntel M5.6.

Constructs unified case timelines across events, alerts, detections, analyst notes,
and derived correlations with strict provenance classification.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from logintel.ai.domain.case import InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_intel import (
    CaseTimelineItem,
    InvestigationCorrelation,
    TimelineSourceType,
)
from logintel.storage.db import Database, db as default_db


class CaseTimelineBuilder:
    """Builds unified case timelines with provenance separation."""

    def __init__(self, database: Optional[Database] = None) -> None:
        self.db = database or default_db

    def build_case_timeline(
        self,
        case: InvestigationCase,
        correlations: Optional[List[InvestigationCorrelation]] = None,
    ) -> List[CaseTimelineItem]:
        """Aggregate all timeline items linked to the case, ordered chronologically."""
        timeline: List[CaseTimelineItem] = []

        # 1. Authoritative Evidence References
        for ref in case.evidence_references:
            if ref.resolution_status == ResolutionStatus.AVAILABLE and ref.resolved_record:
                rec = ref.resolved_record
                ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("last_seen") or rec.get("created_at") or rec.get("ingested_at")
                if not ts:
                    continue

                source_type = TimelineSourceType.OBSERVED_EVENT
                is_auth = True
                if ref.source_type == "alert":
                    source_type = TimelineSourceType.ALERT
                elif ref.source_type == "detection":
                    source_type = TimelineSourceType.DETECTION

                title = rec.get("title") or rec.get("summary") or f"{ref.source_type.title()} {ref.source_id}"
                summary = rec.get("raw_message") or rec.get("description") or rec.get("summary") or str(rec)

                timeline.append(
                    CaseTimelineItem(
                        item_id=f"tl-ev-{ref.reference_id}",
                        case_id=case.case_id,
                        timestamp=str(ts),
                        source_type=source_type,
                        title=str(title)[:100],
                        summary=str(summary)[:250],
                        provenance=f"Authoritative {ref.source_type} ({ref.source_id})",
                        citation_tag=ref.citation_tag,
                        is_authoritative=is_auth,
                        metadata={
                            "host": rec.get("host"),
                            "username": rec.get("username"),
                            "src_ip": rec.get("src_ip"),
                        },
                    )
                )

        # 2. Case Audit Log Milestones
        for a in case.audit_history:
            timeline.append(
                CaseTimelineItem(
                    item_id=f"tl-aud-{a.audit_id or a.timestamp}",
                    case_id=case.case_id,
                    timestamp=a.timestamp,
                    source_type=TimelineSourceType.ANALYST_ANNOTATION,
                    title=f"Analyst Action: {a.action}",
                    summary=f"Operator '{a.actor}' performed {a.action}. {a.reason or ''}",
                    provenance=f"Audit trail record (actor: {a.actor})",
                    citation_tag=None,
                    is_authoritative=True,
                    metadata={"actor": a.actor, "action": a.action},
                )
            )

        # 3. Derived Correlations
        if correlations:
            for corr in correlations:
                timeline.append(
                    CaseTimelineItem(
                        item_id=f"tl-corr-{corr.correlation_id}",
                        case_id=case.case_id,
                        timestamp=case.updated_at,  # correlation timestamp
                        source_type=TimelineSourceType.DERIVED_CORRELATION,
                        title=f"Derived Correlation: {corr.source_item} <-> {corr.target_item}",
                        summary=f"Correlated via {', '.join(corr.reasons)}",
                        provenance="Deterministic Correlation Engine",
                        citation_tag=None,
                        is_authoritative=False,
                        metadata={
                            "reasons": corr.reasons,
                            "shared_entities": corr.shared_entities,
                            "confidence_score": corr.confidence_score,
                        },
                    )
                )

        # Sort chronologically by timestamp
        timeline.sort(key=lambda x: x.timestamp)
        return timeline
