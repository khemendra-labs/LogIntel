"""Refined Multi-Source Timeline Intelligence Builder for LogIntel Milestone 5.7.

Consolidates heterogeneous artifacts into a unified chronological sequence:
- Authoritative Forensic Events (OBSERVED_EVENT)
- Detections & Alerts (DETECTION, ALERT)
- Incidents (INCIDENT)
- Deterministic Correlations (CORRELATION)
- Structured Findings (FINDING)
- Analyst Annotations (ANALYST_NOTE)
- Hypotheses (HYPOTHESIS)
- Governed Threat Hunting Results (THREAT_HUNT_RESULT)
- AI Interpretations (AI_INTERPRETATION)

Strictly preserves is_authoritative and epistemic status across all items.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from logintel.ai.domain.case import InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_dossier import (
    RefinedTimelineItem,
    RefinedTimelineSourceType,
)
from logintel.ai.domain.investigation_intel import (
    EpistemicStatus,
    InvestigationCorrelation,
    InvestigationFinding,
)
from logintel.storage.db import Database


class RefinedTimelineBuilder:
    """Builds unified multi-source chronological investigation timelines."""

    def __init__(self, forensic_db: Database) -> None:
        self.db = forensic_db

    def build_refined_timeline(
        self,
        case: InvestigationCase,
        findings: Optional[List[Dict[str, Any]]] = None,
        correlations: Optional[List[InvestigationCorrelation]] = None,
        ai_interpretations: Optional[List[Dict[str, Any]]] = None,
    ) -> List[RefinedTimelineItem]:
        """Aggregate, sort, and tag all artifacts associated with the case scope."""
        items: List[RefinedTimelineItem] = []

        # 1. Authoritative Evidence References (Events, Alerts, Detections)
        for ref in case.evidence_references:
            rec = ref.resolved_record or {}
            ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at") or ref.created_at

            if ref.source_type == "event":
                items.append(
                    RefinedTimelineItem(
                        item_id=f"tl-ev-{ref.source_id}",
                        case_id=case.case_id,
                        timestamp=ts,
                        source_type=RefinedTimelineSourceType.OBSERVED_EVENT,
                        source_id=ref.source_id,
                        title=f"Observed Event {ref.source_id}: {rec.get('action') or rec.get('event_type') or 'telemetry'}",
                        summary=rec.get("summary") or rec.get("raw_message") or "Authoritative forensic event",
                        epistemic_status=EpistemicStatus.OBSERVED,
                        is_authoritative=True,
                        citation_tag=ref.citation_tag or f"[event:{ref.source_id}]",
                        provenance=f"Authoritative event recorded in forensic log: {rec.get('source', 'syslog')}",
                        metadata={
                            "host": rec.get("host"),
                            "username": rec.get("username"),
                            "src_ip": rec.get("src_ip"),
                            "event_type": rec.get("event_type"),
                        },
                    )
                )
            elif ref.source_type == "alert":
                items.append(
                    RefinedTimelineItem(
                        item_id=f"tl-alt-{ref.source_id}",
                        case_id=case.case_id,
                        timestamp=ts,
                        source_type=RefinedTimelineSourceType.ALERT,
                        source_id=ref.source_id,
                        title=f"Alert: {rec.get('title') or rec.get('rule_id') or ref.source_id}",
                        summary=rec.get("description") or "Operational security alert",
                        epistemic_status=EpistemicStatus.OBSERVED,
                        is_authoritative=True,
                        citation_tag=ref.citation_tag or f"[alert:{ref.source_id}]",
                        provenance=f"Detection rule engine: rule_id={rec.get('rule_id')}",
                        metadata={"severity": rec.get("severity"), "host": rec.get("host")},
                    )
                )
            elif ref.source_type == "detection":
                items.append(
                    RefinedTimelineItem(
                        item_id=f"tl-det-{ref.source_id}",
                        case_id=case.case_id,
                        timestamp=ts,
                        source_type=RefinedTimelineSourceType.DETECTION,
                        source_id=ref.source_id,
                        title=f"Detection: {rec.get('rule_id') or ref.source_id}",
                        summary=rec.get("summary") or "Rule match detection",
                        epistemic_status=EpistemicStatus.OBSERVED,
                        is_authoritative=True,
                        citation_tag=ref.citation_tag or f"[detection:{ref.source_id}]",
                        provenance=f"Detection engine match",
                        metadata={"host": rec.get("host")},
                    )
                )
            elif ref.source_type == "incident":
                items.append(
                    RefinedTimelineItem(
                        item_id=f"tl-inc-{ref.source_id}",
                        case_id=case.case_id,
                        timestamp=ts,
                        source_type=RefinedTimelineSourceType.INCIDENT,
                        source_id=ref.source_id,
                        title=f"Incident: {rec.get('title') or ref.source_id}",
                        summary=rec.get("summary") or "Authoritative incident record",
                        epistemic_status=EpistemicStatus.OBSERVED,
                        is_authoritative=True,
                        citation_tag=ref.citation_tag or f"[incident:{ref.source_id}]",
                        provenance=f"Authoritative incident record in forensic database: {ref.source_id}",
                        metadata={"severity": rec.get("severity"), "status": rec.get("status")},
                    )
                )

        # 2. Governed Threat Hunting Query Executions
        for q in case.query_history:
            items.append(
                RefinedTimelineItem(
                    item_id=f"tl-hunt-{q.query_id}",
                    case_id=case.case_id,
                    timestamp=q.executed_at,
                    source_type=RefinedTimelineSourceType.THREAT_HUNT_RESULT,
                    source_id=q.query_id,
                    title=f"Threat Hunt: {q.query_template_id} ({q.result_count} hits)",
                    summary=f"Governed hunt executed by {q.executed_by}. Rationale: {q.rationale}",
                    epistemic_status=EpistemicStatus.INFERRED,
                    is_authoritative=False,
                    citation_tag=f"[hunt:{q.query_id}]",
                    provenance=f"Governed hunt proposal {q.proposal_id} approved by {q.executed_by}",
                    metadata={"template": q.query_template_id, "hits": q.result_count, "status": q.execution_status},
                )
            )

        # 3. Analyst Hypotheses
        for hyp in case.hypotheses:
            items.append(
                RefinedTimelineItem(
                    item_id=f"tl-hyp-{hyp.hypothesis_id}",
                    case_id=case.case_id,
                    timestamp=hyp.created_at,
                    source_type=RefinedTimelineSourceType.HYPOTHESIS,
                    source_id=hyp.hypothesis_id,
                    title=f"Hypothesis: {hyp.statement[:50]}...",
                    summary=hyp.statement,
                    epistemic_status=EpistemicStatus.UNKNOWN,
                    is_authoritative=False,
                    citation_tag=f"[hypothesis:{hyp.hypothesis_id}]",
                    provenance=f"Analyst-created hypothesis v{hyp.version} by {hyp.created_by}",
                    metadata={"status": hyp.status.value, "version": hyp.version},
                )
            )

        # 4. Deterministic Findings
        if findings:
            for f in findings:
                f_id = f.get("finding_id") or "unknown"
                items.append(
                    RefinedTimelineItem(
                        item_id=f"tl-fnd-{f_id}",
                        case_id=case.case_id,
                        timestamp=f.get("created_at") or case.created_at,
                        source_type=RefinedTimelineSourceType.FINDING,
                        source_id=f_id,
                        title=f"Finding: {f.get('title')}",
                        summary=f.get("description", ""),
                        epistemic_status=EpistemicStatus(f.get("epistemic_status", "INFERRED")),
                        is_authoritative=False,
                        citation_tag=f"[finding:{f_id}]",
                        provenance=f"Generated by {f.get('generated_by', 'CORRELATOR')}",
                        metadata={"review_state": f.get("review_state", "UNREVIEWED"), "type": f.get("finding_type")},
                    )
                )

        # 5. Deterministic Correlations
        if correlations:
            for corr in correlations:
                items.append(
                    RefinedTimelineItem(
                        item_id=f"tl-corr-{corr.correlation_id}",
                        case_id=case.case_id,
                        timestamp=case.created_at,
                        source_type=RefinedTimelineSourceType.CORRELATION,
                        source_id=corr.correlation_id,
                        title=f"Correlation: {corr.source_item} <-> {corr.target_item}",
                        summary="; ".join(corr.reasons),
                        epistemic_status=EpistemicStatus.INFERRED,
                        is_authoritative=False,
                        citation_tag=f"[correlation:{corr.correlation_id}]",
                        provenance=f"Deterministic Correlator: {corr.correlation_type}",
                        metadata={"score": corr.confidence_score, "delta_sec": corr.temporal_distance_seconds},
                    )
                )

        # 6. AI Interpretations (Advisory only)
        if ai_interpretations:
            for interp in ai_interpretations:
                items.append(
                    RefinedTimelineItem(
                        item_id=f"tl-ai-{interp.get('id', 'advisory')}",
                        case_id=case.case_id,
                        timestamp=interp.get("timestamp") or case.created_at,
                        source_type=RefinedTimelineSourceType.AI_INTERPRETATION,
                        source_id=interp.get("id", "ai"),
                        title=f"AI Interpretation: {interp.get('title', 'Synthesis')}",
                        summary=interp.get("summary", ""),
                        epistemic_status=EpistemicStatus.INFERRED,
                        is_authoritative=False,
                        citation_tag=None,
                        provenance="Local AI advisory model (untrusted output)",
                        metadata={"model": interp.get("model", "local-ollama")},
                    )
                )

        # Chronological sort
        items.sort(key=lambda x: x.timestamp or "")
        return items
