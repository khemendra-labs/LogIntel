"""Deterministic Case Briefing & Evidence-Gap Action Builder for LogIntel Milestone 5.7.

Generates structured incident/case briefings distinguishing evidence from interpretation,
and translates evidence gaps into actionable, analyst-controlled next steps without auto-remediation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from logintel.ai.domain.case import InvestigationCase
from logintel.ai.domain.investigation_dossier import CaseBriefing, EvidenceGapAction
from logintel.ai.domain.investigation_intel import EvidenceGap


class BriefingBuilder:
    """Builds deterministic case briefings and converts gaps to structured actions."""

    def build_gap_actions(self, gaps: List[EvidenceGap]) -> List[EvidenceGapAction]:
        """Convert evidence gaps into structured next-action suggestions."""
        actions: List[EvidenceGapAction] = []
        for g in gaps:
            action_desc = f"Execute governed hunting query for {g.gap_type} across scope."
            reason = f"Telemetry gap '{g.gap_type}' prevents conclusive forensic attribution."
            req = f"{g.gap_type} telemetry"

            if g.gap_type == "MISSING_PROCESS_TELEMETRY":
                action_desc = "Review process execution logs (auditd/sysmon) for ±5 minutes around authentication events."
                reason = "Process lineage attribution is currently unavailable."
                req = "Auditd process execution telemetry (SYSCALL execve / PATH)"
            elif g.gap_type == "MISSING_NETWORK_TELEMETRY":
                action_desc = "Inspect network socket connection logs for source and destination IPs in case scope."
                reason = "Outbound network connection telemetry is uncollected or absent."
                req = "Network flow / firewall accept/drop logs"
            elif g.gap_type == "MISSING_AUTHENTICATION_TELEMETRY":
                action_desc = "Collect authentication records (auth.log / Security.evtx) for targeted user accounts."
                reason = "User session authentication telemetry is incomplete."
                req = "PAM session / sshd authentication events"

            actions.append(
                EvidenceGapAction(
                    gap_id=g.gap_id,
                    case_id=g.case_id,
                    gap_type=g.gap_type,
                    description=g.description,
                    affected_scope=g.affected_scope,
                    suggested_action=action_desc,
                    reason=reason,
                    evidence_requirement=req,
                    recommended_governed_query=g.recommended_governed_query,
                    status=g.status,
                    execution_control="ANALYST_CONTROLLED",
                )
            )
        return actions

    def build_briefing(
        self,
        case: InvestigationCase,
        findings: List[Dict[str, Any]],
        gaps: List[EvidenceGap],
        correlations: List[Any],
    ) -> CaseBriefing:
        """Construct deterministic structured case briefing."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # Count observed metrics
        event_cnt = sum(1 for r in case.evidence_references if r.source_type == "event")
        alert_cnt = sum(1 for r in case.evidence_references if r.source_type == "alert")
        det_cnt = sum(1 for r in case.evidence_references if r.source_type == "detection")

        metrics = {
            "evidence_reference_count": len(case.evidence_references),
            "observed_events": event_cnt,
            "associated_alerts": alert_cnt,
            "associated_detections": det_cnt,
            "hypotheses_count": len(case.hypotheses),
            "executed_queries": len(case.query_history),
        }

        # Key findings summary
        findings_summary: List[Dict[str, Any]] = []
        for f in findings:
            findings_summary.append({
                "finding_id": f.get("finding_id"),
                "title": f.get("title"),
                "finding_type": f.get("finding_type"),
                "epistemic_status": f.get("epistemic_status"),
                "review_state": f.get("review_state", "UNREVIEWED"),
                "confidence_basis": f.get("confidence_basis"),
            })

        # Correlations narrative
        corr_narrative: List[str] = []
        for c in correlations:
            reasons = "; ".join(c.reasons) if hasattr(c, "reasons") else ""
            src = getattr(c, "source_item", "")
            tgt = getattr(c, "target_item", "")
            corr_narrative.append(f"{src} <-> {tgt}: {reasons}")

        # Gap actions
        gap_actions = self.build_gap_actions(gaps)
        gap_summaries = [f"{g.gap_type}: {g.description}" for g in gaps]

        # Hypotheses evidence states
        hyp_states: List[Dict[str, Any]] = []
        for h in case.hypotheses:
            hyp_states.append({
                "hypothesis_id": h.hypothesis_id,
                "statement": h.statement,
                "analyst_status": h.status.value,
                "supporting_evidence_count": len(h.supporting_evidence_tags),
                "contradicting_evidence_count": len(h.contradicting_evidence_tags),
                "evidence_gaps_count": len(h.evidence_gaps),
            })

        return CaseBriefing(
            case_id=case.case_id,
            incident_id=case.incident_id,
            case_title=case.title,
            scope_summary={
                "time_start": case.scope.time_start if case.scope else None,
                "time_end": case.scope.time_end if case.scope else None,
                "subject_type": case.scope.subject_type if case.scope else "incident",
                "subject_id": case.scope.subject_id if case.scope else str(case.incident_id),
                "selected_entity_ids": case.scope.selected_entity_ids if case.scope else [],
            },
            observed_metrics=metrics,
            key_findings_summary=findings_summary,
            correlations_narrative=corr_narrative,
            evidence_gaps_summary=gap_summaries,
            hypotheses_evidence_states=hyp_states,
            recommended_next_actions=gap_actions,
            generated_at=now_iso,
            generated_by="DETERMINISTIC_BRIEFING_ENGINE",
        )
