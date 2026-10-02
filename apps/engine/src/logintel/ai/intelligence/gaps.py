"""Evidence Gap Analysis and Corroboration Engine for LogIntel M5.6.

Identifies missing telemetry dimensions, coverage gaps, and generates recommended
governed query proposals without executing them automatically.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from logintel.ai.domain.case import InvestigationCase, ResolutionStatus
from logintel.ai.domain.intelligence import QueryProposal
from logintel.ai.domain.investigation_intel import EvidenceGap


class EvidenceGapEngine:
    """Analyzes investigation evidence completeness and detects critical telemetry gaps."""

    def identify_evidence_gaps(self, case: InvestigationCase) -> List[EvidenceGap]:
        """Examine case evidence, scope, and hypotheses to identify missing telemetry."""
        gaps: List[EvidenceGap] = []

        # 1. Stale / Unresolved Evidence References
        for ref in case.evidence_references:
            if ref.resolution_status != ResolutionStatus.AVAILABLE:
                gaps.append(
                    EvidenceGap(
                        gap_id=f"gap-{case.case_id}-stale-{ref.reference_id[:6]}",
                        case_id=case.case_id,
                        gap_type="STALE_EVIDENCE_REFERENCE",
                        description=f"Evidence reference {ref.citation_tag} ({ref.source_type}:{ref.source_id}) cannot be resolved (status: {ref.resolution_status.value}).",
                        affected_scope={"source_type": ref.source_type, "source_id": ref.source_id},
                        supporting_context="Evidence was previously referenced or pruned by upstream forensic retention.",
                        recommended_governed_query=QueryProposal(
                            title=f"Locate Historical {ref.source_type} {ref.source_id}",
                            intent="EVIDENCE_RECOVERY",
                            rationale=f"Search authoritative forensic events for residual indicators of {ref.source_id}",
                            search_text=ref.source_id,
                            limit=20,
                        ),
                        status="OPEN",
                    )
                )

        # Collect telemetry sources present in resolved evidence
        resolved_types = set()
        resolved_hosts = set()
        resolved_users = set()

        for ref in case.evidence_references:
            if ref.resolution_status == ResolutionStatus.AVAILABLE and ref.resolved_record:
                rec = ref.resolved_record
                src = str(rec.get("source") or rec.get("event_type") or "").lower()
                resolved_types.add(src)
                if rec.get("host"):
                    resolved_hosts.add(rec["host"])
                if rec.get("username"):
                    resolved_users.add(rec["username"])

        # 2. Scope vs Evidence Coverage (Check if declared hosts/users have telemetry)
        primary_host = next(iter(resolved_hosts), None) or (case.scope.selected_entity_ids[0] if case.scope.selected_entity_ids else None)
        primary_user = next(iter(resolved_users), None)

        # Check for missing process execution telemetry
        has_process_telemetry = any("process" in s or "exec" in s or "auditd" in s or "syslog" in s for s in resolved_types)
        if not has_process_telemetry and primary_host:
            gaps.append(
                EvidenceGap(
                    gap_id=f"gap-{case.case_id}-missing-process",
                    case_id=case.case_id,
                    gap_type="MISSING_PROCESS_TELEMETRY",
                    description=f"No process execution or command-line telemetry linked for primary host '{primary_host}'.",
                    affected_scope={"host": primary_host},
                    supporting_context="Process ancestry and execution logs are required to validate privilege escalation or persistence.",
                    recommended_governed_query=QueryProposal(
                        title=f"Search Process Execution on {primary_host}",
                        intent="PROCESS_HUNT",
                        rationale="Query auditd and syslog execution records for parent/child process lineage.",
                        host=primary_host,
                        event_types=["process", "exec", "auditd", "command"],
                        limit=50,
                    ),
                    status="OPEN",
                )
            )

        # Check for missing network telemetry
        has_network_telemetry = any("network" in s or "conn" in s or "socket" in s or "firewall" in s for s in resolved_types)
        if not has_network_telemetry and primary_host:
            gaps.append(
                EvidenceGap(
                    gap_id=f"gap-{case.case_id}-missing-network",
                    case_id=case.case_id,
                    gap_type="MISSING_NETWORK_TELEMETRY",
                    description=f"No egress or network socket connection telemetry associated with host '{primary_host}'.",
                    affected_scope={"host": primary_host},
                    supporting_context="Network socket telemetry is required to corroborate potential lateral movement or C2 beacons.",
                    recommended_governed_query=QueryProposal(
                        title=f"Search Network Connections for {primary_host}",
                        intent="NETWORK_HUNT",
                        rationale="Query external IP connection attempts originating from the compromised host.",
                        host=primary_host,
                        event_types=["network", "connection", "socket"],
                        limit=50,
                    ),
                    status="OPEN",
                )
            )

        # 3. Hypothesis Documented Gaps
        for hyp in case.hypotheses:
            for gap_text in hyp.evidence_gaps:
                gaps.append(
                    EvidenceGap(
                        gap_id=f"gap-{case.case_id}-hyp-{uuid.uuid4().hex[:6]}",
                        case_id=case.case_id,
                        gap_type="ANALYST_HYPOTHESIS_GAP",
                        description=f"Hypothesis '{hyp.statement[:40]}...' gap: {gap_text}",
                        affected_scope={"hypothesis_id": hyp.hypothesis_id},
                        supporting_context=f"Documented by analyst {hyp.created_by} during hypothesis refinement.",
                        recommended_governed_query=QueryProposal(
                            title=f"Corroborate Hypothesis {hyp.hypothesis_id}",
                            intent="HYPOTHESIS_CORROBORATION",
                            rationale=f"Investigate gap: {gap_text}",
                            host=primary_host,
                            username=primary_user,
                            search_text=gap_text.split()[-1] if gap_text.split() else None,
                            limit=25,
                        ),
                        status="OPEN",
                    )
                )

        return gaps
