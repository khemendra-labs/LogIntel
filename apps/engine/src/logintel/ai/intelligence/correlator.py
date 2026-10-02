"""Deterministic investigation correlation and findings engine for LogIntel M5.6.

Identifies multi-attribute relationships across events, alerts, detections, and incident entities,
providing explicit, human-readable reasons for every correlation without probabilistic guesswork.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from logintel.ai.domain.case import CaseEvidenceReference, InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_intel import (
    EpistemicStatus,
    InvestigationCorrelation,
    InvestigationFinding,
)


class DeterministicCorrelator:
    """Computes deterministic correlations and findings for a case."""

    def __init__(self, temporal_window_seconds: float = 300.0) -> None:
        self.temporal_window = temporal_window_seconds

    def correlate_case_evidence(
        self,
        case: InvestigationCase,
        additional_events: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[InvestigationFinding], List[InvestigationCorrelation]]:
        """Correlate resolved evidence references and generate structured findings with explicit reasons."""
        correlations: List[InvestigationCorrelation] = []
        findings: List[InvestigationFinding] = []

        # Extract resolved records
        resolved_items: List[Dict[str, Any]] = []
        for ref in case.evidence_references:
            if ref.resolution_status == ResolutionStatus.AVAILABLE and ref.resolved_record:
                rec = dict(ref.resolved_record)
                rec["_citation_tag"] = ref.citation_tag
                rec["_source_type"] = ref.source_type
                rec["_source_id"] = ref.source_id
                resolved_items.append(rec)

        if additional_events:
            for ev in additional_events:
                ev_copy = dict(ev)
                ev_copy["_citation_tag"] = f"[event:{ev.get('id')}]"
                ev_copy["_source_type"] = "event"
                ev_copy["_source_id"] = str(ev.get("id"))
                resolved_items.append(ev_copy)

        now_iso = datetime.now(timezone.utc).isoformat()

        # Pairwise deterministic correlation
        n = len(resolved_items)
        seen_pairs: Set[Tuple[str, str]] = set()

        for i in range(n):
            for j in range(i + 1, n):
                item_a = resolved_items[i]
                item_b = resolved_items[j]

                tag_a = item_a.get("_citation_tag", "")
                tag_b = item_b.get("_citation_tag", "")

                if (tag_a, tag_b) in seen_pairs or (tag_b, tag_a) in seen_pairs:
                    continue
                seen_pairs.add((tag_a, tag_b))

                reasons: List[str] = []
                shared_entities: List[str] = []

                # 1. Host match
                host_a = item_a.get("host") or item_a.get("primary_host")
                host_b = item_b.get("host") or item_b.get("primary_host")
                if host_a and host_b and str(host_a).lower() == str(host_b).lower():
                    reasons.append(f"same host: {host_a}")
                    shared_entities.append(f"host:{host_a}")

                # 2. User match
                user_a = item_a.get("username") or item_a.get("user")
                user_b = item_b.get("username") or item_b.get("user")
                if user_a and user_b and str(user_a).lower() == str(user_b).lower():
                    reasons.append(f"same user: {user_a}")
                    shared_entities.append(f"user:{user_a}")

                # 3. Source IP match
                src_a = item_a.get("src_ip")
                src_b = item_b.get("src_ip")
                if src_a and src_b and str(src_a) == str(src_b):
                    reasons.append(f"same source IP: {src_a}")
                    shared_entities.append(f"ip:{src_a}")

                # 4. Destination IP match
                dst_a = item_a.get("dst_ip")
                dst_b = item_b.get("dst_ip")
                if dst_a and dst_b and str(dst_a) == str(dst_b):
                    reasons.append(f"same destination IP: {dst_a}")
                    shared_entities.append(f"ip:{dst_a}")

                # 5. Process / Executable match
                proc_a = item_a.get("process_name") or item_a.get("process")
                proc_b = item_b.get("process_name") or item_b.get("process")
                if proc_a and proc_b and str(proc_a).lower() == str(proc_b).lower():
                    reasons.append(f"same process: {proc_a}")
                    shared_entities.append(f"process:{proc_a}")

                # 6. Temporal proximity
                ts_a = self._parse_iso(item_a.get("timestamp") or item_a.get("created_at"))
                ts_b = self._parse_iso(item_b.get("timestamp") or item_b.get("created_at"))
                temp_distance: Optional[float] = None

                if ts_a and ts_b:
                    diff = abs((ts_a - ts_b).total_seconds())
                    temp_distance = diff
                    if diff <= self.temporal_window:
                        reasons.append(f"temporal distance: {diff:.1f} seconds")

                # If at least 2 distinct attributes match, or 1 strong attribute + temporal proximity
                if len(reasons) >= 2 or (len(reasons) == 1 and temp_distance is not None and temp_distance <= 60.0):
                    confidence = min(1.0, 0.5 + 0.15 * len(reasons))
                    corr_type = "MULTI_ATTRIBUTE"
                    if any("same host" in r for r in reasons) and any("same user" in r for r in reasons):
                        corr_type = "SAME_HOST_AND_USER"
                    elif any("same source IP" in r for r in reasons):
                        corr_type = "SAME_SOURCE_INFRASTRUCTURE"

                    correlations.append(
                        InvestigationCorrelation(
                            correlation_id=f"corr-{case.case_id}-{uuid.uuid4().hex[:8]}",
                            case_id=case.case_id,
                            source_item=tag_a,
                            target_item=tag_b,
                            correlation_type=corr_type,
                            reasons=reasons,
                            confidence_score=round(confidence, 2),
                            temporal_distance_seconds=temp_distance,
                            shared_entities=list(set(shared_entities)),
                        )
                    )

        # Derive structured findings from correlations and evidence
        findings.extend(self._derive_findings(case, resolved_items, correlations, now_iso))

        return findings, correlations

    def _derive_findings(
        self,
        case: InvestigationCase,
        items: List[Dict[str, Any]],
        correlations: List[InvestigationCorrelation],
        now_iso: str,
    ) -> List[InvestigationFinding]:
        """Derive structured investigation findings distinguishing OBSERVED vs INFERRED."""
        findings: List[InvestigationFinding] = []

        # 1. Observed Auth Failures / Activity
        auth_events = [it for it in items if "auth" in str(it.get("source", "")).lower() or "auth" in str(it.get("event_type", "")).lower()]
        auth_failures = [
            it for it in auth_events
            if it.get("outcome") == "FAILURE" or "failed" in str(it.get("action", "")).lower() or "failed" in str(it.get("summary", "")).lower()
        ]

        if len(auth_failures) >= 3:
            affected_users = list({str(it.get("username")) for it in auth_failures if it.get("username")})
            affected_hosts = list({str(it.get("host")) for it in auth_failures if it.get("host")})
            findings.append(
                InvestigationFinding(
                    finding_id=f"fnd-{case.case_id}-auth-burst",
                    case_id=case.case_id,
                    finding_type="AUTHENTICATION_FAILURE_BURST",
                    title="Repeated Authentication Failure Sequence",
                    description=f"Identified {len(auth_failures)} authentication failures targeting users {affected_users} on {affected_hosts}.",
                    epistemic_status=EpistemicStatus.OBSERVED,
                    confidence_basis=f"Corroborated by {len(auth_failures)} distinct authoritative forensic failure events.",
                    source_references=[it.get("_citation_tag") for it in auth_failures if it.get("_citation_tag")],
                    related_entities=[f"user:{u}" for u in affected_users] + [f"host:{h}" for h in affected_hosts],
                    related_events=[str(it.get("id") or it.get("_source_id")) for it in auth_failures],
                    created_at=now_iso,
                    generated_by="DETERMINISTIC_CORRELATOR",
                )
            )

        # 2. Correlated Multi-Host or Multi-Entity Lateral Patterns
        ip_clusters: Dict[str, List[str]] = {}
        for corr in correlations:
            for entity in corr.shared_entities:
                if entity.startswith("ip:"):
                    ip = entity.split("ip:", 1)[1]
                    ip_clusters.setdefault(ip, []).append(corr.source_item)
                    ip_clusters[ip].append(corr.target_item)

        for ip, citations in ip_clusters.items():
            unique_citations = list(set(citations))
            if len(unique_citations) >= 2:
                findings.append(
                    InvestigationFinding(
                        finding_id=f"fnd-{case.case_id}-infra-{uuid.uuid4().hex[:6]}",
                        case_id=case.case_id,
                        finding_type="SHARED_INFRASTRUCTURE_PIVOT",
                        title=f"Infrastructure Convergence on IP {ip}",
                        description=f"Correlated {len(unique_citations)} investigation evidence items converging on source IP {ip}.",
                        epistemic_status=EpistemicStatus.INFERRED,
                        confidence_basis=f"Synthesized from {len(unique_citations)} correlated evidence pointers sharing IP address.",
                        source_references=unique_citations,
                        related_entities=[f"ip:{ip}"],
                        created_at=now_iso,
                        generated_by="DETERMINISTIC_CORRELATOR",
                    )
                )

        # 3. Baseline Scope Finding
        scope_entities = list(case.scope.selected_entity_ids or [])
        findings.append(
            InvestigationFinding(
                finding_id=f"fnd-{case.case_id}-scope-baseline",
                case_id=case.case_id,
                finding_type="INVESTIGATION_SCOPE_BASELINE",
                title=f"Active Case Scope: {case.title}",
                description=f"Case bound to incident {case.incident_id} with declared entity scope: {scope_entities}.",
                epistemic_status=EpistemicStatus.OBSERVED,
                confidence_basis="Declared analyst investigation scope.",
                source_references=[f"[incident:{case.incident_id}]"],
                related_entities=scope_entities,
                created_at=now_iso,
                generated_by="DETERMINISTIC_CORRELATOR",
            )
        )

        return findings

    @staticmethod
    def _parse_iso(val: Optional[str]) -> Optional[datetime]:
        if not val:
            return None
        try:
            return datetime.fromisoformat(val.replace("Z", "+00:00"))
        except Exception:
            return None
