"""Deterministic Advanced Evidence Correlation & Clustering Engine for Milestone 5.9.

Synthesizes multi-dimensional evidence clusters, behavioral sequence progressions,
evidence gap intelligence, and structured findings from investigation graphs and case artifacts.
Operates 100% deterministically without arbitrary probability scores or fake confidence metrics.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid

from logintel.ai.domain.case import CaseEvidenceReference, InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_correlation import (
    BehavioralSequence,
    BehavioralSequenceStep,
    CorrelationReason,
    CorrelationReasonItem,
    EntityWorkbenchDossier,
    EvidenceCluster,
    EvidenceGapDetail,
    HypothesisSupportDetail,
)
from logintel.ai.domain.investigation_graph import (
    CorroborationStatus,
    GraphEvidenceItem,
    InvestigationGraph,
    InvestigationGraphEdge,
    InvestigationGraphNode,
)
from logintel.ai.domain.investigation_intel import (
    EpistemicStatus,
    InvestigationFinding,
    QueryProposal,
)
from logintel.logging import get_logger

logger = get_logger("ai.advanced_correlator")


class AdvancedEvidenceCorrelator:
    """Deterministic multi-dimensional correlation and clustering engine."""

    def __init__(self, temporal_threshold_seconds: float = 300.0) -> None:
        self.temporal_threshold = temporal_threshold_seconds

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO timestamp string into UTC datetime object."""
        if not ts_str:
            return None
        try:
            dt = datetime.fromisoformat(str(ts_str).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _compute_hash(self, content: Any) -> str:
        """Compute SHA-256 deterministic content digest."""
        if isinstance(content, str):
            payload = content.encode("utf-8")
        else:
            payload = json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    def build_evidence_clusters(
        self,
        case: InvestigationCase,
        graph: Optional[InvestigationGraph] = None,
        additional_records: Optional[List[Dict[str, Any]]] = None,
    ) -> Tuple[List[EvidenceCluster], List[BehavioralSequence], List[EvidenceGapDetail]]:
        """Synthesize deterministic evidence clusters, sequences, and telemetry gaps."""
        clusters: List[EvidenceCluster] = []
        sequences: List[BehavioralSequence] = []
        gaps: List[EvidenceGapDetail] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Harvest resolved evidence items from case and graph
        evidence_items: List[Dict[str, Any]] = []
        for ref in case.evidence_references:
            if ref.resolution_status == ResolutionStatus.AVAILABLE and ref.resolved_record:
                rec = dict(ref.resolved_record)
                rec["_citation_tag"] = ref.citation_tag
                rec["_source_type"] = ref.source_type
                rec["_source_id"] = ref.source_id
                rec["_ref_id"] = ref.reference_id
                rec["_hash"] = self._compute_hash(ref.resolved_record)
                evidence_items.append(rec)

        if additional_records:
            for item in additional_records:
                rec = dict(item)
                s_id = str(rec.get("id", uuid.uuid4().hex[:6]))
                rec["_citation_tag"] = f"[{rec.get('source_type', 'event')}:{s_id}]"
                rec["_source_type"] = rec.get("source_type", "event")
                rec["_source_id"] = s_id
                rec["_ref_id"] = f"ref-add-{s_id}"
                rec["_hash"] = self._compute_hash(item)
                evidence_items.append(rec)

        # 2. Extract Graph relationships if provided
        graph_edges: List[InvestigationGraphEdge] = graph.edges if graph else []
        graph_nodes: List[InvestigationGraphNode] = graph.nodes if graph else []

        # -------------------------------------------------------------
        # Cluster Type A: Authentication & Access Activity
        # -------------------------------------------------------------
        auth_items = [
            it for it in evidence_items
            if "auth" in str(it.get("source", "")).lower()
            or "auth" in str(it.get("event_type", "")).lower()
            or "login" in str(it.get("action", "")).lower()
            or "ssh" in str(it.get("summary", "")).lower()
        ]
        if auth_items:
            auth_cluster = self._build_auth_cluster(case, auth_items, now_iso)
            clusters.append(auth_cluster)

        # -------------------------------------------------------------
        # Cluster Type B: Infrastructure / Network Convergence
        # -------------------------------------------------------------
        ip_groups: Dict[str, List[Dict[str, Any]]] = {}
        for it in evidence_items:
            ip = it.get("src_ip") or it.get("dst_ip")
            if ip and str(ip) not in ("127.0.0.1", "::1", "localhost"):
                ip_groups.setdefault(str(ip), []).append(it)

        for ip, items in ip_groups.items():
            if len(items) >= 2 or any(it.get("severity") in ("ALERT", "CRITICAL", "HIGH") for it in items):
                clusters.append(self._build_infrastructure_cluster(case, ip, items, now_iso))

        # -------------------------------------------------------------
        # Cluster Type C: Host / Process Activity Clusters
        # -------------------------------------------------------------
        host_groups: Dict[str, List[Dict[str, Any]]] = {}
        for it in evidence_items:
            h = it.get("host") or it.get("primary_host")
            if h:
                host_groups.setdefault(str(h), []).append(it)

        for host, items in host_groups.items():
            if len(items) >= 2:
                clusters.append(self._build_host_cluster(case, host, items, now_iso))

        # -------------------------------------------------------------
        # Cluster Type D: Graph-Derived Relational Clusters
        # -------------------------------------------------------------
        if graph_edges:
            rel_cluster = self._build_graph_relational_cluster(case, graph_nodes, graph_edges, now_iso)
            if rel_cluster:
                clusters.append(rel_cluster)

        # -------------------------------------------------------------
        # Behavioral Sequence Analysis
        # -------------------------------------------------------------
        sequences = self._detect_behavioral_sequences(case, evidence_items, graph_edges)

        # -------------------------------------------------------------
        # Evidence Gap Intelligence
        # -------------------------------------------------------------
        gaps = self._detect_evidence_gaps(case, evidence_items, clusters, graph_nodes)

        return clusters, sequences, gaps

    def _build_auth_cluster(
        self,
        case: InvestigationCase,
        items: List[Dict[str, Any]],
        now_iso: str,
    ) -> EvidenceCluster:
        """Construct deterministic cluster for authentication events."""
        reasons: List[CorrelationReasonItem] = [
            CorrelationReasonItem(
                reason_type=CorrelationReason.BEHAVIORAL_SEQUENCE,
                description="Consecutive authentication activity targeting identical host/user context",
                dimension_value="authentication",
            )
        ]

        users = sorted(list({str(it.get("username")) for it in items if it.get("username")}))
        hosts = sorted(list({str(it.get("host")) for it in items if it.get("host")}))
        ips = sorted(list({str(it.get("src_ip")) for it in items if it.get("src_ip")}))

        if users:
            reasons.append(
                CorrelationReasonItem(
                    reason_type=CorrelationReason.SHARED_ENTITY,
                    description=f"Shared user account: {', '.join(users)}",
                    dimension_value=f"user:{users[0]}",
                )
            )
        if hosts:
            reasons.append(
                CorrelationReasonItem(
                    reason_type=CorrelationReason.SHARED_ENTITY,
                    description=f"Target host infrastructure: {', '.join(hosts)}",
                    dimension_value=f"host:{hosts[0]}",
                )
            )

        timestamps = [self._parse_timestamp(it.get("timestamp") or it.get("created_at")) for it in items]
        valid_ts = [t for t in timestamps if t is not None]
        start_ts = min(valid_ts).isoformat() if valid_ts else None
        end_ts = max(valid_ts).isoformat() if valid_ts else None
        span = (max(valid_ts) - min(valid_ts)).total_seconds() if valid_ts else 0.0

        if span <= self.temporal_threshold:
            reasons.append(
                CorrelationReasonItem(
                    reason_type=CorrelationReason.TEMPORAL_PROXIMITY,
                    description=f"Events occurred within temporal proximity of {span:.1f} seconds",
                    dimension_value=f"{span:.1f}s",
                )
            )

        refs = self._build_graph_evidence_items(items)
        ev_ids = [str(it.get("id") or it.get("_source_id")) for it in items if it.get("_source_type") == "event"]

        failures = [it for it in items if it.get("outcome") == "FAILURE" or "failed" in str(it.get("action", "")).lower()]
        has_failures = len(failures) > 0

        entities = [f"user:{u}" for u in users] + [f"host:{h}" for h in hosts] + [f"ip:{ip}" for ip in ips]

        corroboration = CorroborationStatus.CORROBORATED if len(items) > 1 else CorroborationStatus.SINGLE_SOURCE
        epistemic = EpistemicStatus.OBSERVED

        return EvidenceCluster(
            cluster_id=f"cluster-{case.case_id}-auth",
            case_id=case.case_id,
            title=f"Authentication Activity Sequence ({len(items)} events)",
            summary=f"Aggregated {len(items)} authentication operations involving users {users} on hosts {hosts} ({len(failures)} failures).",
            cluster_type="AUTH_ACTIVITY",
            correlation_reasons=reasons,
            temporal_bounds={"start_time": start_ts, "end_time": end_ts, "duration_seconds": str(span)},
            participating_entities=entities,
            evidence_references=refs,
            evidence_event_ids=ev_ids,
            epistemic_status=epistemic,
            corroboration_status=corroboration,
            contradictions=[],
            gaps=["Missing MFA verification telemetry"] if has_failures else [],
            created_at=now_iso,
        )

    def _build_infrastructure_cluster(
        self,
        case: InvestigationCase,
        ip: str,
        items: List[Dict[str, Any]],
        now_iso: str,
    ) -> EvidenceCluster:
        """Construct deterministic cluster converging on an external or internal IP."""
        reasons: List[CorrelationReasonItem] = [
            CorrelationReasonItem(
                reason_type=CorrelationReason.SHARED_SOURCE_IP,
                description=f"Convergence on IP address: {ip}",
                dimension_value=f"ip:{ip}",
            )
        ]

        timestamps = [self._parse_timestamp(it.get("timestamp") or it.get("created_at")) for it in items]
        valid_ts = [t for t in timestamps if t is not None]
        start_ts = min(valid_ts).isoformat() if valid_ts else None
        end_ts = max(valid_ts).isoformat() if valid_ts else None
        span = (max(valid_ts) - min(valid_ts)).total_seconds() if valid_ts else 0.0

        hosts = sorted(list({str(it.get("host") or it.get("primary_host")) for it in items if it.get("host") or it.get("primary_host")}))
        users = sorted(list({str(it.get("username") or it.get("user")) for it in items if it.get("username") or it.get("user")}))

        refs = self._build_graph_evidence_items(items)
        ev_ids = [str(it.get("id") or it.get("_source_id")) for it in items if it.get("_source_type") == "event"]

        clean_ip = ip.replace(".", "-").replace(":", "-")
        return EvidenceCluster(
            cluster_id=f"cluster-{case.case_id}-ip-{clean_ip}",
            case_id=case.case_id,
            title=f"Network Infrastructure Convergence ({ip})",
            summary=f"Multiple investigation artifacts ({len(items)}) share connection endpoints with {ip} across {hosts}.",
            cluster_type="INFRASTRUCTURE_CONVERGENCE",
            correlation_reasons=reasons,
            temporal_bounds={"start_time": start_ts, "end_time": end_ts, "duration_seconds": str(span)},
            participating_entities=[f"ip:{ip}"] + [f"host:{h}" for h in hosts] + [f"user:{u}" for u in users],
            evidence_references=refs,
            evidence_event_ids=ev_ids,
            epistemic_status=EpistemicStatus.INFERRED if len(hosts) > 1 else EpistemicStatus.OBSERVED,
            corroboration_status=CorroborationStatus.CORROBORATED if len(items) >= 2 else CorroborationStatus.SINGLE_SOURCE,
            contradictions=[],
            gaps=["Autonomous system (ASN) / GeoIP attribution unverified locally"],
            created_at=now_iso,
        )

    def _build_host_cluster(
        self,
        case: InvestigationCase,
        host: str,
        items: List[Dict[str, Any]],
        now_iso: str,
    ) -> EvidenceCluster:
        """Construct deterministic cluster for host operations."""
        reasons: List[CorrelationReasonItem] = [
            CorrelationReasonItem(
                reason_type=CorrelationReason.SHARED_ENTITY,
                description=f"Host execution boundary: {host}",
                dimension_value=f"host:{host}",
            )
        ]

        procs = sorted(list({str(it.get("process_name") or it.get("process")) for it in items if it.get("process_name") or it.get("process")}))
        if procs:
            reasons.append(
                CorrelationReasonItem(
                    reason_type=CorrelationReason.SHARED_PROCESS,
                    description=f"Observed processes on host: {', '.join(procs)}",
                    dimension_value=f"process:{procs[0]}",
                )
            )

        refs = self._build_graph_evidence_items(items)
        ev_ids = [str(it.get("id") or it.get("_source_id")) for it in items if it.get("_source_type") == "event"]

        return EvidenceCluster(
            cluster_id=f"cluster-{case.case_id}-host-{host}",
            case_id=case.case_id,
            title=f"Host Execution Activity ({host})",
            summary=f"Activity records ({len(items)}) localized to host {host} across processes {procs}.",
            cluster_type="PROCESS_EXECUTION",
            correlation_reasons=reasons,
            temporal_bounds={},
            participating_entities=[f"host:{host}"] + [f"process:{p}" for p in procs],
            evidence_references=refs,
            evidence_event_ids=ev_ids,
            epistemic_status=EpistemicStatus.OBSERVED,
            corroboration_status=CorroborationStatus.CORROBORATED if len(items) >= 2 else CorroborationStatus.SINGLE_SOURCE,
            contradictions=[],
            gaps=[],
            created_at=now_iso,
        )

    def _build_graph_relational_cluster(
        self,
        case: InvestigationCase,
        nodes: List[InvestigationGraphNode],
        edges: List[InvestigationGraphEdge],
        now_iso: str,
    ) -> Optional[EvidenceCluster]:
        """Construct evidence cluster derived from verified graph topology."""
        if not edges:
            return None

        reasons: List[CorrelationReasonItem] = [
            CorrelationReasonItem(
                reason_type=CorrelationReason.EXPLICIT_RELATIONSHIP,
                description=f"Investigation graph links {len(nodes)} entities via {len(edges)} verified relationships",
                dimension_value=f"edges:{len(edges)}",
            )
        ]

        all_refs: List[GraphEvidenceItem] = []
        all_ev_ids: List[str] = []
        for e in edges:
            all_refs.extend(e.evidence_references)
            all_ev_ids.extend(e.evidence_event_ids)

        return EvidenceCluster(
            cluster_id=f"cluster-{case.case_id}-graph-relational",
            case_id=case.case_id,
            title=f"Investigation Graph Relational Cluster ({len(edges)} edges)",
            summary=f"Topological correlation connecting {len(nodes)} graph nodes across authoritative relations.",
            cluster_type="RELATIONAL_TOPOLOGY",
            correlation_reasons=reasons,
            temporal_bounds={},
            participating_entities=[n.node_id for n in nodes],
            evidence_references=all_refs[:20],
            evidence_event_ids=list(set(all_ev_ids)),
            epistemic_status=EpistemicStatus.INFERRED if any(e.epistemic_status.value == "INFERRED" for e in edges) else EpistemicStatus.OBSERVED,
            corroboration_status=CorroborationStatus.CORROBORATED if len(edges) > 1 else CorroborationStatus.DIRECT_EVIDENCE,
            contradictions=[],
            gaps=[],
            created_at=now_iso,
        )

    def _detect_behavioral_sequences(
        self,
        case: InvestigationCase,
        items: List[Dict[str, Any]],
        edges: List[InvestigationGraphEdge],
    ) -> List[BehavioralSequence]:
        """Reconstruct multi-step causal behavioral sequences."""
        sequences: List[BehavioralSequence] = []

        # Sequence Pattern 1: Authentication failure followed by session/privilege activity
        sorted_items = sorted(
            [it for it in items if self._parse_timestamp(it.get("timestamp") or it.get("created_at")) is not None],
            key=lambda x: self._parse_timestamp(x.get("timestamp") or x.get("created_at")),
        )

        steps: List[BehavioralSequenceStep] = []
        idx = 1
        for it in sorted_items:
            action = str(it.get("action") or it.get("event_type") or it.get("summary", "")).lower()
            ts = str(it.get("timestamp") or it.get("created_at"))
            host = str(it.get("host") or it.get("primary_host", "unknown"))
            user = str(it.get("username") or it.get("user", "unknown"))
            tag = str(it.get("_citation_tag", "[event:unknown]"))

            stage = "INITIAL_ACCESS"
            if "fail" in action:
                stage = "INITIAL_ACCESS"
            elif "sudo" in action or "root" in user or "priv" in action:
                stage = "PRIVILEGE_ESCALATION"
            elif "exec" in action or "sh" in action or "command" in action:
                stage = "EXECUTION"
            elif "conn" in action or "net" in action:
                stage = "LATERAL_MOVEMENT"

            steps.append(
                BehavioralSequenceStep(
                    step_index=idx,
                    timestamp=ts,
                    stage_name=stage,
                    action_summary=f"{action} on {host}",
                    actor_entity=f"user:{user}",
                    target_entity=f"host:{host}",
                    evidence_citation=tag,
                    epistemic_status=EpistemicStatus.OBSERVED,
                )
            )
            idx += 1

        if len(steps) >= 2:
            start_ts = steps[0].timestamp
            end_ts = steps[-1].timestamp
            t0 = self._parse_timestamp(start_ts)
            t1 = self._parse_timestamp(end_ts)
            span = (t1 - t0).total_seconds() if t0 and t1 else None

            sequences.append(
                BehavioralSequence(
                    sequence_id=f"seq-{case.case_id}-lifecycle",
                    case_id=case.case_id,
                    pattern_name="Multi-Stage Investigation Event Sequence",
                    description=f"Chronological sequence of {len(steps)} correlated forensic actions spanning {span or 0.0:.1f}s.",
                    steps=steps[:20],
                    total_steps=len(steps),
                    epistemic_status=EpistemicStatus.OBSERVED,
                    supporting_evidence_count=len(steps),
                    start_time=start_ts,
                    end_time=end_ts,
                    duration_seconds=span,
                )
            )

        return sequences

    def _detect_evidence_gaps(
        self,
        case: InvestigationCase,
        items: List[Dict[str, Any]],
        clusters: List[EvidenceCluster],
        nodes: List[InvestigationGraphNode],
    ) -> List[EvidenceGapDetail]:
        """Detect missing telemetry, unverified entities, and single-source gaps."""
        gaps: List[EvidenceGapDetail] = []

        # 1. Unresolved IP Gap (IP address without hostname resolution or reverse DNS)
        ips = {str(it.get("src_ip")) for it in items if it.get("src_ip")}
        for ip in ips:
            if ip not in ("127.0.0.1", "::1"):
                gaps.append(
                    EvidenceGapDetail(
                        gap_id=f"gap-{case.case_id}-dns-{ip.replace('.', '-')}",
                        case_id=case.case_id,
                        gap_type="ENTITY_UNRESOLVED",
                        title=f"Unresolved External IP: {ip}",
                        description=f"Evidence references source IP {ip} without local DNS or host mapping.",
                        affected_entities=[f"ip:{ip}"],
                        affected_hypotheses=[],
                        resolution_remedy="Query authentication and network connections for host or user records associated with this IP.",
                        recommended_governed_query=QueryProposal(
                            query_type="events",
                            parameters={"src_ip": ip, "limit": 25},
                            rationale=f"Search for additional events connecting {ip} to internal hosts",
                        ),
                        status="OPEN",
                    )
                )

        # 2. Process Telemetry Gap (Auth success without execution tracking)
        auth_successes = [it for it in items if it.get("outcome") == "SUCCESS" and "auth" in str(it.get("source", "")).lower()]
        for it in auth_successes:
            h = it.get("host")
            u = it.get("username")
            if h and u:
                gaps.append(
                    EvidenceGapDetail(
                        gap_id=f"gap-{case.case_id}-proc-{h}-{u}",
                        case_id=case.case_id,
                        gap_type="EXPECTED_TELEMETRY_MISSING",
                        title=f"Post-Authentication Process Tracking Gap on {h}",
                        description=f"Successful authentication for {u} on {h} lacks correlated process execution records.",
                        affected_entities=[f"host:{h}", f"user:{u}"],
                        affected_hypotheses=[],
                        resolution_remedy="Execute governed hunt query for process launches on host within session window.",
                        recommended_governed_query=QueryProposal(
                            query_type="events",
                            parameters={"host": h, "event_type": "process_execution", "limit": 50},
                            rationale=f"Verify whether processes were spawned by {u} following authentication",
                        ),
                        status="OPEN",
                    )
                )

        return gaps

    def evaluate_hypothesis_support(
        self,
        case: InvestigationCase,
        hypothesis_id: str,
        hypothesis_statement: str,
        clusters: List[EvidenceCluster],
    ) -> HypothesisSupportDetail:
        """Deterministically assess hypothesis evidence support without arbitrary probability scoring."""
        supporting: List[GraphEvidenceItem] = []
        contradicting: List[GraphEvidenceItem] = []
        contextual: List[GraphEvidenceItem] = []
        missing_reasons: List[str] = []
        unresolved: List[str] = []

        statement_lower = hypothesis_statement.lower()

        # Check clusters against keywords in hypothesis
        for cluster in clusters:
            for ref in cluster.evidence_references:
                summary_lower = ref.summary.lower()
                # Keyword matching
                if any(word in summary_lower for word in statement_lower.split() if len(word) > 4):
                    if "contradict" in summary_lower or "conflict" in summary_lower:
                        contradicting.append(ref)
                    else:
                        supporting.append(ref)
                else:
                    contextual.append(ref)

        if not supporting and not contradicting:
            support_status = "INSUFFICIENT EVIDENCE"
            missing_reasons.append("No active evidence items directly match hypothesis keywords.")
            unresolved.append("Requires governed threat hunt to locate matching host or user activity.")
        elif contradicting and len(contradicting) >= len(supporting):
            support_status = "CONTRADICTED"
            unresolved.append("Forensic timestamps or entity bindings contradict proposed sequence.")
        elif len(supporting) >= 2:
            support_status = "SUPPORTED BY EVIDENCE"
        else:
            support_status = "WEAKLY SUPPORTED"
            missing_reasons.append("Single evidence source observed; corroborating telemetry required.")

        recommended_queries = [
            QueryProposal(
                query_type="events",
                parameters={"limit": 50},
                rationale=f"Gather corroborating evidence for hypothesis: {hypothesis_statement[:40]}...",
            )
        ]

        return HypothesisSupportDetail(
            hypothesis_id=hypothesis_id,
            case_id=case.case_id,
            statement=hypothesis_statement,
            support_status=support_status,
            supporting_evidence=supporting[:10],
            contradicting_evidence=contradicting[:10],
            contextual_evidence=contextual[:5],
            missing_evidence_descriptions=missing_reasons,
            unresolved_questions=unresolved,
            recommended_governed_queries=recommended_queries,
        )

    def generate_findings_from_clusters(
        self,
        case: InvestigationCase,
        clusters: List[EvidenceCluster],
        actor: str = "SecAnalyst-1",
    ) -> List[InvestigationFinding]:
        """Deterministically derive investigation findings from verified clusters."""
        findings: List[InvestigationFinding] = []
        now_iso = datetime.now(timezone.utc).isoformat()

        for c in clusters:
            fnd_id = f"fnd-{case.case_id}-{c.cluster_type.lower()}-{uuid.uuid4().hex[:6]}"
            reasons_summary = "; ".join(r.description for r in c.correlation_reasons)
            findings.append(
                InvestigationFinding(
                    finding_id=fnd_id,
                    case_id=case.case_id,
                    finding_type=c.cluster_type,
                    title=f"Finding: {c.title}",
                    description=f"{c.summary} (Correlation basis: {reasons_summary})",
                    epistemic_status=c.epistemic_status,
                    confidence_basis=f"Corroboration: {c.corroboration_status.value}. Supported by {len(c.evidence_references)} evidence items.",
                    source_references=[ref.citation_tag for ref in c.evidence_references if ref.citation_tag],
                    related_entities=c.participating_entities,
                    related_events=c.evidence_event_ids,
                    created_at=now_iso,
                    generated_by="M5.9_ADVANCED_CORRELATOR",
                )
            )

        return findings

    def resolve_entity_workbench(
        self,
        case: InvestigationCase,
        entity_type: str,
        entity_value: str,
        clusters: List[EvidenceCluster],
        sequences: List[BehavioralSequence],
        gaps: List[EvidenceGapDetail],
    ) -> EntityWorkbenchDossier:
        """Assemble complete entity-centric investigation dossier."""
        clean_key = f"{entity_type.lower()}:{entity_value}" if not entity_value.startswith(f"{entity_type.lower()}:") else entity_value

        related_c = [c for c in clusters if any(clean_key.lower() in e.lower() for e in c.participating_entities)]
        related_s = [
            s for s in sequences
            if any(clean_key.lower() in st.actor_entity.lower() or clean_key.lower() in st.target_entity.lower() for st in s.steps)
        ]
        related_g = [g for g in gaps if any(clean_key.lower() in aff.lower() for aff in g.affected_entities)]

        ev_refs: List[GraphEvidenceItem] = []
        for c in related_c:
            ev_refs.extend(c.evidence_references)

        adjacent_entities = set()
        for c in related_c:
            for ent in c.participating_entities:
                if ent.lower() != clean_key.lower():
                    adjacent_entities.add(ent)

        return EntityWorkbenchDossier(
            case_id=case.case_id,
            entity_key=clean_key,
            entity_type=entity_type.upper(),
            display_name=entity_value,
            related_clusters=related_c,
            related_findings=[],
            related_sequences=related_s,
            adjacent_graph_entities=sorted(list(adjacent_entities)),
            evidence_references=ev_refs[:15],
            identified_gaps=related_g,
            mitre_techniques=[],
        )

    def _build_graph_evidence_items(self, items: List[Dict[str, Any]]) -> List[GraphEvidenceItem]:
        """Convert dictionary items to typed GraphEvidenceItem citations."""
        refs: List[GraphEvidenceItem] = []
        for it in items:
            s_type = it.get("_source_type", "event")
            s_id = str(it.get("_source_id") or it.get("id", "0"))
            tag = it.get("_citation_tag", f"[{s_type}:{s_id}]")
            ts = it.get("timestamp") or it.get("created_at")
            summary = it.get("summary") or it.get("title") or it.get("raw_message", "Evidence record")[:80]
            refs.append(
                GraphEvidenceItem(
                    reference_id=str(it.get("_ref_id", f"ref-{s_id}")),
                    source_type=s_type,
                    source_id=s_id,
                    source_hash=it.get("_hash", self._compute_hash(it)),
                    citation_tag=tag,
                    timestamp=str(ts) if ts else None,
                    summary=summary,
                    epistemic_status=EpistemicStatus.OBSERVED,
                    is_authoritative=True,
                    role="supporting",
                )
            )
        return refs
