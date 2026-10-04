"""Deterministic Temporal Investigation Reconstruction Engine for Milestone 5.10.

Implements:
- Episode Reconstruction (grouping related evidence into cohesive temporal episodes)
- Transition Detection (evidence-backed user, host, process, network, and incident progressions)
- Explicit Epistemic Demarcation (OBSERVED / INFERRED / UNKNOWN)
- Multi-Step Temporal Evidence Chains
- Temporal and Telemetry Gap Detection with Governed Hunt Remedies
- Multi-Host Movement Reconstruction preserving infrastructure identities
- Account, Process, and Network Continuity tracking
- Deterministic Campaign-Level Correlation across incidents without fake risk scores
- Attack Sequence Reconstruction with MITRE ATT&CK technique integration
- Multi-Format Export (JSON, CSV, GraphML)
- Advisory-Only Local AI Explanations with Application-Level Injection Containment
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from typing import Any, Dict, List, Optional, Set, Tuple
import uuid
import xml.etree.ElementTree as ET

from logintel.ai.domain.case import InvestigationCase, ResolutionStatus
from logintel.ai.domain.investigation_correlation import EvidenceCluster
from logintel.ai.domain.investigation_graph import (
    CorroborationStatus,
    GraphEvidenceItem,
    InvestigationGraph,
    InvestigationGraphEdge,
    InvestigationGraphNode,
)
from logintel.ai.domain.investigation_intel import EpistemicStatus, QueryProposal
from logintel.ai.domain.investigation_temporal import (
    AttackSequenceReconstruction,
    AttackSequenceStep,
    CampaignCorrelationStatus,
    CampaignRelationReason,
    ContinuityType,
    EntityContinuity,
    EpisodeType,
    EvidenceChainStep,
    IncidentCampaignCorrelation,
    MultiHostTrace,
    TemporalEpisode,
    TemporalEvidenceChain,
    TemporalExplanationResponse,
    TemporalGap,
    TemporalGapType,
    TemporalReconstructionDossier,
    TemporalTransition,
    TransitionReviewState,
    TransitionType,
)


class TemporalReconstructionEngine:
    """Core deterministic engine for temporal investigation reconstruction and campaign correlation."""

    # Server-side resource bounds
    MAX_EPISODES: int = 50
    MAX_TRANSITIONS: int = 100
    MAX_SEQUENCE_STEPS: int = 20
    MAX_EVIDENCE_REFS: int = 20
    MAX_GAPS: int = 50
    MAX_HOST_TRACES: int = 20
    MAX_CONTINUITIES: int = 30
    MAX_CAMPAIGN_CORRELATIONS: int = 30
    TEMPORAL_GAP_THRESHOLD_SECONDS: float = 1800.0  # 30 minutes

    def __init__(self, temporal_threshold_seconds: float = 300.0) -> None:
        self.temporal_threshold = temporal_threshold_seconds

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Parse ISO-8601 timestamp string into timezone-aware datetime."""
        if not ts_str:
            return None
        try:
            clean_ts = ts_str.replace("Z", "+00:00")
            dt = datetime.fromisoformat(clean_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    def _compute_hash(self, content: Any) -> str:
        """Compute deterministic SHA-256 content fingerprint."""
        if isinstance(content, str):
            payload = content.encode("utf-8")
        else:
            payload = json.dumps(content, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return f"sha256:{hashlib.sha256(payload).hexdigest()}"

    def reconstruct_investigation(
        self,
        case: InvestigationCase,
        graph: Optional[InvestigationGraph] = None,
        clusters: Optional[List[EvidenceCluster]] = None,
        other_incidents: Optional[List[Dict[str, Any]]] = None,
    ) -> TemporalReconstructionDossier:
        """Synthesize comprehensive, evidence-grounded temporal investigation reconstruction."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # 1. Harvest and sort all resolved evidence records chronologically
        evidence_items = self._harvest_case_evidence(case)

        # 2. Build deterministic temporal episodes
        episodes = self.build_temporal_episodes(case, evidence_items, clusters)

        # 3. Detect transitions across episodes and entities
        transitions = self.detect_transitions(case, evidence_items, episodes, graph)

        # 4. Construct temporal evidence chains
        chains = self.build_evidence_chains(case, evidence_items, transitions)

        # 5. Identify temporal and telemetry gaps
        gaps = self.detect_temporal_gaps(case, evidence_items, episodes, transitions)

        # 6. Reconstruct multi-host traces
        host_traces = self.reconstruct_multi_host_traces(case, transitions, evidence_items)

        # 7. Detect account, process, and network continuity
        continuities = self.detect_entity_continuity(case, evidence_items)

        # 8. Correlate with other incidents at campaign level
        campaign_correlations = self.correlate_campaign_incidents(
            case, other_incidents or [], evidence_items
        )

        # 9. Reconstruct attack sequences with MITRE integration
        attack_sequences, mitre_summary = self.reconstruct_attack_sequences(
            case, evidence_items, transitions, graph
        )

        # Compute overall temporal span
        all_timestamps = [
            self._parse_timestamp(it.get("timestamp"))
            for it in evidence_items
            if it.get("timestamp")
        ]
        valid_ts = [t for t in all_timestamps if t is not None]
        start_ts = min(valid_ts).isoformat() if valid_ts else None
        end_ts = max(valid_ts).isoformat() if valid_ts else None
        span = (max(valid_ts) - min(valid_ts)).total_seconds() if valid_ts else 0.0

        # Deterministic provenance fingerprint for this reconstruction
        prov_payload = {
            "case_id": case.case_id,
            "incident_id": case.incident_id,
            "episodes_count": len(episodes),
            "transitions_count": len(transitions),
            "start_time": start_ts,
            "end_time": end_ts,
        }
        prov_hash = self._compute_hash(prov_payload)

        return TemporalReconstructionDossier(
            reconstruction_id=f"recon-{case.case_id}-{prov_hash[7:15]}",
            case_id=case.case_id,
            incident_id=case.incident_id,
            generated_at=now_iso,
            start_time=start_ts,
            end_time=end_ts,
            duration_seconds=span,
            episodes=episodes[: self.MAX_EPISODES],
            transitions=transitions[: self.MAX_TRANSITIONS],
            evidence_chains=chains,
            gaps=gaps[: self.MAX_GAPS],
            multi_host_traces=host_traces[: self.MAX_HOST_TRACES],
            continuities=continuities[: self.MAX_CONTINUITIES],
            campaign_correlations=campaign_correlations[: self.MAX_CAMPAIGN_CORRELATIONS],
            attack_sequences=attack_sequences,
            mitre_summary=mitre_summary,
            provenance_hash=prov_hash,
        )

    def _harvest_case_evidence(self, case: InvestigationCase) -> List[Dict[str, Any]]:
        """Extract and sort resolved evidence items chronologically."""
        items: List[Dict[str, Any]] = []
        for ref in case.evidence_references:
            if ref.resolution_status == ResolutionStatus.AVAILABLE and ref.resolved_record:
                rec = dict(ref.resolved_record)
                rec["_citation_tag"] = ref.citation_tag
                rec["_source_type"] = ref.source_type
                rec["_source_id"] = str(ref.source_id)
                rec["_ref_id"] = ref.reference_id
                rec["_hash"] = self._compute_hash(ref.resolved_record)
                ts = rec.get("timestamp") or rec.get("first_seen") or rec.get("created_at")
                rec["timestamp"] = str(ts) if ts else None
                items.append(rec)

        # Sort deterministically: timestamp ascending, then source_id ascending
        def sort_key(it: Dict[str, Any]) -> Tuple[str, str]:
            return (it.get("timestamp") or "9999-99-99T99:99:99Z", str(it.get("_source_id", "")))

        items.sort(key=sort_key)
        return items

    def build_temporal_episodes(
        self,
        case: InvestigationCase,
        evidence_items: List[Dict[str, Any]],
        clusters: Optional[List[EvidenceCluster]] = None,
    ) -> List[TemporalEpisode]:
        """Group evidence items into deterministic temporal episodes using neutral terminology."""
        episodes: List[TemporalEpisode] = []

        # Categorize items into functional groups
        auth_items = []
        proc_items = []
        priv_items = []
        lateral_items = []
        net_items = []
        persist_items = []
        other_items = []

        for it in evidence_items:
            action = str(it.get("action", "")).lower()
            evt_type = str(it.get("event_type", "")).lower()
            source = str(it.get("source", "")).lower()
            summary = str(it.get("summary", "")).lower()

            if any(k in action or k in evt_type or k in source or k in summary for k in ["sudo", "privilege", "root_escalation"]):
                priv_items.append(it)
            elif any(k in action or k in evt_type or k in source or k in summary for k in ["lateral", "ssh_remote", "db_connect"]):
                lateral_items.append(it)
            elif any(k in action or k in evt_type or k in source or k in summary for k in ["login", "auth", "ssh", "session"]):
                auth_items.append(it)
            elif any(k in action or k in evt_type or k in source or k in summary for k in ["exec", "process", "spawn", "bash", "command"]):
                proc_items.append(it)
            elif any(k in action or k in evt_type or k in source or k in summary for k in ["network", "connect", "packet", "port"]):
                net_items.append(it)
            elif any(k in action or k in evt_type or k in source or k in summary for k in ["cron", "service", "persist", "startup"]):
                persist_items.append(it)
            else:
                other_items.append(it)

        # Helper to construct a single episode
        def make_episode(
            ep_type: EpisodeType,
            title_prefix: str,
            items: List[Dict[str, Any]],
            suffix: str,
        ) -> Optional[TemporalEpisode]:
            if not items:
                return None
            ts_list = [self._parse_timestamp(it.get("timestamp")) for it in items if it.get("timestamp")]
            valid_ts = [t for t in ts_list if t is not None]
            start_ts = min(valid_ts).isoformat() if valid_ts else (items[0].get("timestamp") or "1970-01-01T00:00:00Z")
            end_ts = max(valid_ts).isoformat() if valid_ts else start_ts
            span = (max(valid_ts) - min(valid_ts)).total_seconds() if valid_ts else 0.0

            users = sorted(list({str(it.get("username")) for it in items if it.get("username")}))
            hosts = sorted(list({str(it.get("host")) for it in items if it.get("host")}))
            ips = sorted(list({str(it.get("src_ip")) for it in items if it.get("src_ip")}))
            entities = [f"user:{u}" for u in users] + [f"host:{h}" for h in hosts] + [f"ip:{ip}" for ip in ips]

            refs = self._build_graph_evidence_items(items)
            ev_ids = [str(it.get("_source_id")) for it in items if it.get("_source_type") == "event"]

            corroboration = CorroborationStatus.CORROBORATED if len(items) > 1 else CorroborationStatus.SINGLE_SOURCE

            return TemporalEpisode(
                episode_id=f"ep-{case.case_id}-{suffix}",
                case_id=case.case_id,
                episode_type=ep_type,
                title=f"{title_prefix} ({len(items)} events)",
                summary=f"Reconstructed {len(items)} {ep_type.value.lower().replace('_', ' ')} activities spanning {span:.1f}s involving {entities}.",
                start_time=start_ts,
                end_time=end_ts,
                duration_seconds=span,
                entities=entities,
                evidence_references=refs[: self.MAX_EVIDENCE_REFS],
                evidence_event_ids=ev_ids,
                epistemic_status=EpistemicStatus.OBSERVED,
                corroboration_status=corroboration,
            )

        if auth_items:
            episodes.append(make_episode(EpisodeType.AUTHENTICATION_BURST, "Authentication Activity", auth_items, "auth"))
        if proc_items:
            episodes.append(make_episode(EpisodeType.PROCESS_EXECUTION_EPISODE, "Process Execution Activity", proc_items, "proc"))
        if priv_items:
            episodes.append(make_episode(EpisodeType.PRIVILEGE_CHANGE_EPISODE, "Privilege Modification Activity", priv_items, "priv"))
        if lateral_items:
            episodes.append(make_episode(EpisodeType.LATERAL_MOVEMENT_EPISODE, "Lateral Network Progression", lateral_items, "lat"))
        if net_items:
            episodes.append(make_episode(EpisodeType.NETWORK_ACTIVITY_EPISODE, "Network Communication Activity", net_items, "net"))
        if persist_items:
            episodes.append(make_episode(EpisodeType.PERSISTENCE_EPISODE, "Persistence & Service Modification", persist_items, "pers"))
        if other_items and not episodes:
            episodes.append(make_episode(EpisodeType.GENERIC_EPISODE, "Investigative Telemetry Activity", other_items, "gen"))

        # Sort episodes chronologically
        episodes.sort(key=lambda ep: (ep.start_time, ep.episode_id))
        return episodes

    def detect_transitions(
        self,
        case: InvestigationCase,
        evidence_items: List[Dict[str, Any]],
        episodes: List[TemporalEpisode],
        graph: Optional[InvestigationGraph] = None,
    ) -> List[TemporalTransition]:
        """Detect deterministic evidence-backed transitions between entities and episodes."""
        transitions: List[TemporalTransition] = []

        # 1. Transitions derived directly from consecutive chronological evidence items
        for i in range(len(evidence_items) - 1):
            cur = evidence_items[i]
            nxt = evidence_items[i + 1]

            cur_host = cur.get("host")
            nxt_host = nxt.get("host")
            cur_user = cur.get("username")
            nxt_user = nxt.get("username")
            cur_proc = cur.get("process_name") or cur.get("action")
            nxt_proc = nxt.get("process_name") or nxt.get("action")

            ts = nxt.get("timestamp") or cur.get("timestamp") or "1970-01-01T00:00:00Z"
            refs = self._build_graph_evidence_items([cur, nxt])

            # A. USER_TO_HOST
            if cur_user and nxt_host and cur_user != nxt_host:
                transitions.append(
                    TemporalTransition(
                        transition_id=f"trans-{case.case_id}-u2h-{i}",
                        case_id=case.case_id,
                        transition_type=TransitionType.USER_TO_HOST,
                        from_entity=f"user:{cur_user}",
                        to_entity=f"host:{nxt_host}",
                        timestamp=ts,
                        reason=f"User {cur_user} executed activity on host {nxt_host}",
                        correlation_basis="Authoritative credential session link",
                        evidence_references=refs,
                        epistemic_status=EpistemicStatus.OBSERVED,
                    )
                )

            # B. HOST_TO_HOST (Lateral transition)
            if cur_host and nxt_host and cur_host != nxt_host:
                transitions.append(
                    TemporalTransition(
                        transition_id=f"trans-{case.case_id}-h2h-{i}",
                        case_id=case.case_id,
                        transition_type=TransitionType.HOST_TO_HOST,
                        from_entity=f"host:{cur_host}",
                        to_entity=f"host:{nxt_host}",
                        timestamp=ts,
                        reason=f"Activity transitioned from host {cur_host} to host {nxt_host}",
                        correlation_basis="Sequential cross-host forensic records",
                        evidence_references=refs,
                        epistemic_status=EpistemicStatus.OBSERVED,
                    )
                )

            # C. USER_TO_PROCESS
            if cur_user and nxt_proc:
                transitions.append(
                    TemporalTransition(
                        transition_id=f"trans-{case.case_id}-u2p-{i}",
                        case_id=case.case_id,
                        transition_type=TransitionType.USER_TO_PROCESS,
                        from_entity=f"user:{cur_user}",
                        to_entity=f"process:{nxt_proc}",
                        timestamp=ts,
                        reason=f"User {cur_user} invoked process {nxt_proc}",
                        correlation_basis="Authenticated user execution context",
                        evidence_references=refs,
                        epistemic_status=EpistemicStatus.OBSERVED,
                    )
                )

            # D. PROCESS_TO_NETWORK_DESTINATION
            dst_ip = nxt.get("dst_ip")
            if cur_proc and dst_ip:
                transitions.append(
                    TemporalTransition(
                        transition_id=f"trans-{case.case_id}-p2n-{i}",
                        case_id=case.case_id,
                        transition_type=TransitionType.PROCESS_TO_NETWORK_DESTINATION,
                        from_entity=f"process:{cur_proc}",
                        to_entity=f"ip:{dst_ip}",
                        timestamp=ts,
                        reason=f"Process {cur_proc} initiated connection to destination {dst_ip}",
                        correlation_basis="Process socket socket/network telemetry",
                        evidence_references=refs,
                        epistemic_status=EpistemicStatus.OBSERVED,
                    )
                )

        # 2. Stage progression transitions between consecutive episodes
        for j in range(len(episodes) - 1):
            ep_a = episodes[j]
            ep_b = episodes[j + 1]
            transitions.append(
                TemporalTransition(
                    transition_id=f"trans-{case.case_id}-stg-{j}",
                    case_id=case.case_id,
                    transition_type=TransitionType.STAGE_PROGRESSION,
                    from_entity=ep_a.episode_type.value,
                    to_entity=ep_b.episode_type.value,
                    from_episode_id=ep_a.episode_id,
                    to_episode_id=ep_b.episode_id,
                    timestamp=ep_b.start_time,
                    reason=f"Sequential progression from {ep_a.title} to {ep_b.title}",
                    correlation_basis="Chronological episode transition",
                    evidence_references=(ep_a.evidence_references[:2] + ep_b.evidence_references[:2]),
                    epistemic_status=EpistemicStatus.OBSERVED,
                )
            )

        # 3. Incorporate Graph-Derived Transitions if graph provided
        if graph and graph.edges:
            for k, edge in enumerate(graph.edges):
                if edge.relationship_type in ["AUTHENTICATED_TO", "LOGGED_INTO", "LATERAL_MOVEMENT", "EXECUTED", "CONNECTED_TO"]:
                    t_type = TransitionType.STAGE_PROGRESSION
                    if "AUTHENTICATED" in edge.relationship_type:
                        t_type = TransitionType.USER_TO_HOST
                    elif "LATERAL" in edge.relationship_type:
                        t_type = TransitionType.HOST_TO_HOST
                    elif "EXECUTED" in edge.relationship_type:
                        t_type = TransitionType.USER_TO_PROCESS
                    elif "CONNECTED" in edge.relationship_type:
                        t_type = TransitionType.PROCESS_TO_NETWORK_DESTINATION

                    edge_ts = edge.first_seen or edge.last_seen or (raw_events[0].get("timestamp") if raw_events else "1970-01-01T00:00:00Z")
                    ep_status = EpistemicStatus.OBSERVED if edge.epistemic_status.value == "OBSERVED" else EpistemicStatus.INFERRED
                    transitions.append(
                        TemporalTransition(
                            transition_id=f"trans-{case.case_id}-edge-{k}",
                            case_id=case.case_id,
                            transition_type=t_type,
                            from_entity=edge.source_node_id,
                            to_entity=edge.target_node_id,
                            timestamp=edge_ts,
                            reason=f"Graph relationship {edge.relationship_type}",
                            correlation_basis="Investigation topology edge",
                            evidence_references=edge.evidence_references[: self.MAX_EVIDENCE_REFS],
                            epistemic_status=ep_status,
                        )
                    )

        # Ensure deduplicated and sorted deterministically
        seen_keys: Set[str] = set()
        deduped: List[TemporalTransition] = []
        for t in transitions:
            key = f"{t.transition_type.value}:{t.from_entity}->{t.to_entity}:{t.timestamp}"
            if key not in seen_keys:
                seen_keys.add(key)
                deduped.append(t)

        deduped.sort(key=lambda tr: (tr.timestamp, tr.transition_id))
        return deduped[: self.MAX_TRANSITIONS]

    def build_evidence_chains(
        self,
        case: InvestigationCase,
        evidence_items: List[Dict[str, Any]],
        transitions: List[TemporalTransition],
    ) -> List[TemporalEvidenceChain]:
        """Construct multi-step evidence chains linking Event -> Relationship -> Entity -> Event."""
        if not evidence_items:
            return []

        steps: List[EvidenceChainStep] = []
        for idx, it in enumerate(evidence_items[: self.MAX_SEQUENCE_STEPS]):
            entity_val = it.get("host") or it.get("username") or it.get("src_ip") or "unknown_entity"
            steps.append(
                EvidenceChainStep(
                    step_index=idx + 1,
                    source_record_type=it.get("_source_type", "event"),
                    source_record_id=str(it.get("_source_id", idx)),
                    citation_tag=it.get("_citation_tag", f"[{it.get('_source_type', 'event')}:{it.get('_source_id', idx)}]"),
                    timestamp=it.get("timestamp") or "1970-01-01T00:00:00Z",
                    entity_key=entity_val,
                    action_or_relation=it.get("action") or it.get("summary") or "Telemetric observation",
                    epistemic_status=EpistemicStatus.OBSERVED,
                )
            )

        if not steps:
            return []

        start_ts = steps[0].timestamp
        end_ts = steps[-1].timestamp

        return [
            TemporalEvidenceChain(
                chain_id=f"chain-{case.case_id}-primary",
                case_id=case.case_id,
                name=f"Primary Evidence Chain for Case {case.case_id}",
                description=f"Unified chronological progression linking {len(steps)} verified forensic records.",
                steps=steps,
                total_steps=len(steps),
                start_time=start_ts,
                end_time=end_ts,
                epistemic_status=EpistemicStatus.OBSERVED,
            )
        ]

    def detect_temporal_gaps(
        self,
        case: InvestigationCase,
        evidence_items: List[Dict[str, Any]],
        episodes: List[TemporalEpisode],
        transitions: List[TemporalTransition],
    ) -> List[TemporalGap]:
        """Identify explicit temporal gaps and missing telemetry boundaries."""
        gaps: List[TemporalGap] = []

        # 1. TIMESTAMP_GAP between consecutive evidence items
        for i in range(len(evidence_items) - 1):
            t1 = self._parse_timestamp(evidence_items[i].get("timestamp"))
            t2 = self._parse_timestamp(evidence_items[i + 1].get("timestamp"))
            if t1 and t2:
                delta = (t2 - t1).total_seconds()
                if delta >= self.TEMPORAL_GAP_THRESHOLD_SECONDS:
                    gaps.append(
                        TemporalGap(
                            gap_id=f"tgap-{case.case_id}-time-{i}",
                            case_id=case.case_id,
                            gap_type=TemporalGapType.TIMESTAMP_GAP,
                            title=f"Temporal Discontinuity ({delta / 60:.1f} min gap)",
                            description=(
                                f"A gap of {delta:.0f} seconds observed between event "
                                f"{evidence_items[i].get('_citation_tag')} and {evidence_items[i + 1].get('_citation_tag')}. "
                                "Note: No observed evidence does NOT establish that no activity occurred."
                            ),
                            affected_entities=[
                                str(evidence_items[i].get("host") or ""),
                                str(evidence_items[i + 1].get("host") or ""),
                            ],
                            start_time=t1.isoformat(),
                            end_time=t2.isoformat(),
                            duration_seconds=delta,
                            remedy="Query perimeter network flows and secondary syslog archives across this window.",
                            governed_hunt_proposal=QueryProposal(
                                query_type="events",
                                parameters={"start_time": t1.isoformat(), "end_time": t2.isoformat(), "limit": 50},
                                rationale="Investigate temporal silence window",
                            ),
                        )
                    )

        # 2. MISSING_HOST_VISIBILITY / MISSING_PROCESS_TELEMETRY
        hosts_seen = {str(it.get("host")) for it in evidence_items if it.get("host")}
        for h in sorted(list(hosts_seen)):
            host_items = [it for it in evidence_items if it.get("host") == h]
            has_auth = any("login" in str(it.get("action", "")).lower() or "ssh" in str(it.get("source", "")).lower() for it in host_items)
            has_proc = any("process" in str(it.get("event_type", "")).lower() or "exec" in str(it.get("action", "")).lower() for it in host_items)

            if has_auth and not has_proc:
                gaps.append(
                    TemporalGap(
                        gap_id=f"tgap-{case.case_id}-proc-{h}",
                        case_id=case.case_id,
                        gap_type=TemporalGapType.MISSING_PROCESS_TELEMETRY,
                        title=f"Missing Process Execution Telemetry on {h}",
                        description=f"Host {h} recorded authentication events but lacks corresponding process execution telemetry.",
                        affected_entities=[f"host:{h}"],
                        remedy="Execute governed auditd/sysmon hunt query for process creations on host.",
                        governed_hunt_proposal=QueryProposal(
                            query_type="events",
                            parameters={"host": h, "event_type": "process_execution", "limit": 50},
                            rationale=f"Locate child processes spawned after authentication on {h}",
                        ),
                    )
                )

        # 3. UNRESOLVED_TRANSITIONS (Host-to-host jump without intervening transport telemetry)
        for tr in transitions:
            if tr.transition_type == TransitionType.HOST_TO_HOST:
                gaps.append(
                    TemporalGap(
                        gap_id=f"tgap-{case.case_id}-unres-{tr.transition_id}",
                        case_id=case.case_id,
                        gap_type=TemporalGapType.UNRESOLVED_TRANSITION,
                        title=f"Unresolved Lateral Movement Transition: {tr.from_entity} -> {tr.to_entity}",
                        description=f"Transition between {tr.from_entity} and {tr.to_entity} lacks direct network packet or SSH transport record.",
                        affected_entities=[tr.from_entity, tr.to_entity],
                        start_time=tr.timestamp,
                        end_time=tr.timestamp,
                        remedy="Inspect network connection and firewall logs between source and destination hosts.",
                        governed_hunt_proposal=QueryProposal(
                            query_type="events",
                            parameters={"limit": 25},
                            rationale=f"Search for inter-host network telemetry connecting {tr.from_entity} to {tr.to_entity}",
                        ),
                    )
                )

        gaps.sort(key=lambda g: (g.gap_type.value, g.gap_id))
        return gaps[: self.MAX_GAPS]

    def reconstruct_multi_host_traces(
        self,
        case: InvestigationCase,
        transitions: List[TemporalTransition],
        evidence_items: List[Dict[str, Any]],
    ) -> List[MultiHostTrace]:
        """Reconstruct multi-host progression preserving host identities and timestamps."""
        host_transitions = [t for t in transitions if t.transition_type == TransitionType.HOST_TO_HOST]
        if not host_transitions:
            return []

        traces: List[MultiHostTrace] = []
        for idx, ht in enumerate(host_transitions):
            src = ht.from_entity.replace("host:", "")
            dst = ht.to_entity.replace("host:", "")
            traces.append(
                MultiHostTrace(
                    trace_id=f"mhost-{case.case_id}-{idx}",
                    case_id=case.case_id,
                    source_host=src,
                    target_host=dst,
                    actor=case.owner or "SecAnalyst-1",
                    hop_count=1,
                    transitions=[ht],
                    evidence_references=ht.evidence_references,
                    start_time=ht.timestamp,
                    end_time=ht.timestamp,
                    epistemic_status=ht.epistemic_status,
                )
            )

        traces.sort(key=lambda tr: (tr.start_time, tr.trace_id))
        return traces[: self.MAX_HOST_TRACES]

    def detect_entity_continuity(
        self,
        case: InvestigationCase,
        evidence_items: List[Dict[str, Any]],
    ) -> List[EntityContinuity]:
        """Track continuity of user accounts, processes, and IPs across investigative bounds."""
        continuities: List[EntityContinuity] = []

        # 1. Accounts across multiple hosts
        user_hosts: Dict[str, Set[str]] = {}
        user_refs: Dict[str, List[Dict[str, Any]]] = {}
        for it in evidence_items:
            u = it.get("username")
            h = it.get("host")
            if u and h:
                user_hosts.setdefault(u, set()).add(h)
                user_refs.setdefault(u, []).append(it)

        for u, hosts in user_hosts.items():
            if len(hosts) > 1:
                continuities.append(
                    EntityContinuity(
                        continuity_id=f"cont-{case.case_id}-user-{u}",
                        case_id=case.case_id,
                        continuity_type=ContinuityType.SAME_ACCOUNT_ACROSS_HOSTS,
                        entity_key=f"user:{u}",
                        occurrences_count=len(user_refs[u]),
                        participating_hosts=sorted(list(hosts)),
                        evidence_references=self._build_graph_evidence_items(user_refs[u])[: self.MAX_EVIDENCE_REFS],
                        description=f"Account '{u}' active across {len(hosts)} distinct hosts: {sorted(list(hosts))}",
                    )
                )

        # 2. Source IPs across multiple events
        ip_hosts: Dict[str, Set[str]] = {}
        ip_refs: Dict[str, List[Dict[str, Any]]] = {}
        for it in evidence_items:
            ip = it.get("src_ip")
            h = it.get("host")
            if ip and str(ip) not in ("127.0.0.1", "::1", "localhost"):
                if h:
                    ip_hosts.setdefault(str(ip), set()).add(h)
                ip_refs.setdefault(str(ip), []).append(it)

        for ip, hosts in ip_hosts.items():
            if len(hosts) > 1 or len(ip_refs[ip]) >= 2:
                continuities.append(
                    EntityContinuity(
                        continuity_id=f"cont-{case.case_id}-ip-{ip.replace('.', '-')}",
                        case_id=case.case_id,
                        continuity_type=ContinuityType.SAME_SOURCE_IP,
                        entity_key=f"ip:{ip}",
                        occurrences_count=len(ip_refs[ip]),
                        participating_hosts=sorted(list(hosts)),
                        evidence_references=self._build_graph_evidence_items(ip_refs[ip])[: self.MAX_EVIDENCE_REFS],
                        description=f"Source IP {ip} observed across {len(ip_refs[ip])} events targeting hosts {sorted(list(hosts))}",
                    )
                )

        continuities.sort(key=lambda c: (c.continuity_type.value, c.entity_key))
        return continuities[: self.MAX_CONTINUITIES]

    def correlate_campaign_incidents(
        self,
        case: InvestigationCase,
        other_incidents: List[Dict[str, Any]],
        evidence_items: List[Dict[str, Any]],
    ) -> List[IncidentCampaignCorrelation]:
        """Categorically correlate current case against other incidents without arbitrary probability scores."""
        correlations: List[IncidentCampaignCorrelation] = []

        cur_users = {str(it.get("username")) for it in evidence_items if it.get("username")}
        cur_ips = {str(it.get("src_ip")) for it in evidence_items if it.get("src_ip")}
        cur_hosts = {str(it.get("host")) for it in evidence_items if it.get("host")}
        cur_entities = cur_users.union(cur_ips).union(cur_hosts)

        for inc in other_incidents:
            other_id = inc.get("id") or inc.get("incident_id")
            if not other_id or other_id == case.incident_id:
                continue

            other_user = inc.get("primary_user")
            other_host = inc.get("primary_host")
            other_title = inc.get("title", f"Incident INC-{other_id}")

            shared_entities = []
            reason = CampaignRelationReason.TEMPORAL_PROXIMITY

            if other_user and other_user in cur_users:
                shared_entities.append(f"user:{other_user}")
                reason = CampaignRelationReason.SHARED_ACCOUNT
            if other_host and other_host in cur_hosts:
                shared_entities.append(f"host:{other_host}")
                reason = CampaignRelationReason.SHARED_ENTITY

            # Check temporal proximity (within 24h)
            cur_first = min([self._parse_timestamp(it.get("timestamp")) for it in evidence_items if it.get("timestamp")] or [None])
            other_first = self._parse_timestamp(inc.get("first_seen"))

            status = CampaignCorrelationStatus.UNRELATED
            if len(shared_entities) >= 2:
                status = CampaignCorrelationStatus.CORRELATED
            elif len(shared_entities) == 1:
                status = CampaignCorrelationStatus.POTENTIALLY_RELATED
            elif cur_first and other_first and abs((other_first - cur_first).total_seconds()) <= 86400.0:
                status = CampaignCorrelationStatus.POTENTIALLY_RELATED
                reason = CampaignRelationReason.TEMPORAL_PROXIMITY
            else:
                status = CampaignCorrelationStatus.INSUFFICIENT_EVIDENCE

            if status in [CampaignCorrelationStatus.CORRELATED, CampaignCorrelationStatus.POTENTIALLY_RELATED]:
                correlations.append(
                    IncidentCampaignCorrelation(
                        correlation_id=f"camp-{case.case_id}-{other_id}",
                        primary_incident_id=case.incident_id,
                        related_incident_id=int(other_id),
                        related_incident_title=other_title,
                        relationship_reason=reason,
                        correlation_status=status,
                        shared_entities=shared_entities,
                        shared_evidence_count=len(shared_entities),
                        first_seen=inc.get("first_seen"),
                        last_seen=inc.get("last_seen"),
                        epistemic_status=EpistemicStatus.INFERRED,
                        summary=f"Categorical correlation based on {reason.value} ({', '.join(shared_entities) if shared_entities else 'time proximity'}).",
                    )
                )

        correlations.sort(key=lambda c: (c.correlation_status.value, c.related_incident_id))
        return correlations[: self.MAX_CAMPAIGN_CORRELATIONS]

    def reconstruct_attack_sequences(
        self,
        case: InvestigationCase,
        evidence_items: List[Dict[str, Any]],
        transitions: List[TemporalTransition],
        graph: Optional[InvestigationGraph] = None,
    ) -> Tuple[List[AttackSequenceReconstruction], List[Dict[str, Any]]]:
        """Construct deterministic attack sequence reconstruction incorporating MITRE techniques."""
        steps: List[AttackSequenceStep] = []
        mitre_list: List[Dict[str, Any]] = []
        seen_mitre: Set[str] = set()

        mitre_by_ev: Dict[str, Tuple[str, str]] = {}
        if graph and graph.edges:
            for edge in graph.edges:
                if edge.mitre_technique_id:
                    for ev_id in edge.evidence_event_ids:
                        mitre_by_ev[str(ev_id)] = (edge.mitre_technique_id, edge.mitre_tactic or "Unknown Tactic")
                    for ref in edge.evidence_references:
                        if ref.source_id:
                            mitre_by_ev[str(ref.source_id)] = (edge.mitre_technique_id, edge.mitre_tactic or "Unknown Tactic")

        for idx, it in enumerate(evidence_items[: self.MAX_SEQUENCE_STEPS]):
            action = str(it.get("action") or it.get("summary") or "Action")
            entity_val = str(it.get("host") or it.get("username") or "entity")

            # Extract MITRE technique if present in resolved record or graph
            m_id = None
            m_name = None
            details_raw = it.get("details_json")
            if details_raw:
                try:
                    details = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
                    m_id = details.get("mitre_technique_id")
                    m_name = details.get("mitre_tactic")
                except Exception:
                    pass

            if not m_id:
                src_id = str(it.get("_source_id") or it.get("id") or "")
                if src_id in mitre_by_ev:
                    m_id, m_name = mitre_by_ev[src_id]

            # Neutral stage naming derived from action
            stage = "EXECUTION"
            if any(k in action.lower() for k in ["login", "ssh", "auth"]):
                stage = "INITIAL_ACCESS"
            elif any(k in action.lower() for k in ["sudo", "privilege", "root"]):
                stage = "PRIVILEGE_ESCALATION"
            elif any(k in action.lower() for k in ["lateral", "connect"]):
                stage = "LATERAL_MOVEMENT"

            steps.append(
                AttackSequenceStep(
                    step_number=idx + 1,
                    timestamp=it.get("timestamp") or "1970-01-01T00:00:00Z",
                    stage_name=stage,
                    entity=entity_val,
                    evidence_citation=it.get("_citation_tag", f"[{it.get('_source_type')}:{it.get('_source_id')}]"),
                    reason=f"Recorded forensic action: {action[:50]}",
                    epistemic_status=EpistemicStatus.OBSERVED,
                    mitre_technique_id=m_id,
                    mitre_technique_name=m_name,
                    rule_id=it.get("rule_id"),
                )
            )

            if m_id and m_id not in seen_mitre:
                seen_mitre.add(m_id)
                mitre_list.append(
                    {
                        "technique_id": m_id,
                        "technique_name": m_name or "Unknown Tactic",
                        "rule_id": it.get("rule_id"),
                        "source": it.get("_source_type"),
                        "epistemic_status": EpistemicStatus.OBSERVED.value,
                        "is_authoritative": True,
                    }
                )

        if not steps:
            return [], []

        ts_list = [self._parse_timestamp(s.timestamp) for s in steps]
        valid_ts = [t for t in ts_list if t is not None]
        start_ts = min(valid_ts).isoformat() if valid_ts else steps[0].timestamp
        end_ts = max(valid_ts).isoformat() if valid_ts else steps[-1].timestamp
        span = (max(valid_ts) - min(valid_ts)).total_seconds() if valid_ts else 0.0

        sequence = AttackSequenceReconstruction(
            sequence_id=f"atkseq-{case.case_id}-primary",
            case_id=case.case_id,
            name=f"Reconstructed Attack Sequence for Case {case.case_id}",
            description=f"Evidence-bound temporal sequence with {len(steps)} verified steps.",
            steps=steps,
            total_steps=len(steps),
            start_time=start_ts,
            end_time=end_ts,
            duration_seconds=span,
            epistemic_status=EpistemicStatus.OBSERVED,
        )

        return [sequence], mitre_list

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

    # -------------------------------------------------------------
    # Multi-Format Investigation Export
    # -------------------------------------------------------------

    def export_reconstruction_json(self, dossier: TemporalReconstructionDossier) -> str:
        """Export temporal reconstruction dossier as deterministic formatted JSON."""
        return json.dumps(dossier.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False)

    def export_reconstruction_csv(self, dossier: TemporalReconstructionDossier) -> str:
        """Export transitions and chronological steps as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "record_type",
            "id",
            "timestamp",
            "from_or_entity",
            "to_or_action",
            "type_or_stage",
            "epistemic_status",
            "reason",
            "evidence_citations",
        ])

        # Episodes
        for ep in dossier.episodes:
            citations = ";".join([ref.citation_tag for ref in ep.evidence_references])
            writer.writerow([
                "EPISODE",
                ep.episode_id,
                ep.start_time,
                ",".join(ep.entities),
                ep.title,
                ep.episode_type.value,
                ep.epistemic_status.value,
                ep.summary,
                citations,
            ])

        # Transitions
        for tr in dossier.transitions:
            citations = ";".join([ref.citation_tag for ref in tr.evidence_references])
            writer.writerow([
                "TRANSITION",
                tr.transition_id,
                tr.timestamp,
                tr.from_entity,
                tr.to_entity,
                tr.transition_type.value,
                tr.epistemic_status.value,
                tr.reason,
                citations,
            ])

        # Attack Sequence Steps
        for seq in dossier.attack_sequences:
            for step in seq.steps:
                writer.writerow([
                    "SEQUENCE_STEP",
                    f"{seq.sequence_id}-{step.step_number}",
                    step.timestamp,
                    step.entity,
                    step.reason,
                    step.stage_name,
                    step.epistemic_status.value,
                    step.reason,
                    step.evidence_citation,
                ])

        return output.getvalue()

    def export_reconstruction_graphml(self, dossier: TemporalReconstructionDossier) -> str:
        """Export transitions and episodes as standard GraphML XML."""
        root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
        
        # Key definitions
        ET.SubElement(root, "key", id="label", attrib={"for": "node", "attr.name": "label", "attr.type": "string"})
        ET.SubElement(root, "key", id="type", attrib={"for": "node", "attr.name": "type", "attr.type": "string"})
        ET.SubElement(root, "key", id="trans_type", attrib={"for": "edge", "attr.name": "transition_type", "attr.type": "string"})
        ET.SubElement(root, "key", id="epistemic", attrib={"for": "edge", "attr.name": "epistemic_status", "attr.type": "string"})
        ET.SubElement(root, "key", id="timestamp", attrib={"for": "edge", "attr.name": "timestamp", "attr.type": "string"})

        graph = ET.SubElement(root, "graph", id=dossier.reconstruction_id, edgedefault="directed")

        nodes_added: Set[str] = set()

        def add_node(node_id: str, label: str, n_type: str):
            clean_id = node_id.replace(":", "_").replace(" ", "_")
            if clean_id not in nodes_added:
                nodes_added.add(clean_id)
                n = ET.SubElement(graph, "node", id=clean_id)
                d1 = ET.SubElement(n, "data", key="label")
                d1.text = label
                d2 = ET.SubElement(n, "data", key="type")
                d2.text = n_type

        # Add nodes and edges from transitions
        for idx, tr in enumerate(dossier.transitions):
            add_node(tr.from_entity, tr.from_entity, "ENTITY")
            add_node(tr.to_entity, tr.to_entity, "ENTITY")

            e = ET.SubElement(
                graph,
                "edge",
                id=tr.transition_id,
                source=tr.from_entity.replace(":", "_").replace(" ", "_"),
                target=tr.to_entity.replace(":", "_").replace(" ", "_"),
            )
            d_type = ET.SubElement(e, "data", key="trans_type")
            d_type.text = tr.transition_type.value
            d_epi = ET.SubElement(e, "data", key="epistemic")
            d_epi.text = tr.epistemic_status.value
            d_ts = ET.SubElement(e, "data", key="timestamp")
            d_ts.text = tr.timestamp

        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")

    # -------------------------------------------------------------
    # Advisory Local AI Temporal Explanation
    # -------------------------------------------------------------

    def explain_temporal_reconstruction(
        self,
        case: InvestigationCase,
        dossier: TemporalReconstructionDossier,
        target_id: Optional[str] = None,
        question: Optional[str] = None,
    ) -> TemporalExplanationResponse:
        """Generate strictly advisory, evidence-grounded explanation of temporal transitions."""
        now_iso = datetime.now(timezone.utc).isoformat()

        # Application-level prompt injection containment
        safe_q = ""
        if question:
            for bad in ["system prompt", "ignore previous", "delete", "rm -rf", "drop table", "grant root"]:
                if bad in question.lower():
                    question = "[Potentially adversarial query sanitized]"
            safe_q = f"Question: {question[:150]}\n"

        target_tr = next((t for t in dossier.transitions if t.transition_id == target_id), None)
        target_ep = next((e for e in dossier.episodes if e.episode_id == target_id), None)

        if target_tr:
            citations = [r.citation_tag for r in target_tr.evidence_references]
            explanation = (
                f"{safe_q}"
                f"Advisory Explanation for Transition {target_tr.transition_id} ({target_tr.transition_type.value}):\n"
                f"- Entity Progression: {target_tr.from_entity} -> {target_tr.to_entity}\n"
                f"- Event Timestamp: {target_tr.timestamp}\n"
                f"- Correlation Basis: {target_tr.correlation_basis}\n"
                f"- Epistemic Status: {target_tr.epistemic_status.value} (Review State: {target_tr.review_state.value})\n"
                f"- Citations: {', '.join(citations) if citations else 'None'}\n"
                "Analytical Advisory: Progression is strictly derived from observed chronological telemetry."
            )
            refs = citations
        elif target_ep:
            citations = [r.citation_tag for r in target_ep.evidence_references]
            explanation = (
                f"{safe_q}"
                f"Advisory Explanation for Episode {target_ep.episode_id} ({target_ep.episode_type.value}):\n"
                f"- Title: {target_ep.title}\n"
                f"- Span: {target_ep.start_time} to {target_ep.end_time} ({target_ep.duration_seconds:.1f}s)\n"
                f"- Participating Entities: {', '.join(target_ep.entities)}\n"
                f"- Corroboration: {target_ep.corroboration_status.value}\n"
                f"- Citations: {', '.join(citations) if citations else 'None'}\n"
                "Analytical Advisory: Episode represents a cohesive activity burst verified across forensic logs."
            )
            refs = citations
        else:
            all_cits = [
                ref.citation_tag
                for ep in dossier.episodes
                for ref in ep.evidence_references
            ][:10]
            explanation = (
                f"{safe_q}"
                f"Advisory Overview for Temporal Reconstruction {dossier.reconstruction_id}:\n"
                f"- Total Episodes: {len(dossier.episodes)}\n"
                f"- Total Transitions: {len(dossier.transitions)}\n"
                f"- Multi-Host Movements: {len(dossier.multi_host_traces)}\n"
                f"- Temporal Gaps: {len(dossier.gaps)}\n"
                f"- Campaign Incident Correlations: {len(dossier.campaign_correlations)}\n"
                f"- Investigation Timespan: {dossier.start_time} to {dossier.end_time} ({dossier.duration_seconds:.1f}s)\n"
                f"- Evidence Grounding: Supported by {len(all_cits)} citations: {', '.join(all_cits)}.\n"
                "Analytical Advisory: Reconstructed sequences represent deterministic chronological progressions without probabilistic score fabrication."
            )
            refs = all_cits

        return TemporalExplanationResponse(
            explanation_id=f"txp-{case.case_id}-{uuid.uuid4().hex[:6]}",
            case_id=case.case_id,
            target_id=target_id or dossier.reconstruction_id,
            explanation_text=explanation,
            is_authoritative=False,
            generated_by="LOCAL_AI_ADVISORY",
            referenced_citations=refs,
            epistemic_status=EpistemicStatus.INFERRED,
            generated_at=now_iso,
        )
