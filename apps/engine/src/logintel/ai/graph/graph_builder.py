"""Deterministic Investigation Graph Builder for Milestone 5.8.

Synthesizes evidence-bound investigation graphs, path reconstructions,
temporal relationship chains, and entity pivots from authoritative forensic records
and persistent investigation case artifacts.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional, Set, Tuple
import xml.etree.ElementTree as ET

from logintel.ai.domain.case import InvestigationCase
from logintel.ai.domain.investigation_graph import (
    CorroborationStatus,
    EntityPivotGraph,
    GraphEvidenceItem,
    GraphNodeType,
    InvestigationGraph,
    InvestigationGraphEdge,
    InvestigationGraphNode,
    InvestigationPath,
    PathNature,
    RelationshipEpistemicStatus,
    TemporalChain,
    TemporalChainStep,
    TemporalRelation,
)
from logintel.ai.domain.investigation_intel import EpistemicStatus
from logintel.logging import get_logger
from logintel.models.incidents import ConfidenceLevel, Incident, IncidentEntity, IncidentRelationship
from logintel.models.investigation import MitreMapping
from logintel.storage.db import Database

logger = get_logger("ai.graph_builder")

# Strict server-side bounds
DEFAULT_MAX_NODES = 50
MAX_NODES_CLAMP = 200
DEFAULT_MAX_EDGES = 100
MAX_EDGES_CLAMP = 500
DEFAULT_MAX_DEPTH = 2
MAX_DEPTH_CLAMP = 5


class InvestigationGraphBuilder:
    """Builder providing deterministic investigation graphs, bounded traversals, and evidence bindings."""

    def __init__(self, forensic_db: Optional[Database] = None) -> None:
        self.db = forensic_db

    def _compute_sha256(self, payload: Any) -> str:
        """Deterministically compute 64-character SHA-256 hex digest."""
        if isinstance(payload, str):
            data = payload.encode("utf-8")
        else:
            data = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return f"sha256:{hashlib.sha256(data).hexdigest()}"

    def _parse_timestamp(self, ts_str: Optional[str]) -> Optional[datetime]:
        """Safely parse ISO timestamp string into UTC datetime object."""
        if not ts_str:
            return None
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return None

    def build_graph(
        self,
        case: InvestigationCase,
        incident: Optional[Incident],
        entities: List[IncidentEntity],
        relationships: List[IncidentRelationship],
        mitre_mappings: Optional[List[MitreMapping]] = None,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_edges: int = DEFAULT_MAX_EDGES,
        entity_type: Optional[str] = None,
        relationship_type: Optional[str] = None,
        epistemic_status: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> InvestigationGraph:
        """Construct a bounded, evidence-bound investigation graph for a case."""
        # Enforce server-side governance bounds
        clamped_max_nodes = max(1, min(max_nodes, MAX_NODES_CLAMP))
        clamped_max_edges = max(1, min(max_edges, MAX_EDGES_CLAMP))

        start_dt = self._parse_timestamp(start_time)
        end_dt = self._parse_timestamp(end_time)

        # 1. Build Base Nodes from Incident Entities
        nodes_dict: Dict[str, InvestigationGraphNode] = {}
        for ent in entities:
            # Type filter
            if entity_type and ent.entity_type.value.upper() != entity_type.upper():
                continue

            node_id = f"ent:{ent.entity_key}"
            # Extract node type mapping
            try:
                g_type = GraphNodeType(ent.entity_type.value.upper())
            except Exception:
                g_type = GraphNodeType.HOST

            metadata = ent.metadata or {}
            nodes_dict[node_id] = InvestigationGraphNode(
                node_id=node_id,
                node_type=g_type,
                display_label=ent.display_name or ent.entity_key,
                entity_key=ent.entity_key,
                is_authoritative=True,
                epistemic_status=EpistemicStatus.OBSERVED,
                source_reference=f"incident_entities:{ent.id}",
                metadata=metadata,
                first_seen=incident.first_seen.isoformat() if incident else None,
                last_seen=incident.last_seen.isoformat() if incident else None,
                degree=0,
            )

        # 2. Extract Evidence References lookup from Case
        evidence_by_source_id: Dict[str, Any] = {}
        contradicting_event_ids: Set[str] = set()
        for ref in case.evidence_references:
            evidence_by_source_id[ref.source_id] = ref
            if getattr(ref, "role", "").lower() == "contradicting":
                contradicting_event_ids.add(ref.source_id)

        # Also inspect hypotheses for contradictory evidence tags
        for hyp in case.hypotheses:
            for tag in hyp.contradicting_evidence_tags:
                if ":" in tag:
                    contradicting_event_ids.add(tag.split(":", 1)[1].strip("[]"))
                else:
                    contradicting_event_ids.add(tag.strip("[]"))

        # Build MITRE mapping lookup
        mitre_lookup: Dict[str, MitreMapping] = {}
        if mitre_mappings:
            for m in mitre_mappings:
                for ev_id in m.supporting_event_ids:
                    mitre_lookup[ev_id] = m

        # 3. Build Edges from Incident Relationships
        edges_list: List[InvestigationGraphEdge] = []
        for rel in relationships:
            src_node_id = f"ent:{rel.source_entity_key}"
            tgt_node_id = f"ent:{rel.target_entity_key}"

            src_type_guess = rel.source_entity_key.split(":")[0].upper() if ":" in rel.source_entity_key else "HOST"
            tgt_type_guess = rel.target_entity_key.split(":")[0].upper() if ":" in rel.target_entity_key else "HOST"

            if entity_type:
                if src_type_guess != entity_type.upper() and tgt_type_guess != entity_type.upper():
                    continue

            # Ensure both endpoint nodes exist or lazily create them
            if src_node_id not in nodes_dict:
                if not entity_type or src_type_guess == entity_type.upper():
                    try:
                        g_type = GraphNodeType(src_type_guess)
                    except Exception:
                        g_type = GraphNodeType.HOST
                    nodes_dict[src_node_id] = InvestigationGraphNode(
                        node_id=src_node_id,
                        node_type=g_type,
                        display_label=rel.source_entity_key,
                        entity_key=rel.source_entity_key,
                        is_authoritative=True,
                        epistemic_status=EpistemicStatus.OBSERVED,
                        source_reference=f"incident_relationships:lazy",
                        metadata={},
                        degree=0,
                    )

            if tgt_node_id not in nodes_dict:
                if not entity_type or tgt_type_guess == entity_type.upper():
                    try:
                        g_type = GraphNodeType(tgt_type_guess)
                    except Exception:
                        g_type = GraphNodeType.HOST
                    nodes_dict[tgt_node_id] = InvestigationGraphNode(
                        node_id=tgt_node_id,
                        node_type=g_type,
                        display_label=rel.target_entity_key,
                        entity_key=rel.target_entity_key,
                        is_authoritative=True,
                        epistemic_status=EpistemicStatus.OBSERVED,
                        source_reference=f"incident_relationships:lazy",
                        metadata={},
                        degree=0,
                    )

            # Filtering
            if relationship_type and rel.relationship_type.upper() != relationship_type.upper():
                continue

            edge_time = rel.matched_at.isoformat() if rel.matched_at else None
            edge_dt = rel.matched_at
            if start_dt and edge_dt and edge_dt < start_dt:
                continue
            if end_dt and edge_dt and edge_dt > end_dt:
                continue

            edge_id = f"edge:{rel.source_entity_key}->{rel.target_entity_key}:{rel.relationship_type}"

            # Assemble concrete evidence items
            evidence_items: List[GraphEvidenceItem] = []
            has_contradiction = False
            for ev_id in rel.evidence_event_ids:
                if ev_id in contradicting_event_ids:
                    has_contradiction = True

                ev_ref = evidence_by_source_id.get(ev_id)
                ev_hash = self._compute_sha256(ev_id)
                citation = ev_ref.citation_tag if ev_ref and ev_ref.citation_tag else f"[event:{ev_id}]"

                evidence_items.append(
                    GraphEvidenceItem(
                        reference_id=f"ev-{ev_id}",
                        source_type="event",
                        source_id=ev_id,
                        source_hash=ev_hash,
                        citation_tag=citation,
                        timestamp=edge_time,
                        summary=f"Forensic telemetry event supporting {rel.relationship_type}",
                        epistemic_status=EpistemicStatus.OBSERVED,
                        is_authoritative=True,
                        role="contradicting" if ev_id in contradicting_event_ids else "primary",
                    )
                )

            # Corroboration status determination
            if has_contradiction:
                corroboration = CorroborationStatus.CONTRADICTED
            elif len(evidence_items) > 1:
                corroboration = CorroborationStatus.CORROBORATED
            elif len(evidence_items) == 1:
                corroboration = CorroborationStatus.DIRECT_EVIDENCE
            else:
                corroboration = CorroborationStatus.INSUFFICIENT_EVIDENCE

            # Epistemic status & authority
            # Relationships from incident_relationships are authoritative persisted records
            is_auth = True
            r_epistemic = RelationshipEpistemicStatus.OBSERVED

            if epistemic_status and r_epistemic.value.upper() != epistemic_status.upper():
                continue

            # MITRE association
            mitre_id = None
            mitre_tactic = None
            for ev_id in rel.evidence_event_ids:
                if ev_id in mitre_lookup:
                    mitre_id = mitre_lookup[ev_id].technique_id
                    mitre_tactic = mitre_lookup[ev_id].tactic
                    break

            edges_list.append(
                InvestigationGraphEdge(
                    edge_id=edge_id,
                    source_node_id=src_node_id,
                    target_node_id=tgt_node_id,
                    relationship_type=rel.relationship_type,
                    epistemic_status=r_epistemic,
                    is_authoritative=is_auth,
                    confidence=rel.confidence,
                    corroboration_status=corroboration,
                    evidence_references=evidence_items,
                    evidence_event_ids=rel.evidence_event_ids,
                    first_seen=edge_time,
                    last_seen=edge_time,
                    duration_seconds=0.0,
                    temporal_relation=TemporalRelation.CO_OCCURRED,
                    mitre_technique_id=mitre_id,
                    mitre_tactic=mitre_tactic,
                    description=f"{rel.source_entity_key} {rel.relationship_type} {rel.target_entity_key}",
                    provenance=f"incident_relationships:id={rel.id}",
                )
            )

        # 4. Integrate Candidate Edges from Governed Threat Hunting
        for query in case.query_history:
            if getattr(query, "execution_status", "") == "SUCCESS":
                q_id = getattr(query, "query_id", "q")
                params = getattr(query, "parameters", {}) or {}
                # If query parameters link a host and IP/user, add candidate edge
                host_param = params.get("host")
                user_param = params.get("username") or params.get("user")
                ip_param = params.get("src_ip") or params.get("ip")

                if host_param and (user_param or ip_param):
                    src_key = f"user:{user_param}" if user_param else f"ip:{ip_param}"
                    tgt_key = f"host:{host_param}"
                    src_node_id = f"ent:{src_key}"
                    tgt_node_id = f"ent:{tgt_key}"

                    if src_node_id not in nodes_dict:
                        nodes_dict[src_node_id] = InvestigationGraphNode(
                            node_id=src_node_id,
                            node_type=GraphNodeType.USER if user_param else GraphNodeType.IP,
                            display_label=src_key,
                            entity_key=src_key,
                            is_authoritative=False,
                            epistemic_status=EpistemicStatus.INFERRED,
                            source_reference=f"case_query_history:{q_id}",
                            metadata=params,
                        )
                    if tgt_node_id not in nodes_dict:
                        nodes_dict[tgt_node_id] = InvestigationGraphNode(
                            node_id=tgt_node_id,
                            node_type=GraphNodeType.HOST,
                            display_label=tgt_key,
                            entity_key=tgt_key,
                            is_authoritative=False,
                            epistemic_status=EpistemicStatus.INFERRED,
                            source_reference=f"case_query_history:{q_id}",
                            metadata=params,
                        )

                    c_edge_id = f"edge:{src_key}->{tgt_key}:HUNT_CANDIDATE"
                    edges_list.append(
                        InvestigationGraphEdge(
                            edge_id=c_edge_id,
                            source_node_id=src_node_id,
                            target_node_id=tgt_node_id,
                            relationship_type="HUNT_CANDIDATE",
                            epistemic_status=RelationshipEpistemicStatus.INFERRED,
                            is_authoritative=False,
                            confidence=ConfidenceLevel.INFERRED,
                            corroboration_status=CorroborationStatus.SINGLE_SOURCE,
                            evidence_references=[
                                GraphEvidenceItem(
                                    reference_id=f"hunt-{q_id}",
                                    source_type="hunt_query",
                                    source_id=q_id,
                                    source_hash=self._compute_sha256(params),
                                    citation_tag=f"[hunt:{q_id}]",
                                    timestamp=getattr(query, "executed_at", None),
                                    summary=f"Governed threat hunt candidate correlation",
                                    epistemic_status=EpistemicStatus.INFERRED,
                                    is_authoritative=False,
                                    role="supporting",
                                )
                            ],
                            evidence_event_ids=[],
                            first_seen=getattr(query, "executed_at", None),
                            last_seen=getattr(query, "executed_at", None),
                            temporal_relation=TemporalRelation.DURING,
                            description=f"Governed threat hunt candidate linkage between {src_key} and {tgt_key}",
                            provenance=f"case_query_history:query_id={q_id}",
                        )
                    )

        # 5. Apply Hard Clamps on Edges & Calculate Degrees
        edges_clamped = edges_list[:clamped_max_edges]

        # Calculate degrees
        for edge in edges_clamped:
            if edge.source_node_id in nodes_dict:
                nodes_dict[edge.source_node_id].degree += 1
            if edge.target_node_id in nodes_dict:
                nodes_dict[edge.target_node_id].degree += 1

        # Sort nodes by degree descending and clamp
        sorted_nodes = sorted(nodes_dict.values(), key=lambda n: n.degree, reverse=True)
        nodes_clamped = sorted_nodes[:clamped_max_nodes]
        retained_node_ids = {n.node_id for n in nodes_clamped}

        # Filter edges to only include retained nodes
        final_edges = [
            e for e in edges_clamped if e.source_node_id in retained_node_ids and e.target_node_id in retained_node_ids
        ]

        # Compute summary counts
        obs_count = sum(1 for e in final_edges if e.epistemic_status == RelationshipEpistemicStatus.OBSERVED)
        inf_count = sum(1 for e in final_edges if e.epistemic_status == RelationshipEpistemicStatus.INFERRED)
        cor_count = sum(1 for e in final_edges if e.corroboration_status == CorroborationStatus.CORROBORATED)
        con_count = sum(1 for e in final_edges if e.corroboration_status == CorroborationStatus.CONTRADICTED)

        now_iso = datetime.now(timezone.utc).isoformat()
        return InvestigationGraph(
            case_id=case.case_id,
            incident_id=case.incident_id,
            nodes=nodes_clamped,
            edges=final_edges,
            total_nodes=len(nodes_clamped),
            total_edges=len(final_edges),
            observed_edges_count=obs_count,
            inferred_edges_count=inf_count,
            corroborated_edges_count=cor_count,
            contradicted_edges_count=con_count,
            generated_at=now_iso,
        )

    def reconstruct_investigation_path(
        self,
        graph: InvestigationGraph,
        source_node_id: str,
        target_node_id: str,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> Optional[InvestigationPath]:
        """Reconstruct bounded investigation path between source and target nodes with cycle protection."""
        clamped_depth = max(1, min(max_depth, MAX_DEPTH_CLAMP))

        node_map = {n.node_id: n for n in graph.nodes}

        def resolve_node_id(identifier: str) -> Optional[str]:
            if identifier in node_map:
                return identifier
            for n in graph.nodes:
                if n.entity_key == identifier or n.display_label == identifier:
                    return n.node_id
            if f"ent:{identifier}" in node_map:
                return f"ent:{identifier}"
            return None

        resolved_source = resolve_node_id(source_node_id)
        resolved_target = resolve_node_id(target_node_id)
        if not resolved_source or not resolved_target:
            return None

        source_node_id = resolved_source
        target_node_id = resolved_target

        # Build adjacency graph
        adj: Dict[str, List[InvestigationGraphEdge]] = {n.node_id: [] for n in graph.nodes}
        for e in graph.edges:
            adj[e.source_node_id].append(e)

        # BFS queue storing (current_node, [edges_in_path], visited_nodes_set)
        queue: List[Tuple[str, List[InvestigationGraphEdge], Set[str]]] = [
            (source_node_id, [], {source_node_id})
        ]

        shortest_path: Optional[List[InvestigationGraphEdge]] = None

        while queue:
            curr_node, current_path, visited = queue.pop(0)

            if curr_node == target_node_id and current_path:
                shortest_path = current_path
                break

            if len(current_path) >= clamped_depth:
                continue

            for edge in adj.get(curr_node, []):
                next_node = edge.target_node_id
                if next_node not in visited:
                    new_visited = set(visited)
                    new_visited.add(next_node)
                    queue.append((next_node, current_path + [edge], new_visited))

        if not shortest_path:
            return None

        # Assemble path nodes
        path_nodes: List[InvestigationGraphNode] = [node_map[source_node_id]]
        for edge in shortest_path:
            path_nodes.append(node_map[edge.target_node_id])

        # Determine path nature
        has_obs = any(e.epistemic_status == RelationshipEpistemicStatus.OBSERVED for e in shortest_path)
        has_inf = any(e.epistemic_status == RelationshipEpistemicStatus.INFERRED for e in shortest_path)
        if has_obs and not has_inf:
            nature = PathNature.OBSERVED
        elif has_inf and not has_obs:
            nature = PathNature.INFERRED
        else:
            nature = PathNature.MIXED

        evidence_count = sum(len(e.evidence_references) for e in shortest_path)
        summary = (
            f"Investigation path connecting {node_map[source_node_id].display_label} to "
            f"{node_map[target_node_id].display_label} across {len(shortest_path)} transitions "
            f"({nature.value}) backed by {evidence_count} evidence citations."
        )

        return InvestigationPath(
            case_id=graph.case_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            nodes=path_nodes,
            edges=shortest_path,
            total_steps=len(shortest_path),
            path_nature=nature,
            evidence_references_count=evidence_count,
            total_duration_seconds=0.0,
            summary=summary,
        )

    def build_temporal_chain(self, graph: InvestigationGraph) -> TemporalChain:
        """Derive a chronological sequence of relationship transitions with delta time calculation."""
        # Filter edges with timestamps and sort chronologically
        timed_edges = [e for e in graph.edges if e.first_seen is not None]
        timed_edges.sort(key=lambda e: e.first_seen or "")

        steps: List[TemporalChainStep] = []
        prev_dt: Optional[datetime] = None

        for idx, edge in enumerate(timed_edges):
            curr_dt = self._parse_timestamp(edge.first_seen)
            delta = None
            if prev_dt and curr_dt:
                delta = max(0.0, (curr_dt - prev_dt).total_seconds())

            citation = edge.evidence_references[0].citation_tag if edge.evidence_references else "[unverified]"

            steps.append(
                TemporalChainStep(
                    step_index=idx + 1,
                    timestamp=edge.first_seen or datetime.now(timezone.utc).isoformat(),
                    edge_id=edge.edge_id,
                    source_node_id=edge.source_node_id,
                    target_node_id=edge.target_node_id,
                    relationship_type=edge.relationship_type,
                    delta_seconds_from_previous=delta,
                    evidence_citation=citation,
                    epistemic_status=edge.epistemic_status,
                )
            )
            if curr_dt:
                prev_dt = curr_dt

        start_time = steps[0].timestamp if steps else None
        end_time = steps[-1].timestamp if steps else None
        total_span = None
        if start_time and end_time:
            s_dt = self._parse_timestamp(start_time)
            e_dt = self._parse_timestamp(end_time)
            if s_dt and e_dt:
                total_span = max(0.0, (e_dt - s_dt).total_seconds())

        return TemporalChain(
            case_id=graph.case_id,
            steps=steps,
            total_steps=len(steps),
            start_time=start_time,
            end_time=end_time,
            total_span_seconds=total_span,
        )

    def build_entity_pivot_graph(
        self,
        graph: InvestigationGraph,
        entity_key: str,
        entity_type: str,
    ) -> EntityPivotGraph:
        """Construct an entity-centered sub-graph showing immediately adjacent nodes and evidence metrics."""
        target_node_id = f"ent:{entity_key}"

        connected_edges = [
            e for e in graph.edges if e.source_node_id == target_node_id or e.target_node_id == target_node_id
        ]

        adjacent_node_ids = {target_node_id}
        for e in connected_edges:
            adjacent_node_ids.add(e.source_node_id)
            adjacent_node_ids.add(e.target_node_id)

        node_map = {n.node_id: n for n in graph.nodes}
        connected_nodes = [node_map[nid] for nid in adjacent_node_ids if nid in node_map]

        # Calculate metrics from connected edges
        event_ids: Set[str] = set()
        for e in connected_edges:
            for ev_id in e.evidence_event_ids:
                event_ids.add(ev_id)

        return EntityPivotGraph(
            entity_key=entity_key,
            entity_type=entity_type,
            case_id=graph.case_id,
            connected_nodes=connected_nodes,
            connected_edges=connected_edges,
            related_alerts_count=1 if any("ALERT" in e.relationship_type for e in connected_edges) else 0,
            related_events_count=len(event_ids),
            related_findings_count=len(connected_edges),
            timeline_occurrences_count=len(connected_edges),
        )

    def export_graph_json(self, graph: InvestigationGraph) -> str:
        """Export investigation graph with complete provenance and evidence references to JSON string."""
        return json.dumps(graph.model_dump(), indent=2, ensure_ascii=False)

    def export_graphml(self, graph: InvestigationGraph) -> str:
        """Export investigation graph to standard GraphML XML string."""
        root = ET.Element(
            "graphml",
            {
                "xmlns": "http://graphml.graphdrawing.org/xmlns",
                "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
                "xsi:schemaLocation": "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd",
            },
        )

        # Keys
        ET.SubElement(root, "key", {"id": "d0", "for": "node", "attr.name": "label", "attr.type": "string"})
        ET.SubElement(root, "key", {"id": "d1", "for": "node", "attr.name": "type", "attr.type": "string"})
        ET.SubElement(root, "key", {"id": "d2", "for": "edge", "attr.name": "relationship", "attr.type": "string"})
        ET.SubElement(root, "key", {"id": "d3", "for": "edge", "attr.name": "epistemic_status", "attr.type": "string"})
        ET.SubElement(root, "key", {"id": "d4", "for": "edge", "attr.name": "evidence_count", "attr.type": "int"})

        g_elem = ET.SubElement(root, "graph", {"id": f"case_{graph.case_id}", "edgedefault": "directed"})

        for node in graph.nodes:
            n_elem = ET.SubElement(g_elem, "node", {"id": node.node_id})
            d0 = ET.SubElement(n_elem, "data", {"key": "d0"})
            d0.text = node.display_label
            d1 = ET.SubElement(n_elem, "data", {"key": "d1"})
            d1.text = node.node_type.value

        for edge in graph.edges:
            e_elem = ET.SubElement(g_elem, "edge", {"id": edge.edge_id, "source": edge.source_node_id, "target": edge.target_node_id})
            d2 = ET.SubElement(e_elem, "data", {"key": "d2"})
            d2.text = edge.relationship_type
            d3 = ET.SubElement(e_elem, "data", {"key": "d3"})
            d3.text = edge.epistemic_status.value
            d4 = ET.SubElement(e_elem, "data", {"key": "d4"})
            d4.text = str(len(edge.evidence_references))

        return ET.tostring(root, encoding="utf-8", xml_declaration=True).decode("utf-8")
