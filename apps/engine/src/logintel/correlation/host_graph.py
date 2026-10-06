"""Host Telemetry Correlator and Attack Graph Integration Engine (Milestone M6.8).

Correlates multi-layer Linux host telemetry into unified causal graphs:
- Process ancestry and command execution (M6.2)
- Advanced user identity and session continuity (M6.3)
- Network sockets and outbound connections (M6.4)
- Filesystem integrity and persistence targets (M6.5)
- Systemd service lifecycle and kernel security (M6.6)
- Container runtimes and namespace isolation (M6.7)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from logintel.correlation.ancestry import build_process_identity
from logintel.correlation.host_graph_models import (
    HostEdgeType,
    HostGraphEdge,
    HostGraphNode,
    HostNodeType,
    UnifiedHostGraph,
)
from logintel.logging import get_logger
from logintel.models.incidents import ConfidenceLevel

logger = get_logger("correlation.host_graph")


class HostGraphBuilder:
    """Constructs deterministic, causal multi-layer host graphs from telemetry events."""

    def __init__(self):
        pass

    def build_from_events(
        self,
        host: str,
        events: List[Dict[str, Any]],
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ) -> UnifiedHostGraph:
        """Process a collection of telemetry event dictionaries into a UnifiedHostGraph."""
        host_clean = host.strip().lower() if host else "unknown"
        nodes: Dict[str, HostGraphNode] = {}
        edges: Dict[str, HostGraphEdge] = {}

        # 1. Base Host Node
        host_node_id = f"host:{host_clean}"
        nodes[host_node_id] = HostGraphNode(
            id=host_node_id,
            node_type=HostNodeType.HOST,
            label=host_clean,
            properties={"hostname": host_clean},
            epistemic_status="OBSERVED",
        )

        for ev in events:
            ev_id = ev.get("id")
            ev_type = ev.get("event_type", "")
            raw_meta = ev.get("metadata", {}) or {}
            ts_val = ev.get("timestamp") or ev.get("first_seen")
            ts = self._parse_dt(ts_val)

            user = ev.get("username") or raw_meta.get("username")
            pid = ev.get("pid") or raw_meta.get("pid")
            ppid = ev.get("ppid") or raw_meta.get("ppid")
            proc_name = ev.get("process_name") or raw_meta.get("process_name") or raw_meta.get("exe")
            cmdline = raw_meta.get("cmdline") or raw_meta.get("command_line") or ev.get("summary")
            src_ip = ev.get("src_ip") or raw_meta.get("src_ip")
            dst_ip = ev.get("dst_ip") or raw_meta.get("dst_ip")
            dst_port = raw_meta.get("dst_port") or raw_meta.get("remote_port")
            src_port = raw_meta.get("src_port") or raw_meta.get("local_port")
            file_path = raw_meta.get("file_path") or raw_meta.get("path")
            unit_name = raw_meta.get("unit_name") or raw_meta.get("service")
            container_id = raw_meta.get("container_id") or raw_meta.get("container")
            session_id = raw_meta.get("session_id") or raw_meta.get("ses")

            # --- A. User Node ---
            user_node_id = None
            if user and str(user).strip() not in ("-", "unknown", ""):
                u_str = str(user).strip()
                user_node_id = f"user:{u_str}"
                if user_node_id not in nodes:
                    nodes[user_node_id] = HostGraphNode(
                        id=user_node_id,
                        node_type=HostNodeType.USER,
                        label=u_str,
                        properties={"username": u_str},
                        epistemic_status="OBSERVED",
                        first_seen=ts,
                        last_seen=ts,
                    )
                else:
                    self._update_node_times(nodes[user_node_id], ts)

                # User -> Host AUTHENTICATED_TO
                edge_id = f"{user_node_id}->{host_node_id}:AUTHENTICATED_TO"
                if edge_id not in edges:
                    edges[edge_id] = HostGraphEdge(
                        id=edge_id,
                        source=user_node_id,
                        target=host_node_id,
                        edge_type=HostEdgeType.AUTHENTICATED_TO,
                        confidence=ConfidenceLevel.DIRECT,
                        evidence_event_ids=[ev_id] if ev_id else [],
                        timestamp=ts,
                    )

            # --- B. Process Node ---
            proc_node_id = None
            if pid or proc_name:
                p_label = str(proc_name) if proc_name else f"PID:{pid}"
                proc_node_id = f"process:{host_clean}:{pid or 'unknown'}:{p_label}"
                if proc_node_id not in nodes:
                    nodes[proc_node_id] = HostGraphNode(
                        id=proc_node_id,
                        node_type=HostNodeType.PROCESS,
                        label=p_label,
                        properties={
                            "pid": pid,
                            "ppid": ppid,
                            "name": proc_name,
                            "command_line": cmdline,
                            "host": host_clean,
                        },
                        epistemic_status="OBSERVED",
                        first_seen=ts,
                        last_seen=ts,
                    )
                else:
                    self._update_node_times(nodes[proc_node_id], ts)

                # User -> Process EXECUTED
                if user_node_id:
                    edge_id = f"{user_node_id}->{proc_node_id}:EXECUTED"
                    if edge_id not in edges:
                        edges[edge_id] = HostGraphEdge(
                            id=edge_id,
                            source=user_node_id,
                            target=proc_node_id,
                            edge_type=HostEdgeType.EXECUTED,
                            confidence=ConfidenceLevel.DIRECT,
                            evidence_event_ids=[ev_id] if ev_id else [],
                            timestamp=ts,
                        )

                # Parent -> Child SPAWNED
                if ppid and ppid > 0:
                    parent_node_id = f"process:{host_clean}:{ppid}:parent"
                    if parent_node_id not in nodes:
                        nodes[parent_node_id] = HostGraphNode(
                            id=parent_node_id,
                            node_type=HostNodeType.PROCESS,
                            label=f"PID:{ppid}",
                            properties={"pid": ppid, "host": host_clean},
                            epistemic_status="INFERRED",
                            first_seen=ts,
                            last_seen=ts,
                        )
                    edge_id = f"{parent_node_id}->{proc_node_id}:SPAWNED"
                    if edge_id not in edges:
                        edges[edge_id] = HostGraphEdge(
                            id=edge_id,
                            source=parent_node_id,
                            target=proc_node_id,
                            edge_type=HostEdgeType.SPAWNED,
                            confidence=ConfidenceLevel.DIRECT,
                            evidence_event_ids=[ev_id] if ev_id else [],
                            timestamp=ts,
                        )

            # --- C. Network Connection Node & Edge ---
            target_ip = dst_ip or src_ip
            if target_ip and str(target_ip).strip() not in ("-", "unknown", "127.0.0.1", "::1", ""):
                ip_clean = str(target_ip).strip()
                ip_node_id = f"ip:{ip_clean}"
                if ip_node_id not in nodes:
                    nodes[ip_node_id] = HostGraphNode(
                        id=ip_node_id,
                        node_type=HostNodeType.IP,
                        label=ip_clean,
                        properties={"ip": ip_clean, "port": dst_port or src_port},
                        epistemic_status="OBSERVED",
                        first_seen=ts,
                        last_seen=ts,
                    )
                else:
                    self._update_node_times(nodes[ip_node_id], ts)

                # Process -> IP CONNECTED_TO
                source_id = proc_node_id or host_node_id
                edge_id = f"{source_id}->{ip_node_id}:CONNECTED_TO"
                if edge_id not in edges:
                    edges[edge_id] = HostGraphEdge(
                        id=edge_id,
                        source=source_id,
                        target=ip_node_id,
                        edge_type=HostEdgeType.CONNECTED_TO,
                        confidence=ConfidenceLevel.DIRECT if proc_node_id else ConfidenceLevel.STRONG,
                        evidence_event_ids=[ev_id] if ev_id else [],
                        timestamp=ts,
                    )

            # --- D. Filesystem Node & Edge ---
            if file_path and str(file_path).strip() not in ("-", "unknown", ""):
                fp_clean = str(file_path).strip()
                file_node_id = f"file:{fp_clean}"
                if file_node_id not in nodes:
                    nodes[file_node_id] = HostGraphNode(
                        id=file_node_id,
                        node_type=HostNodeType.FILE,
                        label=fp_clean,
                        properties={"path": fp_clean},
                        epistemic_status="OBSERVED",
                        first_seen=ts,
                        last_seen=ts,
                    )
                else:
                    self._update_node_times(nodes[file_node_id], ts)

                # Process -> File ACCESSED_FILE
                source_id = proc_node_id or user_node_id or host_node_id
                edge_id = f"{source_id}->{file_node_id}:ACCESSED_FILE"
                if edge_id not in edges:
                    edges[edge_id] = HostGraphEdge(
                        id=edge_id,
                        source=source_id,
                        target=file_node_id,
                        edge_type=HostEdgeType.ACCESSED_FILE,
                        confidence=ConfidenceLevel.DIRECT if proc_node_id else ConfidenceLevel.STRONG,
                        evidence_event_ids=[ev_id] if ev_id else [],
                        timestamp=ts,
                    )

            # --- E. Systemd Service Node & Edge ---
            if unit_name and str(unit_name).strip() not in ("-", "unknown", ""):
                svc_clean = str(unit_name).strip()
                svc_node_id = f"service:{svc_clean}"
                if svc_node_id not in nodes:
                    nodes[svc_node_id] = HostGraphNode(
                        id=svc_node_id,
                        node_type=HostNodeType.SERVICE,
                        label=svc_clean,
                        properties={"unit_name": svc_clean},
                        epistemic_status="OBSERVED",
                        first_seen=ts,
                        last_seen=ts,
                    )
                else:
                    self._update_node_times(nodes[svc_node_id], ts)

                # Process -> Service MANAGED_BY
                if proc_node_id:
                    edge_id = f"{proc_node_id}->{svc_node_id}:MANAGED_BY"
                    if edge_id not in edges:
                        edges[edge_id] = HostGraphEdge(
                            id=edge_id,
                            source=proc_node_id,
                            target=svc_node_id,
                            edge_type=HostEdgeType.MANAGED_BY,
                            confidence=ConfidenceLevel.DIRECT,
                            evidence_event_ids=[ev_id] if ev_id else [],
                            timestamp=ts,
                        )

            # --- F. Container Node & Edge ---
            if container_id and str(container_id).strip() not in ("-", "unknown", ""):
                c_clean = str(container_id).strip()[:12]
                cont_node_id = f"container:{c_clean}"
                if cont_node_id not in nodes:
                    nodes[cont_node_id] = HostGraphNode(
                        id=cont_node_id,
                        node_type=HostNodeType.CONTAINER,
                        label=c_clean,
                        properties={"container_id": c_clean},
                        epistemic_status="OBSERVED",
                        first_seen=ts,
                        last_seen=ts,
                    )
                else:
                    self._update_node_times(nodes[cont_node_id], ts)

                # Process -> Container CONTAINED_IN or ESCAPED_FROM
                if proc_node_id:
                    is_escape = "escape" in ev_type.lower() or "breakout" in str(ev.get("summary", "")).lower()
                    edge_type = HostEdgeType.ESCAPED_FROM if is_escape else HostEdgeType.CONTAINED_IN
                    edge_id = f"{proc_node_id}->{cont_node_id}:{edge_type.value}"
                    if edge_id not in edges:
                        edges[edge_id] = HostGraphEdge(
                            id=edge_id,
                            source=proc_node_id,
                            target=cont_node_id,
                            edge_type=edge_type,
                            confidence=ConfidenceLevel.DIRECT,
                            evidence_event_ids=[ev_id] if ev_id else [],
                            timestamp=ts,
                        )

        # Sort nodes and edges deterministically by ID
        sorted_nodes = sorted(nodes.values(), key=lambda n: n.id)
        sorted_edges = sorted(edges.values(), key=lambda e: e.id)

        proc_cnt = sum(1 for n in sorted_nodes if n.node_type == HostNodeType.PROCESS)
        conn_cnt = sum(1 for e in sorted_edges if e.edge_type == HostEdgeType.CONNECTED_TO)
        cont_cnt = sum(1 for n in sorted_nodes if n.node_type == HostNodeType.CONTAINER)
        svc_cnt = sum(1 for n in sorted_nodes if n.node_type == HostNodeType.SERVICE)
        file_cnt = sum(1 for n in sorted_nodes if n.node_type == HostNodeType.FILE)

        summary_text = (
            f"Host {host_clean}: {len(sorted_nodes)} entities ({proc_cnt} processes, "
            f"{cont_cnt} containers, {svc_cnt} services, {file_cnt} files) "
            f"connected by {len(sorted_edges)} causal edges."
        )

        return UnifiedHostGraph(
            host=host_clean,
            nodes=sorted_nodes,
            edges=sorted_edges,
            total_processes=proc_cnt,
            total_connections=conn_cnt,
            total_containers=cont_cnt,
            total_services=svc_cnt,
            total_files=file_cnt,
            summary=summary_text,
        )

    @staticmethod
    def _update_node_times(node: HostGraphNode, ts: Optional[datetime]) -> None:
        if not ts:
            return
        if not node.first_seen or ts < node.first_seen:
            node.first_seen = ts
        if not node.last_seen or ts > node.last_seen:
            node.last_seen = ts

    @staticmethod
    def _parse_dt(val: Any) -> Optional[datetime]:
        if not val:
            return None
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        if isinstance(val, str):
            try:
                dt = datetime.fromisoformat(val)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:
                return None
        return None


# Global singleton instance
host_graph_builder = HostGraphBuilder()
