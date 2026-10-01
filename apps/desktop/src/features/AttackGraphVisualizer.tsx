import React, { useMemo, useState } from "react";
import { ConfidenceBadge, EntityTypeBadge } from "../components/StatusBadge";
import { AttackGraphEdge, AttackGraphNode, AttackGraphResponse } from "../types/incidents";

interface AttackGraphVisualizerProps {
  graph: AttackGraphResponse;
  onSelectEntity?: (entityKey: string) => void;
  onSelectEventId?: (eventId: string) => void;
}

interface LayoutNode extends AttackGraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

export function AttackGraphVisualizer({
  graph,
  onSelectEntity,
  onSelectEventId,
}: AttackGraphVisualizerProps) {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [zoomLevel, setZoomLevel] = useState<number>(1);

  // Deterministic 2D layout calculation for nodes
  const layout = useMemo(() => {
    const nodes = graph.nodes;
    const edges = graph.edges;
    const width = 760;
    const height = 420;

    if (nodes.length === 0) {
      return { nodes: [], edges: [] };
    }

    // Initialize node positions in a circle around center
    const layoutNodes: LayoutNode[] = nodes.map((n, idx) => {
      const angle = (2 * Math.PI * idx) / Math.max(1, nodes.length);
      const radius = Math.min(width, height) * 0.35;
      return {
        ...n,
        x: width / 2 + radius * Math.cos(angle),
        y: height / 2 + radius * Math.sin(angle),
        vx: 0,
        vy: 0,
      };
    });

    const nodeMap = new Map<string, LayoutNode>();
    layoutNodes.forEach((n) => nodeMap.set(n.id, n));

    // Run simple spring-electrical force simulation (deterministic 60 iterations)
    const k = 140; // ideal spring distance
    const dt = 0.4;
    const iterations = 60;

    for (let iter = 0; iter < iterations; iter++) {
      // Repulsion between all node pairs
      for (let i = 0; i < layoutNodes.length; i++) {
        for (let j = i + 1; j < layoutNodes.length; j++) {
          const n1 = layoutNodes[i];
          const n2 = layoutNodes[j];
          let dx = n1.x - n2.x;
          let dy = n1.y - n2.y;
          let dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 1) {
            dx = (Math.random() - 0.5) * 10;
            dy = (Math.random() - 0.5) * 10;
            dist = 10;
          }
          const repForce = (k * k) / (dist * dist);
          const fx = (dx / dist) * repForce * 15;
          const fy = (dy / dist) * repForce * 15;

          n1.vx += fx;
          n1.vy += fy;
          n2.vx -= fx;
          n2.vy -= fy;
        }
      }

      // Spring attraction along edges
      for (const edge of edges) {
        const src = nodeMap.get(edge.source);
        const tgt = nodeMap.get(edge.target);
        if (src && tgt) {
          const dx = tgt.x - src.x;
          const dy = tgt.y - src.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const springForce = (dist - k) * 0.05;
          const fx = (dx / dist) * springForce;
          const fy = (dy / dist) * springForce;

          src.vx += fx;
          src.vy += fy;
          tgt.vx -= fx;
          tgt.vy -= fy;
        }
      }

      // Center gravity pull
      for (const n of layoutNodes) {
        const dx = width / 2 - n.x;
        const dy = height / 2 - n.y;
        n.vx += dx * 0.01;
        n.vy += dy * 0.01;

        // Apply velocity with damping
        n.x += n.vx * dt;
        n.y += n.vy * dt;
        n.vx *= 0.5;
        n.vy *= 0.5;

        // Bounding clamp
        n.x = Math.max(60, Math.min(width - 60, n.x));
        n.y = Math.max(40, Math.min(height - 40, n.y));
      }
    }

    return {
      nodes: layoutNodes,
      edges,
      width,
      height,
    };
  }, [graph]);

  const selectedNode = graph.nodes.find((n) => n.id === selectedNodeId);
  const selectedEdge = graph.edges.find((e) => e.id === selectedEdgeId);

  const getNodeColor = (type: string) => {
    switch (type.toUpperCase()) {
      case "HOST":
        return { stroke: "#0284c7", fill: "#f0f9ff", text: "#0369a1" };
      case "USER":
        return { stroke: "#d97706", fill: "#fffbeb", text: "#b45309" };
      case "IP":
        return { stroke: "#dc2626", fill: "#fef2f2", text: "#b91c1c" };
      case "PROCESS":
        return { stroke: "#7c3aed", fill: "#f5f3ff", text: "#6d28d9" };
      default:
        return { stroke: "#475569", fill: "#f8fafc", text: "#334155" };
    }
  };

  const nodeMap = useMemo(() => {
    const map = new Map<string, LayoutNode>();
    layout.nodes.forEach((n) => map.set(n.id, n));
    return map;
  }, [layout.nodes]);

  return (
    <div className="attack-graph-container" style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
      {/* Controls toolbar */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>
            Attack Graph Topology:
          </span>
          <span className="badge badge-neutral" style={{ fontSize: "11px" }}>
            {graph.nodes.length} Entities
          </span>
          <span className="badge badge-neutral" style={{ fontSize: "11px" }}>
            {graph.edges.length} Relationships
          </span>
        </div>

        <div style={{ display: "flex", gap: "4px" }}>
          <button
            className="btn btn-secondary"
            style={{ padding: "3px 8px", fontSize: "11px" }}
            onClick={() => setZoomLevel((z) => Math.max(0.6, z - 0.15))}
          >
            - Zoom
          </button>
          <span style={{ fontSize: "11px", padding: "4px 6px", fontFamily: "var(--font-mono)" }}>
            {Math.round(zoomLevel * 100)}%
          </span>
          <button
            className="btn btn-secondary"
            style={{ padding: "3px 8px", fontSize: "11px" }}
            onClick={() => setZoomLevel((z) => Math.min(1.8, z + 0.15))}
          >
            + Zoom
          </button>
          <button
            className="btn btn-secondary"
            style={{ padding: "3px 8px", fontSize: "11px" }}
            onClick={() => {
              setZoomLevel(1);
              setSelectedNodeId(null);
              setSelectedEdgeId(null);
            }}
          >
            Reset
          </button>
        </div>
      </div>

      {/* SVG Canvas */}
      <div
        style={{
          border: "1px solid var(--border-subtle)",
          borderRadius: "2px",
          background: "var(--bg-surface)",
          position: "relative",
          overflow: "hidden",
        }}
      >
        <svg
          viewBox={`0 0 ${layout.width || 760} ${layout.height || 420}`}
          style={{
            width: "100%",
            height: "420px",
            transform: `scale(${zoomLevel})`,
            transformOrigin: "center center",
            transition: "transform 0.15s ease-out",
          }}
        >
          <defs>
            {/* Arrowhead marker definition */}
            <marker
              id="graph-arrow"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
            </marker>
            <marker
              id="graph-arrow-active"
              viewBox="0 0 10 10"
              refX="18"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1 L 10 5 L 0 9 z" fill="#0284c7" />
            </marker>
          </defs>

          {/* Edges */}
          {layout.edges.map((edge) => {
            const src = nodeMap.get(edge.source);
            const tgt = nodeMap.get(edge.target);
            if (!src || !tgt) return null;

            const isSelected = selectedEdgeId === edge.id;
            const midX = (src.x + tgt.x) / 2;
            const midY = (src.y + tgt.y) / 2;
            const isCorrelated = edge.confidence === "CORRELATED" || edge.confidence === "INFERRED";

            return (
              <g
                key={edge.id}
                style={{ cursor: "pointer" }}
                onClick={() => {
                  setSelectedEdgeId(edge.id);
                  setSelectedNodeId(null);
                }}
              >
                {/* Edge line */}
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke={isSelected ? "#0284c7" : "#94a3b8"}
                  strokeWidth={isSelected ? 2.5 : 1.5}
                  strokeDasharray={isCorrelated ? "4,3" : undefined}
                  markerEnd={isSelected ? "url(#graph-arrow-active)" : "url(#graph-arrow)"}
                />

                {/* Edge label pill */}
                <rect
                  x={midX - 44}
                  y={midY - 9}
                  width="88"
                  height="18"
                  rx="3"
                  fill="var(--bg-surface)"
                  stroke={isSelected ? "#0284c7" : "#cbd5e1"}
                  strokeWidth="1"
                />
                <text
                  x={midX}
                  y={midY + 3.5}
                  textAnchor="middle"
                  fontSize="8.5"
                  fontWeight="600"
                  fill={isSelected ? "#0284c7" : "#475569"}
                  fontFamily="var(--font-mono)"
                >
                  {edge.relationship_type.replace(/_/g, " ")}
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {layout.nodes.map((node) => {
            const colors = getNodeColor(node.entity_type);
            const isSelected = selectedNodeId === node.id;
            const width = 110;
            const height = 42;

            return (
              <g
                key={node.id}
                transform={`translate(${node.x - width / 2}, ${node.y - height / 2})`}
                style={{ cursor: "pointer" }}
                onClick={() => {
                  setSelectedNodeId(node.id);
                  setSelectedEdgeId(null);
                  if (onSelectEntity) onSelectEntity(node.id);
                }}
              >
                {/* Node Box */}
                <rect
                  width={width}
                  height={height}
                  rx="4"
                  fill={colors.fill}
                  stroke={isSelected ? "#0284c7" : colors.stroke}
                  strokeWidth={isSelected ? 2.5 : 1.25}
                  filter={isSelected ? "drop-shadow(0 2px 4px rgba(0,0,0,0.12))" : undefined}
                />

                {/* Node Type Pill */}
                <text
                  x="8"
                  y="15"
                  fontSize="8"
                  fontWeight="700"
                  fill={colors.text}
                  fontFamily="var(--font-mono)"
                >
                  {node.entity_type}
                </text>

                {/* Node Label */}
                <text
                  x="8"
                  y="31"
                  fontSize="11"
                  fontWeight="600"
                  fill="var(--text-primary)"
                  fontFamily="var(--font-sans)"
                >
                  {node.label.length > 14 ? `${node.label.slice(0, 13)}…` : node.label}
                </text>
              </g>
            );
          })}
        </svg>

        {graph.nodes.length === 0 && (
          <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
            No entity graph elements correlated for this incident.
          </div>
        )}
      </div>

      {/* Selected Entity / Edge Inspector Drawer */}
      {selectedNode && (
        <div
          className="panel"
          style={{
            padding: "12px 14px",
            background: "var(--bg-surface-subtle)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "2px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <EntityTypeBadge entityType={selectedNode.entity_type} />
              <strong style={{ fontSize: "13px" }}>{selectedNode.label}</strong>
              <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                ({selectedNode.id})
              </span>
            </div>
            <button
              className="btn btn-secondary"
              style={{ padding: "2px 6px", fontSize: "10px" }}
              onClick={() => setSelectedNodeId(null)}
            >
              Close
            </button>
          </div>

          <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
            <strong>Entity Metadata:</strong>
            <pre
              style={{
                marginTop: "4px",
                padding: "8px",
                background: "var(--bg-surface)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "2px",
                fontFamily: "var(--font-mono)",
                fontSize: "11px",
              }}
            >
              {JSON.stringify(selectedNode.metadata, null, 2)}
            </pre>
          </div>
        </div>
      )}

      {selectedEdge && (
        <div
          className="panel"
          style={{
            padding: "12px 14px",
            background: "var(--bg-surface-subtle)",
            border: "1px solid var(--border-subtle)",
            borderRadius: "2px",
          }}
        >
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <span className="badge badge-notice" style={{ fontWeight: 600 }}>
                {selectedEdge.relationship_type}
              </span>
              <ConfidenceBadge confidence={selectedEdge.confidence} />
              <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                <strong>{selectedEdge.source}</strong> &rarr; <strong>{selectedEdge.target}</strong>
              </span>
            </div>
            <button
              className="btn btn-secondary"
              style={{ padding: "2px 6px", fontSize: "10px" }}
              onClick={() => setSelectedEdgeId(null)}
            >
              Close
            </button>
          </div>

          {selectedEdge.evidence_event_ids && selectedEdge.evidence_event_ids.length > 0 && (
            <div style={{ marginTop: "6px" }}>
              <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>
                Supporting Evidence Events ({selectedEdge.evidence_event_ids.length}):
              </span>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "4px" }}>
                {selectedEdge.evidence_event_ids.map((evId) => (
                  <button
                    key={evId}
                    className="btn btn-secondary"
                    style={{
                      padding: "2px 8px",
                      fontSize: "11px",
                      fontFamily: "var(--font-mono)",
                      cursor: onSelectEventId ? "pointer" : "default",
                    }}
                    onClick={() => onSelectEventId && onSelectEventId(evId)}
                  >
                    Event {evId.slice(0, 8)}...
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
