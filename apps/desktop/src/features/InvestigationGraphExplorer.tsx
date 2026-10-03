import React, { useEffect, useState, useMemo } from "react";
import {
  InvestigationGraph,
  InvestigationGraphNode,
  InvestigationGraphEdge,
  GraphEvidenceItem,
  EntityPivotGraph,
  InvestigationPath,
  TemporalChain,
  GraphExplanationResponse,
  RelationshipEpistemicStatus,
} from "../types/investigation";
import {
  fetchCaseInvestigationGraph,
  fetchCaseGraphNodeDetail,
  fetchCaseGraphEdgeEvidence,
  fetchCaseEntityPivotGraph,
  fetchCaseInvestigationPath,
  fetchCaseGraphTemporalChain,
  explainCaseGraphRelationship,
  exportCaseInvestigationGraph,
} from "../lib/api";
import { GraphIcon, TimelineIcon, ExportIcon, SearchIcon, FilterIcon, RefreshIcon, CheckIcon } from "../components/Icons";

interface InvestigationGraphExplorerProps {
  caseId: number;
  incidentId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function InvestigationGraphExplorer({
  caseId,
  incidentId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}: InvestigationGraphExplorerProps) {
  // Graph state
  const [graph, setGraph] = useState<InvestigationGraph | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Selection & Detail
  const [selectedNode, setSelectedNode] = useState<InvestigationGraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<InvestigationGraphEdge | null>(null);
  const [edgeEvidence, setEdgeEvidence] = useState<{
    edge: InvestigationGraphEdge;
    evidence_references: Array<Record<string, any>>;
    evidence_event_ids: string[];
    corroboration_status: string;
    epistemic_status: string;
    is_authoritative: boolean;
  } | null>(null);
  const [edgeEvidenceLoading, setEdgeEvidenceLoading] = useState<boolean>(false);

  // Filter controls
  const [epistemicFilter, setEpistemicFilter] = useState<string>("ALL");
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [maxNodesLimit, setMaxNodesLimit] = useState<number>(100);

  // View Mode
  const [viewMode, setViewMode] = useState<"graph" | "pivot" | "path" | "temporal">("graph");

  // Pivot Mode State
  const [pivotKey, setPivotKey] = useState<string>("");
  const [pivotData, setPivotData] = useState<EntityPivotGraph | null>(null);
  const [pivotLoading, setPivotLoading] = useState<boolean>(false);

  // Path Mode State
  const [pathSource, setPathSource] = useState<string>("");
  const [pathTarget, setPathTarget] = useState<string>("");
  const [investigationPath, setInvestigationPath] = useState<InvestigationPath | null>(null);
  const [pathLoading, setPathLoading] = useState<boolean>(false);

  // Temporal Chain State
  const [temporalChain, setTemporalChain] = useState<TemporalChain | null>(null);
  const [temporalLoading, setTemporalLoading] = useState<boolean>(false);

  // Local AI Explanation State
  const [aiExplanation, setAiExplanation] = useState<GraphExplanationResponse | null>(null);
  const [aiExplaining, setAiExplaining] = useState<boolean>(false);
  const [aiQuestion, setAiQuestion] = useState<string>("");

  // Export State
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  useEffect(() => {
    loadGraph();
  }, [caseId]);

  const loadGraph = async () => {
    setLoading(true);
    setError(null);
    try {
      const g = await fetchCaseInvestigationGraph(caseId, {
        max_nodes: maxNodesLimit,
        epistemic_status: epistemicFilter !== "ALL" ? (epistemicFilter as RelationshipEpistemicStatus) : undefined,
        relationship_type: typeFilter !== "ALL" ? typeFilter : undefined,
      });
      setGraph(g);
      setSelectedNode(null);
      setSelectedEdge(null);
      setEdgeEvidence(null);
      setAiExplanation(null);
    } catch (err: any) {
      setError(err.message || "Failed to load investigation graph");
    } finally {
      setLoading(false);
    }
  };

  const handleSelectEdge = async (edge: InvestigationGraphEdge) => {
    setSelectedEdge(edge);
    setSelectedNode(null);
    setAiExplanation(null);
    setEdgeEvidenceLoading(true);
    try {
      const res = await fetchCaseGraphEdgeEvidence(caseId, edge.edge_id);
      setEdgeEvidence(res);
    } catch (err: any) {
      setEdgeEvidence({
        edge,
        evidence_references: edge.evidence_references,
        evidence_event_ids: edge.evidence_event_ids,
        corroboration_status: edge.corroboration_status,
        epistemic_status: edge.epistemic_status,
        is_authoritative: edge.is_authoritative,
      });
    } finally {
      setEdgeEvidenceLoading(false);
    }
  };

  const handleSelectNode = async (node: InvestigationGraphNode) => {
    setSelectedNode(node);
    setSelectedEdge(null);
    setEdgeEvidence(null);
    setAiExplanation(null);
    setPivotKey(node.display_label);
  };

  const handleRunPivot = async (keyToPivot?: string) => {
    const k = keyToPivot || pivotKey;
    if (!k.trim()) return;
    setPivotLoading(true);
    setError(null);
    try {
      let entityType = "host";
      let entityValue = k.trim();
      if (k.includes(":")) {
        const parts = k.split(":");
        entityType = parts[0];
        entityValue = parts.slice(1).join(":");
      }
      const p = await fetchCaseEntityPivotGraph(caseId, entityType, entityValue);
      setPivotData(p);
      setViewMode("pivot");
    } catch (err: any) {
      setError(err.message || "Failed to run entity pivot query");
    } finally {
      setPivotLoading(false);
    }
  };

  const handleFindPath = async () => {
    if (!pathSource.trim() || !pathTarget.trim()) return;
    setPathLoading(true);
    setError(null);
    try {
      const p = await fetchCaseInvestigationPath(caseId, pathSource.trim(), pathTarget.trim(), 5);
      setInvestigationPath(p);
    } catch (err: any) {
      setError(err.message || "Failed to find investigation path");
    } finally {
      setPathLoading(false);
    }
  };

  const handleLoadTemporal = async () => {
    setTemporalLoading(true);
    setError(null);
    try {
      const t = await fetchCaseGraphTemporalChain(caseId);
      setTemporalChain(t);
    } catch (err: any) {
      setError(err.message || "Failed to load temporal relationship chain");
    } finally {
      setTemporalLoading(false);
    }
  };

  const handleAiExplainEdge = async () => {
    if (!selectedEdge) return;
    setAiExplaining(true);
    try {
      const exp = await explainCaseGraphRelationship(caseId, {
        edge_id: selectedEdge.edge_id,
        question: aiQuestion.trim() || undefined,
        include_evidence_citations: true,
      });
      setAiExplanation(exp);
    } catch (err: any) {
      setError(err.message || "Failed to generate AI explanation");
    } finally {
      setAiExplaining(false);
    }
  };

  const handleExport = async (format: "json" | "graphml") => {
    try {
      const res = await exportCaseInvestigationGraph(caseId, format);
      const blob = new Blob([res.content], { type: format === "json" ? "application/json" : "application/xml" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case_${caseId}_investigation_graph.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      setExportNotice(`Exported graph as ${format.toUpperCase()}`);
      setTimeout(() => setExportNotice(null), 3000);
    } catch (err: any) {
      setError(err.message || `Failed to export graph as ${format}`);
    }
  };

  // Filtered nodes and edges for display
  const filteredNodes = useMemo(() => {
    if (!graph) return [];
    return graph.nodes.filter((n) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        return n.display_label.toLowerCase().includes(q) || n.node_type.toLowerCase().includes(q);
      }
      return true;
    });
  }, [graph, searchQuery]);

  const filteredEdges = useMemo(() => {
    if (!graph) return [];
    return graph.edges.filter((e) => {
      if (epistemicFilter !== "ALL" && e.epistemic_status !== epistemicFilter) return false;
      if (typeFilter !== "ALL" && e.relationship_type !== typeFilter) return false;
      return true;
    });
  }, [graph, epistemicFilter, typeFilter]);

  // Distinct relationship types for filtering
  const distinctRelTypes = useMemo(() => {
    if (!graph) return [];
    const types = new Set<string>();
    graph.edges.forEach((e) => types.add(e.relationship_type));
    return Array.from(types).sort();
  }, [graph]);

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", gap: "10px" }}>
      {/* Top Controls Bar */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "8px",
          padding: "8px 12px",
          background: "var(--bg-surface)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "4px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <button
            className={`btn btn-secondary ${viewMode === "graph" ? "active" : ""}`}
            style={{ padding: "4px 8px", fontSize: "11px", fontWeight: viewMode === "graph" ? 600 : 400 }}
            onClick={() => setViewMode("graph")}
          >
            <GraphIcon /> Investigation Graph
          </button>
          <button
            className={`btn btn-secondary ${viewMode === "pivot" ? "active" : ""}`}
            style={{ padding: "4px 8px", fontSize: "11px", fontWeight: viewMode === "pivot" ? 600 : 400 }}
            onClick={() => setViewMode("pivot")}
          >
            <SearchIcon /> Entity Pivot
          </button>
          <button
            className={`btn btn-secondary ${viewMode === "path" ? "active" : ""}`}
            style={{ padding: "4px 8px", fontSize: "11px", fontWeight: viewMode === "path" ? 600 : 400 }}
            onClick={() => setViewMode("path")}
          >
            Investigation Path
          </button>
          <button
            className={`btn btn-secondary ${viewMode === "temporal" ? "active" : ""}`}
            style={{ padding: "4px 8px", fontSize: "11px", fontWeight: viewMode === "temporal" ? 600 : 400 }}
            onClick={() => {
              setViewMode("temporal");
              if (!temporalChain) handleLoadTemporal();
            }}
          >
            <TimelineIcon /> Temporal Chain
          </button>
        </div>

        {/* Action Controls & Export */}
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <button
            className="btn btn-secondary"
            style={{ padding: "4px 8px", fontSize: "11px" }}
            onClick={loadGraph}
            disabled={loading}
          >
            <RefreshIcon /> {loading ? "Loading..." : "Refresh"}
          </button>
          <button
            className="btn btn-secondary"
            style={{ padding: "4px 8px", fontSize: "11px" }}
            onClick={() => handleExport("json")}
          >
            <ExportIcon /> Export JSON
          </button>
          <button
            className="btn btn-secondary"
            style={{ padding: "4px 8px", fontSize: "11px" }}
            onClick={() => handleExport("graphml")}
          >
            Export GraphML
          </button>
        </div>
      </div>

      {exportNotice && (
        <div style={{ padding: "6px 12px", background: "var(--bg-accent-subtle, #1a2a1a)", color: "#4caf50", fontSize: "11px", borderRadius: "3px" }}>
          <CheckIcon /> {exportNotice}
        </div>
      )}

      {error && (
        <div style={{ padding: "8px 12px", background: "rgba(220, 53, 69, 0.1)", color: "var(--badge-alert-text)", fontSize: "11px", borderRadius: "3px" }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* Main Workspace Body */}
      {viewMode === "graph" && (
        <div style={{ display: "flex", flex: 1, gap: "10px", minHeight: "520px" }}>
          {/* Left / Center Graph & Tables */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "8px" }}>
            {/* Filter Bar */}
            <div
              style={{
                display: "flex",
                gap: "8px",
                alignItems: "center",
                padding: "6px 10px",
                background: "var(--bg-surface)",
                border: "1px solid var(--border-subtle)",
                borderRadius: "3px",
                fontSize: "11px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                <FilterIcon />
                <span>Epistemic:</span>
                <select
                  value={epistemicFilter}
                  onChange={(e) => setEpistemicFilter(e.target.value)}
                  style={{ padding: "2px 6px", fontSize: "11px", background: "var(--bg-primary)", border: "1px solid var(--border-strong)" }}
                >
                  <option value="ALL">All Statuses</option>
                  <option value="OBSERVED">OBSERVED</option>
                  <option value="INFERRED">INFERRED</option>
                  <option value="UNKNOWN">UNKNOWN</option>
                </select>
              </div>

              {distinctRelTypes.length > 0 && (
                <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
                  <span>Relation:</span>
                  <select
                    value={typeFilter}
                    onChange={(e) => setTypeFilter(e.target.value)}
                    style={{ padding: "2px 6px", fontSize: "11px", background: "var(--bg-primary)", border: "1px solid var(--border-strong)" }}
                  >
                    <option value="ALL">All Types</option>
                    {distinctRelTypes.map((rt) => (
                      <option key={rt} value={rt}>{rt}</option>
                    ))}
                  </select>
                </div>
              )}

              <div style={{ display: "flex", alignItems: "center", gap: "4px", marginLeft: "auto" }}>
                <input
                  type="text"
                  placeholder="Filter nodes..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{ padding: "2px 6px", fontSize: "11px", border: "1px solid var(--border-strong)", width: "140px" }}
                />
              </div>

              <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                Nodes: {filteredNodes.length}/{graph?.nodes?.length || 0} | Edges: {filteredEdges.length}/{graph?.edges?.length || 0}
              </div>
            </div>

            {/* Edge Matrix / Graph List View */}
            <div
              style={{
                flex: 1,
                overflowY: "auto",
                border: "1px solid var(--border-subtle)",
                borderRadius: "3px",
                background: "var(--bg-surface)",
              }}
            >
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                <thead>
                  <tr style={{ background: "var(--bg-subtle, #181b20)", borderBottom: "1px solid var(--border-subtle)", textAlign: "left" }}>
                    <th style={{ padding: "6px 8px" }}>Source Node</th>
                    <th style={{ padding: "6px 8px" }}>Relationship</th>
                    <th style={{ padding: "6px 8px" }}>Target Node</th>
                    <th style={{ padding: "6px 8px" }}>Epistemic Status</th>
                    <th style={{ padding: "6px 8px" }}>Corroboration</th>
                    <th style={{ padding: "6px 8px" }}>Evidence Items</th>
                    <th style={{ padding: "6px 8px" }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredEdges.map((e) => {
                    const isSelected = selectedEdge?.edge_id === e.edge_id;
                    const statusColor =
                      e.epistemic_status === "OBSERVED"
                        ? "#2e7d32"
                        : e.epistemic_status === "INFERRED"
                        ? "#f57c00"
                        : "#757575";

                    return (
                      <tr
                        key={e.edge_id}
                        onClick={() => handleSelectEdge(e)}
                        style={{
                          borderBottom: "1px solid var(--border-subtle)",
                          background: isSelected ? "var(--bg-active, rgba(0, 120, 215, 0.15))" : "transparent",
                          cursor: "pointer",
                        }}
                      >
                        <td style={{ padding: "6px 8px", fontWeight: 500 }}>
                          <span
                            onClick={(ev) => {
                              ev.stopPropagation();
                              const n = graph?.nodes.find((x) => x.node_id === e.source_node_id);
                              if (n) handleSelectNode(n);
                            }}
                            style={{ textDecoration: "underline", color: "var(--link-color, #4ea8de)" }}
                          >
                            {e.source_node_id}
                          </span>
                        </td>
                        <td style={{ padding: "6px 8px" }}>
                          <span style={{ fontFamily: "monospace", fontSize: "10px", fontWeight: 600 }}>
                            {e.relationship_type} &rarr;
                          </span>
                        </td>
                        <td style={{ padding: "6px 8px", fontWeight: 500 }}>
                          <span
                            onClick={(ev) => {
                              ev.stopPropagation();
                              const n = graph?.nodes.find((x) => x.node_id === e.target_node_id);
                              if (n) handleSelectNode(n);
                            }}
                            style={{ textDecoration: "underline", color: "var(--link-color, #4ea8de)" }}
                          >
                            {e.target_node_id}
                          </span>
                        </td>
                        <td style={{ padding: "6px 8px" }}>
                          <span
                            style={{
                              display: "inline-block",
                              padding: "2px 6px",
                              borderRadius: "2px",
                              fontSize: "9px",
                              fontWeight: 700,
                              color: "#fff",
                              backgroundColor: statusColor,
                            }}
                          >
                            {e.epistemic_status}
                          </span>
                        </td>
                        <td style={{ padding: "6px 8px", fontSize: "10px", color: "var(--text-muted)" }}>
                          {e.corroboration_status}
                        </td>
                        <td style={{ padding: "6px 8px", fontSize: "10px" }}>
                          {e.evidence_references?.length || e.evidence_event_ids?.length || 0} ref{(e.evidence_references?.length || 0) === 1 ? "" : "s"}
                        </td>
                        <td style={{ padding: "6px 8px" }}>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: "2px 6px", fontSize: "10px" }}
                            onClick={(ev) => {
                              ev.stopPropagation();
                              handleSelectEdge(e);
                            }}
                          >
                            Inspect Evidence
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                  {filteredEdges.length === 0 && (
                    <tr>
                      <td colSpan={7} style={{ padding: "20px", textAlign: "center", color: "var(--text-muted)" }}>
                        {loading ? "Loading investigation graph..." : "No relationship edges match current filters."}
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            {/* Nodes Summary Strip */}
            <div
              style={{
                display: "flex",
                gap: "6px",
                overflowX: "auto",
                padding: "6px",
                border: "1px solid var(--border-subtle)",
                borderRadius: "3px",
                background: "var(--bg-surface)",
                fontSize: "11px",
              }}
            >
              <span style={{ fontWeight: 600, color: "var(--text-muted)", alignSelf: "center", marginRight: "4px" }}>
                Entities:
              </span>
              {filteredNodes.slice(0, 20).map((n) => (
                <div
                  key={n.node_id}
                  onClick={() => handleSelectNode(n)}
                  style={{
                    padding: "2px 8px",
                    background: selectedNode?.node_id === n.node_id ? "var(--bg-active, #0078d7)" : "var(--bg-primary)",
                    color: selectedNode?.node_id === n.node_id ? "#fff" : "var(--text-primary)",
                    border: "1px solid var(--border-strong)",
                    borderRadius: "2px",
                    cursor: "pointer",
                    whiteSpace: "nowrap",
                    fontSize: "10px",
                  }}
                >
                  <strong>[{n.node_type}]</strong> {n.display_label}
                </div>
              ))}
              {filteredNodes.length > 20 && (
                <span style={{ fontSize: "10px", color: "var(--text-muted)", alignSelf: "center" }}>
                  +{filteredNodes.length - 20} more
                </span>
              )}
            </div>
          </div>

          {/* Right Panel: Structured Evidence Side Panel (M58-17) or Node Detail */}
          <div
            style={{
              width: "380px",
              display: "flex",
              flexDirection: "column",
              border: "1px solid var(--border-subtle)",
              borderRadius: "4px",
              background: "var(--bg-surface)",
              overflowY: "auto",
              padding: "12px",
              fontSize: "11px",
            }}
          >
            {selectedEdge ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <div style={{ borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
                    Evidence Side Panel (M58-17)
                  </div>
                  <div style={{ fontSize: "13px", fontWeight: 700, marginTop: "4px" }}>
                    {selectedEdge.source_node_id} &rarr; {selectedEdge.target_node_id}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                    Relationship: <strong style={{ color: "var(--text-primary)" }}>{selectedEdge.relationship_type}</strong>
                  </div>
                </div>

                {/* Epistemic Status & Authority */}
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
                  <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>Epistemic Status</div>
                    <div style={{ fontWeight: 700, color: selectedEdge.epistemic_status === "OBSERVED" ? "#4caf50" : "#ff9800" }}>
                      {selectedEdge.epistemic_status}
                    </div>
                  </div>
                  <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>Authority</div>
                    <div style={{ fontWeight: 600, fontSize: "10px" }}>
                      {selectedEdge.is_authoritative ? "AUTHORITATIVE_TELEMETRY" : "DERIVED_ANALYTICAL"}
                    </div>
                  </div>
                </div>

                <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                  <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>Corroboration Quality</div>
                  <div style={{ fontWeight: 600 }}>{selectedEdge.corroboration_status}</div>
                </div>

                {/* Temporal Context */}
                <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                  <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>Temporal Bounds</div>
                  <div style={{ fontSize: "10px" }}>
                    First: {selectedEdge.first_seen || "N/A"}<br />
                    Last: {selectedEdge.last_seen || "N/A"}
                  </div>
                </div>

                {/* MITRE Mapping */}
                {selectedEdge.mitre_technique_id && (
                  <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>MITRE ATT&CK Mapping</div>
                    <div style={{ display: "flex", gap: "4px", flexWrap: "wrap", marginTop: "4px" }}>
                      <span style={{ padding: "1px 5px", background: "#b71c1c", color: "#fff", borderRadius: "2px", fontSize: "9px", fontWeight: 700 }}>
                        {selectedEdge.mitre_technique_id} {selectedEdge.mitre_tactic ? `(${selectedEdge.mitre_tactic})` : ""}
                      </span>
                    </div>
                  </div>
                )}

                {/* Supporting Evidence Items */}
                <div>
                  <div style={{ fontWeight: 700, fontSize: "11px", marginBottom: "6px" }}>
                    Supporting Evidence ({edgeEvidence?.evidence_references?.length || selectedEdge.evidence_references?.length || 0})
                  </div>
                  {edgeEvidenceLoading && <div style={{ color: "var(--text-muted)" }}>Loading evidence records...</div>}
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {(edgeEvidence?.evidence_references || selectedEdge.evidence_references || []).map((ev: any, idx: number) => (
                      <div
                        key={ev.source_id || idx}
                        style={{
                          padding: "6px 8px",
                          background: "var(--bg-primary)",
                          border: "1px solid var(--border-subtle)",
                          borderRadius: "3px",
                        }}
                      >
                        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "10px" }}>
                          <span style={{ fontWeight: 600 }}>{ev.source_type || ev.role || "EVIDENCE"}</span>
                          <span style={{ color: "var(--text-muted)" }}>{ev.timestamp || "N/A"}</span>
                        </div>
                        <div style={{ fontSize: "11px", marginTop: "2px" }}>{ev.summary}</div>
                        <div style={{ fontSize: "9px", color: "var(--text-muted)", marginTop: "4px" }}>
                          Source: {ev.citation_tag || ev.source_id} | Epistemic: {ev.epistemic_status}
                        </div>
                        {ev.citation_tag && typeof ev.citation_tag === "string" && ev.citation_tag.startsWith("[event:") && onSelectEventId && (
                          <button
                            className="btn btn-secondary"
                            style={{ padding: "1px 5px", fontSize: "9px", marginTop: "4px" }}
                            onClick={() => onSelectEventId(ev.source_id)}
                          >
                            View Forensic Event
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Provenance Path */}
                {selectedEdge.provenance && (
                  <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                    Provenance: <span style={{ fontFamily: "monospace" }}>{selectedEdge.provenance}</span>
                  </div>
                )}

                {/* Local AI Graph Explanation (M58-13) */}
                <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "8px", marginTop: "4px" }}>
                  <div style={{ fontWeight: 700, fontSize: "11px" }}>Local AI Relationship Explanation</div>
                  <div style={{ fontSize: "9px", color: "var(--text-muted)", marginBottom: "6px" }}>
                    Advisory only — derived strictly from verified evidence.
                  </div>
                  <input
                    type="text"
                    placeholder="Specific question (optional)..."
                    value={aiQuestion}
                    onChange={(e) => setAiQuestion(e.target.value)}
                    style={{ width: "100%", padding: "4px 6px", fontSize: "10px", border: "1px solid var(--border-strong)", marginBottom: "6px" }}
                  />
                  <button
                    className="btn btn-secondary"
                    style={{ padding: "4px 8px", fontSize: "10px", width: "100%" }}
                    onClick={handleAiExplainEdge}
                    disabled={aiExplaining}
                  >
                    {aiExplaining ? "Explaining with Local AI..." : "Explain Relationship"}
                  </button>

                  {aiExplanation && (
                    <div style={{ marginTop: "8px", padding: "8px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-primary)" }}>
                        {aiExplanation.summary}
                      </div>
                      {aiExplanation.evidence_citations && aiExplanation.evidence_citations.length > 0 && (
                        <div style={{ marginTop: "6px", fontSize: "9px", color: "var(--text-muted)" }}>
                          Citations: {aiExplanation.evidence_citations.join(", ")}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            ) : selectedNode ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                <div style={{ borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px" }}>
                  <div style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 700 }}>
                    Entity Node Detail
                  </div>
                  <div style={{ fontSize: "14px", fontWeight: 700, marginTop: "4px" }}>
                    {selectedNode.display_label}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                    Type: <strong style={{ color: "var(--text-primary)" }}>{selectedNode.node_type}</strong>
                  </div>
                </div>

                <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                  <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>Node ID</div>
                  <div style={{ fontFamily: "monospace", fontSize: "10px" }}>{selectedNode.node_id}</div>
                </div>

                <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                  <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>Epistemic Status & Authority</div>
                  <div style={{ fontWeight: 600 }}>
                    {selectedNode.epistemic_status} &middot; {selectedNode.is_authoritative ? "AUTHORITATIVE" : "DERIVED"}
                  </div>
                </div>

                {selectedNode.source_reference && (
                  <div style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
                    <div style={{ fontSize: "9px", color: "var(--text-muted)" }}>Source Reference</div>
                    <div style={{ fontSize: "10px", fontFamily: "monospace" }}>{selectedNode.source_reference}</div>
                  </div>
                )}

                <button
                  className="btn btn-primary"
                  style={{ padding: "6px 10px", fontSize: "11px", marginTop: "10px" }}
                  onClick={() => handleRunPivot(selectedNode.display_label)}
                >
                  Pivot on {selectedNode.display_label} &rarr;
                </button>
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "100%", color: "var(--text-muted)", textAlign: "center" }}>
                <GraphIcon />
                <div style={{ marginTop: "8px", fontWeight: 600 }}>Select a Relationship Edge or Node</div>
                <div style={{ fontSize: "10px", marginTop: "4px" }}>
                  Inspect evidence, corroboration quality, epistemic status, temporal bounds, and local AI explanation.
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Mode: Entity Pivot Explorer (M58-06) */}
      {viewMode === "pivot" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", minHeight: "520px" }}>
          <div style={{ display: "flex", gap: "8px", alignItems: "center", background: "var(--bg-surface)", padding: "8px 12px", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
            <span style={{ fontSize: "11px", fontWeight: 600 }}>Entity Key / Identifier:</span>
            <input
              type="text"
              placeholder="e.g. 192.168.1.100 or alice or powershell.exe"
              value={pivotKey}
              onChange={(e) => setPivotKey(e.target.value)}
              style={{ padding: "4px 8px", fontSize: "11px", border: "1px solid var(--border-strong)", width: "320px" }}
            />
            <button
              className="btn btn-primary"
              style={{ padding: "4px 10px", fontSize: "11px" }}
              onClick={() => handleRunPivot()}
              disabled={pivotLoading || !pivotKey.trim()}
            >
              {pivotLoading ? "Executing Pivot..." : "Run Entity Pivot"}
            </button>
          </div>

          {pivotData ? (
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px", flex: 1 }}>
              {/* Connected Nodes */}
              <div style={{ border: "1px solid var(--border-subtle)", borderRadius: "3px", padding: "10px", background: "var(--bg-surface)", overflowY: "auto" }}>
                <div style={{ fontWeight: 700, fontSize: "12px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "6px", marginBottom: "8px" }}>
                  Connected Entities ({pivotData.connected_nodes.length})
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {pivotData.connected_nodes.map((node) => (
                    <div key={node.node_id} style={{ padding: "6px", background: "var(--bg-primary)", borderRadius: "3px", fontSize: "11px" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", color: "var(--text-muted)", fontSize: "9px" }}>
                        <span>[{node.node_type}]</span>
                        <span>{node.epistemic_status}</span>
                      </div>
                      <div style={{ fontWeight: 600, marginTop: "2px" }}>{node.display_label}</div>
                    </div>
                  ))}
                  {pivotData.connected_nodes.length === 0 && (
                    <div style={{ color: "var(--text-muted)", fontSize: "11px" }}>No connected entities directly linked.</div>
                  )}
                </div>
              </div>

              {/* Connected Relationships & Metrics */}
              <div style={{ border: "1px solid var(--border-subtle)", borderRadius: "3px", padding: "10px", background: "var(--bg-surface)", overflowY: "auto" }}>
                <div style={{ fontWeight: 700, fontSize: "12px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "6px", marginBottom: "8px" }}>
                  Pivot Telemetry Metrics
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "8px", marginBottom: "12px" }}>
                  <div style={{ padding: "8px", background: "var(--bg-primary)", borderRadius: "3px", textAlign: "center" }}>
                    <div style={{ fontSize: "18px", fontWeight: 700 }}>{pivotData.related_events_count}</div>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>Related Events</div>
                  </div>
                  <div style={{ padding: "8px", background: "var(--bg-primary)", borderRadius: "3px", textAlign: "center" }}>
                    <div style={{ fontSize: "18px", fontWeight: 700 }}>{pivotData.related_alerts_count}</div>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>Related Alerts</div>
                  </div>
                  <div style={{ padding: "8px", background: "var(--bg-primary)", borderRadius: "3px", textAlign: "center" }}>
                    <div style={{ fontSize: "18px", fontWeight: 700 }}>{pivotData.related_findings_count}</div>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>Related Findings</div>
                  </div>
                  <div style={{ padding: "8px", background: "var(--bg-primary)", borderRadius: "3px", textAlign: "center" }}>
                    <div style={{ fontSize: "18px", fontWeight: 700 }}>{pivotData.timeline_occurrences_count}</div>
                    <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>Timeline Points</div>
                  </div>
                </div>

                <div style={{ fontWeight: 600, fontSize: "11px", marginBottom: "6px" }}>Connected Edges ({pivotData.connected_edges.length}):</div>
                <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                  {pivotData.connected_edges.map((edge) => (
                    <div key={edge.edge_id} style={{ padding: "4px 6px", background: "var(--bg-primary)", borderRadius: "2px", fontSize: "10px" }}>
                      {edge.source_node_id} &rarr; <strong>{edge.relationship_type}</strong> &rarr; {edge.target_node_id}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "300px", color: "var(--text-muted)", fontSize: "11px" }}>
              Enter an entity key above and click Run Entity Pivot to explore all connected telemetry.
            </div>
          )}
        </div>
      )}

      {/* Mode: Investigation Path Analysis (M58-11) */}
      {viewMode === "path" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px", minHeight: "520px" }}>
          <div style={{ display: "flex", gap: "8px", alignItems: "center", background: "var(--bg-surface)", padding: "8px 12px", borderRadius: "3px", border: "1px solid var(--border-subtle)" }}>
            <span style={{ fontSize: "11px", fontWeight: 600 }}>Source Entity:</span>
            <input
              type="text"
              placeholder="e.g. user:alice"
              value={pathSource}
              onChange={(e) => setPathSource(e.target.value)}
              style={{ padding: "4px 8px", fontSize: "11px", border: "1px solid var(--border-strong)", width: "200px" }}
            />
            <span style={{ fontSize: "11px", fontWeight: 600 }}>Target Entity:</span>
            <input
              type="text"
              placeholder="e.g. ip:10.0.0.5"
              value={pathTarget}
              onChange={(e) => setPathTarget(e.target.value)}
              style={{ padding: "4px 8px", fontSize: "11px", border: "1px solid var(--border-strong)", width: "200px" }}
            />
            <button
              className="btn btn-primary"
              style={{ padding: "4px 10px", fontSize: "11px" }}
              onClick={handleFindPath}
              disabled={pathLoading || !pathSource.trim() || !pathTarget.trim()}
            >
              {pathLoading ? "Analyzing Paths..." : "Find Investigation Path"}
            </button>
          </div>

          {investigationPath ? (
            <div style={{ border: "1px solid var(--border-subtle)", borderRadius: "3px", padding: "12px", background: "var(--bg-surface)", flex: 1, overflowY: "auto" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px", marginBottom: "12px" }}>
                <div>
                  <span style={{ fontWeight: 700, fontSize: "13px" }}>
                    Investigation Path: {investigationPath.source_node_id} &rarr; {investigationPath.target_node_id}
                  </span>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                    Path Nature: <strong>{investigationPath.path_nature}</strong> &middot; Summary: {investigationPath.summary}
                  </div>
                </div>
                <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                  Total Steps: {investigationPath.edges.length} edges
                </div>
              </div>

              {/* Step-by-step chain */}
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {investigationPath.edges.map((e, idx) => (
                  <div
                    key={e.edge_id || idx}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: "12px",
                      padding: "8px 12px",
                      background: "var(--bg-primary)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "3px",
                    }}
                  >
                    <div style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-muted)" }}>
                      Step {idx + 1}
                    </div>
                    <div style={{ fontWeight: 600, fontSize: "12px" }}>
                      {e.source_node_id}
                    </div>
                    <div style={{ fontSize: "10px", padding: "2px 6px", background: "var(--bg-surface)", border: "1px solid var(--border-strong)", borderRadius: "2px" }}>
                      &mdash;[{e.relationship_type}]&rarr;
                    </div>
                    <div style={{ fontWeight: 600, fontSize: "12px" }}>
                      {e.target_node_id}
                    </div>
                    <div style={{ marginLeft: "auto", display: "flex", gap: "6px" }}>
                      <span style={{ fontSize: "10px", fontWeight: 700, padding: "2px 6px", borderRadius: "2px", background: e.epistemic_status === "OBSERVED" ? "#2e7d32" : "#f57c00", color: "#fff" }}>
                        {e.epistemic_status}
                      </span>
                      <span style={{ fontSize: "10px", color: "var(--text-muted)", alignSelf: "center" }}>
                        {e.evidence_references?.length || e.evidence_event_ids?.length || 0} evidence items
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "300px", color: "var(--text-muted)", fontSize: "11px" }}>
              Enter source and target entity IDs to trace the deterministic evidence-backed investigation path.
            </div>
          )}
        </div>
      )}

      {/* Mode: Temporal Chain (M58-05) */}
      {viewMode === "temporal" && (
        <div style={{ border: "1px solid var(--border-subtle)", borderRadius: "3px", padding: "12px", background: "var(--bg-surface)", flex: 1, overflowY: "auto" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "8px", marginBottom: "12px" }}>
            <div style={{ fontWeight: 700, fontSize: "13px" }}>
              Deterministic Temporal Relationship Intelligence (M58-05)
            </div>
            <button
              className="btn btn-secondary"
              style={{ padding: "4px 8px", fontSize: "11px" }}
              onClick={handleLoadTemporal}
              disabled={temporalLoading}
            >
              <RefreshIcon /> {temporalLoading ? "Ordering..." : "Refresh Sequence"}
            </button>
          </div>

          {temporalChain && temporalChain.steps.length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              {temporalChain.steps.map((st) => (
                <div
                  key={st.step_index}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "12px",
                    padding: "8px 12px",
                    background: "var(--bg-primary)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "3px",
                  }}
                >
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-muted)", width: "60px" }}>
                    #{st.step_index + 1}
                  </div>
                  <div style={{ fontSize: "11px", color: "var(--text-muted)", width: "180px", fontFamily: "monospace" }}>
                    {st.timestamp || "Undated"}
                  </div>
                  <div style={{ fontWeight: 600, fontSize: "11px" }}>
                    {st.source_node_id} &rarr; <span style={{ color: "var(--link-color, #4ea8de)" }}>{st.relationship_type}</span> &rarr; {st.target_node_id}
                  </div>
                  {st.delta_seconds_from_previous !== undefined && st.delta_seconds_from_previous !== null && (
                    <div style={{ fontSize: "10px", padding: "1px 6px", background: "var(--bg-surface)", border: "1px solid var(--border-strong)", borderRadius: "2px", color: "var(--text-muted)" }}>
                      +{st.delta_seconds_from_previous.toFixed(1)}s
                    </div>
                  )}
                  <div style={{ marginLeft: "auto", fontSize: "10px", color: "var(--text-muted)" }}>
                    Epistemic: <strong>{st.epistemic_status}</strong>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "center", height: "200px", color: "var(--text-muted)", fontSize: "11px" }}>
              {temporalLoading ? "Computing temporal order from forensic evidence..." : "No timestamped relationships recorded in this case."}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
