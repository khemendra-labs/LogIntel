import React, { useEffect, useState, useMemo } from "react";
import {
  EvidenceCluster,
  BehavioralSequence,
  HypothesisSupportDetail,
  EvidenceGapDetail,
  EntityWorkbenchDossier,
  CorrelationExplanationResponse,
  GraphEvidenceItem,
  EpistemicStatus,
  CorroborationStatus,
} from "../types/investigation";
import {
  fetchEvidenceClusters,
  fetchEvidenceClusterDetail,
  fetchBehavioralSequences,
  fetchHypothesisCorrelationSupport,
  fetchCorrelationEvidenceGaps,
  generateFindingsFromClusters,
  fetchEntityWorkbenchDossier,
  explainCorrelationCluster,
  fetchInvestigationHypotheses,
} from "../lib/api";
import {
  RefreshIcon,
  SearchIcon,
  FilterIcon,
  CheckIcon,
  AlertIcon,
  TimelineIcon,
  ActivityIcon,
} from "../components/Icons";

interface InvestigationCorrelationExplorerProps {
  caseId: number;
  incidentId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function InvestigationCorrelationExplorer({
  caseId,
  incidentId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}: InvestigationCorrelationExplorerProps) {
  // Navigation mode
  const [activeView, setActiveView] = useState<
    "clusters" | "sequences" | "hypotheses" | "gaps" | "workbench"
  >("clusters");

  // General state
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  // Clusters state
  const [clusters, setClusters] = useState<EvidenceCluster[]>([]);
  const [clusterTypeFilter, setClusterTypeFilter] = useState<string>("ALL");
  const [selectedCluster, setSelectedCluster] = useState<EvidenceCluster | null>(null);
  const [clusterDetailLoading, setClusterDetailLoading] = useState<boolean>(false);
  const [selectedClusterDetail, setSelectedClusterDetail] = useState<{
    cluster: EvidenceCluster;
    related_findings: any[];
    related_entities: any[];
  } | null>(null);

  // Sequences state
  const [sequences, setSequences] = useState<BehavioralSequence[]>([]);
  const [selectedSequence, setSelectedSequence] = useState<BehavioralSequence | null>(null);

  // Hypothesis support state
  const [caseHypotheses, setCaseHypotheses] = useState<Array<{ hypothesis_id: string; statement: string; status: string }>>([]);
  const [selectedHypothesisId, setSelectedHypothesisId] = useState<string>("");
  const [hypothesisSupport, setHypothesisSupport] = useState<HypothesisSupportDetail | null>(null);
  const [hypothesisLoading, setHypothesisLoading] = useState<boolean>(false);

  // Gaps state
  const [gaps, setGaps] = useState<EvidenceGapDetail[]>([]);

  // Workbench state
  const [wbEntityType, setWbEntityType] = useState<string>("user");
  const [wbEntityVal, setWbEntityVal] = useState<string>("");
  const [workbenchDossier, setWorkbenchDossier] = useState<EntityWorkbenchDossier | null>(null);
  const [wbLoading, setWbLoading] = useState<boolean>(false);

  // AI Explanation state
  const [aiExplanation, setAiExplanation] = useState<CorrelationExplanationResponse | null>(null);
  const [aiExplaining, setAiExplaining] = useState<boolean>(false);
  const [aiQuestion, setAiQuestion] = useState<string>("");

  // Finding Generation state
  const [generatingFindings, setGeneratingFindings] = useState<boolean>(false);

  // Load initial data
  useEffect(() => {
    loadAllData();
  }, [caseId]);

  const loadAllData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [clustersRes, seqsRes, gapsRes, hypsRes] = await Promise.all([
        fetchEvidenceClusters(caseId, clusterTypeFilter !== "ALL" ? clusterTypeFilter : undefined),
        fetchBehavioralSequences(caseId),
        fetchCorrelationEvidenceGaps(caseId),
        fetchInvestigationHypotheses(incidentId).catch(() => ({ investigation_id: incidentId, items: [], total: 0 })),
      ]);
      setClusters(clustersRes.clusters || []);
      if (clustersRes.clusters && clustersRes.clusters.length > 0 && !selectedCluster) {
        setSelectedCluster(clustersRes.clusters[0]);
        loadClusterDetail(clustersRes.clusters[0].cluster_id);
      }
      setSequences(seqsRes.sequences || []);
      if (seqsRes.sequences && seqsRes.sequences.length > 0 && !selectedSequence) {
        setSelectedSequence(seqsRes.sequences[0]);
      }
      setGaps(gapsRes.gaps || []);
      const hypItems = hypsRes?.items || [];
      setCaseHypotheses(hypItems);
      if (hypItems.length > 0 && !selectedHypothesisId) {
        setSelectedHypothesisId(hypItems[0].hypothesis_id);
        loadHypothesisSupport(hypItems[0].hypothesis_id);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load correlation data");
    } finally {
      setLoading(false);
    }
  };

  const loadClusterDetail = async (clusterId: string) => {
    setClusterDetailLoading(true);
    try {
      const detail = await fetchEvidenceClusterDetail(caseId, clusterId);
      setSelectedClusterDetail(detail);
    } catch (err: any) {
      console.error("Failed to load cluster detail:", err);
    } finally {
      setClusterDetailLoading(false);
    }
  };

  const loadHypothesisSupport = async (hypId: string) => {
    if (!hypId) return;
    setHypothesisLoading(true);
    try {
      const detail = await fetchHypothesisCorrelationSupport(caseId, hypId);
      setHypothesisSupport(detail);
    } catch (err: any) {
      console.error("Failed to load hypothesis support:", err);
    } finally {
      setHypothesisLoading(false);
    }
  };

  const handleEntityWorkbenchSearch = async () => {
    if (!wbEntityVal.trim()) return;
    setWbLoading(true);
    setError(null);
    try {
      const dossier = await fetchEntityWorkbenchDossier(
        caseId,
        wbEntityType,
        wbEntityVal.trim()
      );
      setWorkbenchDossier(dossier);
    } catch (err: any) {
      setError(err.message || "Failed to retrieve entity workbench dossier");
    } finally {
      setWbLoading(false);
    }
  };

  const handleGenerateFindings = async () => {
    setGeneratingFindings(true);
    try {
      const res = await generateFindingsFromClusters(caseId);
      setSuccessNotice(`Successfully generated ${res.generated_count} structured finding(s) from evidence clusters.`);
      setTimeout(() => setSuccessNotice(null), 4000);
      loadAllData();
    } catch (err: any) {
      setError(err.message || "Failed to generate findings from clusters");
    } finally {
      setGeneratingFindings(false);
    }
  };

  const handleExplainWithAi = async () => {
    setAiExplaining(true);
    try {
      const res = await explainCorrelationCluster(caseId, {
        cluster_id: selectedCluster?.cluster_id || undefined,
        sequence_id: selectedSequence?.sequence_id || undefined,
        question: aiQuestion.trim() || undefined,
      });
      setAiExplanation(res);
    } catch (err: any) {
      setError(err.message || "Failed to generate advisory explanation");
    } finally {
      setAiExplaining(false);
    }
  };

  // Helper for Epistemic Badge styling
  const renderEpistemicBadge = (status: EpistemicStatus | string) => {
    let bg = "#f7fafc";
    let text = "#4a5568";
    let border = "#cbd5e0";
    if (status === "OBSERVED") {
      bg = "rgba(40, 167, 69, 0.12)";
      text = "#2e7d32";
      border = "rgba(40, 167, 69, 0.35)";
    } else if (status === "INFERRED") {
      bg = "rgba(255, 193, 7, 0.12)";
      text = "#b78103";
      border = "rgba(255, 193, 7, 0.4)";
    } else if (status === "UNKNOWN") {
      bg = "rgba(108, 117, 125, 0.12)";
      text = "#5a6268";
      border = "rgba(108, 117, 125, 0.3)";
    }
    return (
      <span
        style={{
          display: "inline-block",
          padding: "2px 6px",
          fontSize: "10px",
          fontWeight: 700,
          fontFamily: "var(--font-mono, monospace)",
          borderRadius: "3px",
          background: bg,
          color: text,
          border: `1px solid ${border}`,
        }}
      >
        {status}
      </span>
    );
  };

  // Helper for Corroboration Badge styling
  const renderCorroborationBadge = (status: CorroborationStatus | string) => {
    let bg = "#f7fafc";
    let text = "#4a5568";
    let border = "#cbd5e0";
    if (status === "CORROBORATED") {
      bg = "rgba(40, 167, 69, 0.12)";
      text = "#2e7d32";
      border = "rgba(40, 167, 69, 0.35)";
    } else if (status === "CONTRADICTED") {
      bg = "rgba(220, 53, 69, 0.12)";
      text = "#c53030";
      border = "rgba(220, 53, 69, 0.4)";
    } else if (status === "INSUFFICIENT_EVIDENCE") {
      bg = "rgba(237, 137, 54, 0.12)";
      text = "#c05621";
      border = "rgba(237, 137, 54, 0.35)";
    }
    return (
      <span
        style={{
          display: "inline-block",
          padding: "2px 6px",
          fontSize: "10px",
          fontWeight: 600,
          fontFamily: "var(--font-mono, monospace)",
          borderRadius: "3px",
          background: bg,
          color: text,
          border: `1px solid ${border}`,
        }}
      >
        {status}
      </span>
    );
  };

  const filteredClusters = useMemo(() => {
    if (clusterTypeFilter === "ALL") return clusters;
    return clusters.filter((c) => c.cluster_type.toUpperCase() === clusterTypeFilter.toUpperCase());
  }, [clusters, clusterTypeFilter]);

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: "12px",
        background: "var(--card-bg, #ffffff)",
        border: "1px solid var(--border-color, #e2e8f0)",
        borderRadius: "4px",
        padding: "16px",
        color: "var(--text-primary, #1a202c)",
      }}
    >
      {/* Top Header & View Switcher */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "8px",
          borderBottom: "1px solid var(--border-color, #e2e8f0)",
          paddingBottom: "10px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <div style={{ fontSize: "14px", fontWeight: 700, letterSpacing: "0.4px" }}>
            EVIDENCE CORRELATION & INVESTIGATION INTELLIGENCE (M5.9)
          </div>
          <span
            style={{
              fontSize: "10px",
              padding: "2px 6px",
              background: "#edf2f7",
              borderRadius: "3px",
              color: "#4a5568",
              fontFamily: "var(--font-mono, monospace)",
            }}
          >
            DETERMINISTIC
          </span>
        </div>

        {/* View Switch Buttons */}
        <div style={{ display: "flex", gap: "4px" }}>
          {[
            { id: "clusters", label: `Evidence Clusters (${clusters.length})` },
            { id: "sequences", label: `Behavioral Sequences (${sequences.length})` },
            { id: "hypotheses", label: "Hypothesis Support" },
            { id: "gaps", label: `Evidence Gaps (${gaps.length})` },
            { id: "workbench", label: "Entity Workbench" },
          ].map((v) => (
            <button
              key={v.id}
              className={activeView === v.id ? "btn btn-primary" : "btn btn-secondary"}
              style={{ fontSize: "11px", padding: "4px 10px" }}
              onClick={() => setActiveView(v.id as any)}
            >
              {v.label}
            </button>
          ))}
        </div>

        {/* Global Action Buttons */}
        <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
          <button
            className="btn btn-secondary"
            style={{ fontSize: "11px", padding: "4px 8px" }}
            onClick={loadAllData}
            disabled={loading}
          >
            <RefreshIcon /> {loading ? "Loading..." : "Refresh"}
          </button>
          <button
            className="btn btn-primary"
            style={{ fontSize: "11px", padding: "4px 10px" }}
            onClick={handleGenerateFindings}
            disabled={generatingFindings || clusters.length === 0}
            title="Derive formal case findings from deterministic evidence clusters"
          >
            {generatingFindings ? "Generating..." : "Generate Findings from Clusters"}
          </button>
        </div>
      </div>

      {/* Notices */}
      {successNotice && (
        <div
          style={{
            padding: "8px 12px",
            background: "#f0fff4",
            border: "1px solid #9ae6b4",
            color: "#22543d",
            borderRadius: "4px",
            fontSize: "11px",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <CheckIcon /> {successNotice}
        </div>
      )}
      {error && (
        <div
          style={{
            padding: "8px 12px",
            background: "#fff5f5",
            border: "1px solid #feb2b2",
            color: "#c53030",
            borderRadius: "4px",
            fontSize: "11px",
            display: "flex",
            alignItems: "center",
            gap: "6px",
          }}
        >
          <AlertIcon /> <strong>Error:</strong> {error}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 1. EVIDENCE CLUSTERS VIEW                                                 */}
      {/* ========================================================================= */}
      {activeView === "clusters" && (
        <div style={{ display: "flex", gap: "14px", minHeight: "480px" }}>
          {/* Cluster List & Filter Pane */}
          <div
            style={{
              width: "320px",
              display: "flex",
              flexDirection: "column",
              gap: "8px",
              borderRight: "1px solid var(--border-color, #e2e8f0)",
              paddingRight: "12px",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <FilterIcon />
              <span style={{ fontSize: "11px", fontWeight: 600 }}>Cluster Type:</span>
              <select
                value={clusterTypeFilter}
                onChange={(e) => setClusterTypeFilter(e.target.value)}
                style={{
                  padding: "3px 6px",
                  fontSize: "11px",
                  background: "var(--card-bg, #ffffff)",
                  border: "1px solid var(--border-color, #cbd5e0)",
                  borderRadius: "3px",
                  flex: 1,
                }}
              >
                <option value="ALL">All Types ({clusters.length})</option>
                <option value="ENTITY">ENTITY</option>
                <option value="TEMPORAL">TEMPORAL</option>
                <option value="INCIDENT">INCIDENT</option>
                <option value="DETECTION">DETECTION</option>
              </select>
            </div>

            <div
              style={{
                flex: 1,
                overflowY: "auto",
                display: "flex",
                flexDirection: "column",
                gap: "6px",
              }}
            >
              {filteredClusters.length === 0 ? (
                <div style={{ fontSize: "11px", color: "#718096", padding: "12px", textAlign: "center" }}>
                  No evidence clusters identified for this filter.
                </div>
              ) : (
                filteredClusters.map((c) => {
                  const isSelected = selectedCluster?.cluster_id === c.cluster_id;
                  return (
                    <div
                      key={c.cluster_id}
                      onClick={() => {
                        setSelectedCluster(c);
                        loadClusterDetail(c.cluster_id);
                      }}
                      style={{
                        padding: "8px 10px",
                        borderRadius: "4px",
                        border: isSelected ? "2px solid #3182ce" : "1px solid var(--border-color, #e2e8f0)",
                        background: isSelected ? "#ebf8ff" : "#f7fafc",
                        cursor: "pointer",
                        transition: "border-color 0.15s ease",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: "4px" }}>
                        <span style={{ fontSize: "11px", fontWeight: 700, color: "#2d3748" }}>{c.title}</span>
                        {renderEpistemicBadge(c.epistemic_status)}
                      </div>
                      <div style={{ fontSize: "10px", color: "#718096", marginTop: "4px" }}>
                        Type: <strong>{c.cluster_type}</strong> • Evidence: {c.evidence_references?.length ?? 0}
                      </div>
                      <div style={{ fontSize: "10px", color: "#718096", marginTop: "2px" }}>
                        Entities: {c.participating_entities.slice(0, 3).join(", ")}
                        {c.participating_entities.length > 3 && ` +${c.participating_entities.length - 3}`}
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Cluster Detail Pane */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "10px" }}>
            {selectedCluster ? (
              <>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "flex-start",
                    borderBottom: "1px solid var(--border-color, #e2e8f0)",
                    paddingBottom: "8px",
                  }}
                >
                  <div>
                    <div style={{ fontSize: "14px", fontWeight: 700, color: "#1a202c" }}>
                      {selectedCluster.title}
                    </div>
                    <div
                      style={{
                        fontSize: "11px",
                        color: "#718096",
                        fontFamily: "var(--font-mono, monospace)",
                        marginTop: "2px",
                      }}
                    >
                      Cluster ID: {selectedCluster.cluster_id}
                    </div>
                  </div>
                  <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                    {renderEpistemicBadge(selectedCluster.epistemic_status)}
                    {renderCorroborationBadge(selectedCluster.corroboration_status)}
                  </div>
                </div>

                <div style={{ fontSize: "12px", lineHeight: "1.5", color: "#2d3748" }}>
                  {selectedCluster.summary}
                </div>

                {/* Temporal Bounds */}
                <div
                  style={{
                    display: "flex",
                    gap: "12px",
                    padding: "6px 10px",
                    background: "#f7fafc",
                    border: "1px solid #edf2f7",
                    borderRadius: "4px",
                    fontSize: "11px",
                  }}
                >
                  <div>
                    <span style={{ color: "#718096" }}>Start:</span>{" "}
                    <strong>{selectedCluster.temporal_bounds.start_time || "N/A"}</strong>
                  </div>
                  <div>
                    <span style={{ color: "#718096" }}>End:</span>{" "}
                    <strong>{selectedCluster.temporal_bounds.end_time || "N/A"}</strong>
                  </div>
                  {selectedCluster.temporal_bounds.duration_seconds && (
                    <div>
                      <span style={{ color: "#718096" }}>Duration:</span>{" "}
                      <strong>{selectedCluster.temporal_bounds.duration_seconds}</strong>
                    </div>
                  )}
                </div>

                {/* Correlation Reasons */}
                <div>
                  <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", color: "#4a5568", marginBottom: "4px" }}>
                    Deterministic Correlation Reasons ({selectedCluster.correlation_reasons.length})
                  </div>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                    {selectedCluster.correlation_reasons.map((r, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: "6px 8px",
                          background: "#ffffff",
                          border: "1px solid #e2e8f0",
                          borderRadius: "3px",
                          fontSize: "11px",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <div>
                          <strong style={{ color: "#2b6cb0", fontFamily: "var(--font-mono, monospace)" }}>
                            {r.reason_type}
                          </strong>
                          {r.dimension_value && <span style={{ marginLeft: "8px", color: "#4a5568" }}>({r.dimension_value})</span>}
                          <div style={{ fontSize: "10px", color: "#718096", marginTop: "2px" }}>{r.description}</div>
                        </div>
                        <span
                          style={{
                            fontSize: "9px",
                            fontFamily: "var(--font-mono, monospace)",
                            color: "#718096",
                            padding: "2px 4px",
                            background: "#edf2f7",
                            borderRadius: "2px",
                          }}
                        >
                          {r.correlation_basis}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Participating Entities */}
                <div>
                  <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", color: "#4a5568", marginBottom: "4px" }}>
                    Participating Entities ({selectedCluster.participating_entities.length})
                  </div>
                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                    {selectedCluster.participating_entities.map((ent, idx) => (
                      <button
                        key={idx}
                        className="btn btn-secondary"
                        style={{ fontSize: "10px", padding: "2px 8px", fontFamily: "var(--font-mono, monospace)" }}
                        onClick={() => {
                          if (onSelectEntityKey) onSelectEntityKey(ent);
                          const parts = ent.split(":");
                          if (parts.length >= 2) {
                            setWbEntityType(parts[0]);
                            setWbEntityVal(parts.slice(1).join(":"));
                            setActiveView("workbench");
                          }
                        }}
                        title="Click to pivot into Entity Workbench"
                      >
                        {ent} ↗
                      </button>
                    ))}
                  </div>
                </div>

                {/* Evidence Citations */}
                <div>
                  <div style={{ fontSize: "11px", fontWeight: 700, textTransform: "uppercase", color: "#4a5568", marginBottom: "4px" }}>
                    Evidence Citations ({selectedCluster.evidence_references.length})
                  </div>
                  <div style={{ maxHeight: "150px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px" }}>
                    {selectedCluster.evidence_references.map((ev, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: "4px 8px",
                          background: "#f7fafc",
                          border: "1px solid #edf2f7",
                          borderRadius: "3px",
                          fontSize: "10px",
                          fontFamily: "var(--font-mono, monospace)",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <span>
                          [{ev.citation_tag || ev.reference_id}] {ev.source_type} #{ev.source_id}
                          {ev.summary && <span style={{ color: "#718096", marginLeft: "6px" }}>— {ev.summary}</span>}
                        </span>
                        {ev.source_type === "events" && onSelectEventId && (
                          <button
                            className="btn btn-secondary"
                            style={{ fontSize: "9px", padding: "1px 4px" }}
                            onClick={() => onSelectEventId(ev.source_id)}
                          >
                            View Event
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Advisory AI Explanation Bar */}
                <div
                  style={{
                    marginTop: "auto",
                    padding: "10px",
                    background: "#f7fafc",
                    border: "1px solid #e2e8f0",
                    borderRadius: "4px",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                    <span style={{ fontSize: "11px", fontWeight: 700, color: "#2d3748" }}>
                      Advisory Local AI Explanation
                    </span>
                    <span style={{ fontSize: "10px", color: "#718096", fontStyle: "italic" }}>
                      Non-authoritative
                    </span>
                  </div>
                  <div style={{ display: "flex", gap: "6px" }}>
                    <input
                      type="text"
                      className="input-field"
                      style={{ flex: 1, padding: "4px 8px", fontSize: "11px" }}
                      placeholder="Ask local AI to explain why these records are correlated..."
                      value={aiQuestion}
                      onChange={(e) => setAiQuestion(e.target.value)}
                    />
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: "11px", padding: "4px 10px" }}
                      onClick={handleExplainWithAi}
                      disabled={aiExplaining}
                    >
                      {aiExplaining ? "Explaining..." : "Explain Cluster"}
                    </button>
                  </div>
                  {aiExplanation && (
                    <div
                      style={{
                        marginTop: "8px",
                        padding: "8px",
                        background: "#ffffff",
                        border: "1px solid #cbd5e0",
                        borderRadius: "3px",
                        fontSize: "11px",
                      }}
                    >
                      <div style={{ fontWeight: 600, color: "#2b6cb0", marginBottom: "2px" }}>
                        {aiExplanation.summary}
                      </div>
                      <div style={{ color: "#4a5568", lineHeight: "1.4" }}>
                        {aiExplanation.reasoning_explanation}
                      </div>
                      {aiExplanation.identified_unknowns.length > 0 && (
                        <div style={{ marginTop: "4px", color: "#c53030", fontSize: "10px" }}>
                          <strong>Unknowns / Gaps:</strong> {aiExplanation.identified_unknowns.join("; ")}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div style={{ fontSize: "12px", color: "#718096", padding: "20px", textAlign: "center" }}>
                Select an evidence cluster from the left to inspect correlation reasons, entities, and citations.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 2. BEHAVIORAL SEQUENCES VIEW                                              */}
      {/* ========================================================================= */}
      {activeView === "sequences" && (
        <div style={{ display: "flex", gap: "14px", minHeight: "480px" }}>
          {/* Sequences List */}
          <div
            style={{
              width: "280px",
              display: "flex",
              flexDirection: "column",
              gap: "6px",
              borderRight: "1px solid var(--border-color, #e2e8f0)",
              paddingRight: "12px",
            }}
          >
            <div style={{ fontSize: "11px", fontWeight: 700, color: "#4a5568" }}>
              Identified Sequences ({sequences.length})
            </div>
            {sequences.length === 0 ? (
              <div style={{ fontSize: "11px", color: "#718096", padding: "12px" }}>
                No multi-stage behavioral sequences observed.
              </div>
            ) : (
              sequences.map((s) => (
                <div
                  key={s.sequence_id}
                  onClick={() => setSelectedSequence(s)}
                  style={{
                    padding: "8px 10px",
                    borderRadius: "4px",
                    border: selectedSequence?.sequence_id === s.sequence_id ? "2px solid #3182ce" : "1px solid #e2e8f0",
                    background: selectedSequence?.sequence_id === s.sequence_id ? "#ebf8ff" : "#f7fafc",
                    cursor: "pointer",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "11px", fontWeight: 700 }}>{s.pattern_name}</span>
                    {renderEpistemicBadge(s.epistemic_status)}
                  </div>
                  <div style={{ fontSize: "10px", color: "#718096", marginTop: "3px" }}>
                    {s.total_steps} step(s) • {s.supporting_evidence_count} evidence item(s)
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Sequence Detail / Timeline Steps */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", gap: "10px" }}>
            {selectedSequence ? (
              <>
                <div style={{ borderBottom: "1px solid #e2e8f0", paddingBottom: "8px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <div style={{ fontSize: "14px", fontWeight: 700 }}>{selectedSequence.pattern_name}</div>
                    {renderEpistemicBadge(selectedSequence.epistemic_status)}
                  </div>
                  <div style={{ fontSize: "11px", color: "#718096", marginTop: "2px" }}>
                    {selectedSequence.description}
                  </div>
                </div>

                {/* Steps Timeline */}
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  {selectedSequence.steps.map((st) => (
                    <div
                      key={st.step_index}
                      style={{
                        padding: "8px 12px",
                        background: "#ffffff",
                        border: "1px solid #e2e8f0",
                        borderRadius: "4px",
                        display: "flex",
                        alignItems: "flex-start",
                        gap: "12px",
                      }}
                    >
                      <div
                        style={{
                          width: "24px",
                          height: "24px",
                          borderRadius: "50%",
                          background: "#edf2f7",
                          display: "flex",
                          alignItems: "center",
                          justifyContent: "center",
                          fontSize: "11px",
                          fontWeight: 700,
                          color: "#4a5568",
                        }}
                      >
                        {st.step_index}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <span style={{ fontSize: "12px", fontWeight: 700, color: "#2d3748" }}>
                            {st.stage_name}
                          </span>
                          <span style={{ fontSize: "10px", color: "#718096", fontFamily: "var(--font-mono, monospace)" }}>
                            {st.timestamp}
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", color: "#4a5568", marginTop: "3px" }}>
                          {st.action_summary}
                        </div>
                        <div style={{ fontSize: "10px", color: "#718096", marginTop: "4px" }}>
                          Actor: <strong>{st.actor_entity}</strong> → Target: <strong>{st.target_entity}</strong> • Citation: [{st.evidence_citation}]
                        </div>
                      </div>
                      {renderEpistemicBadge(st.epistemic_status)}
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div style={{ fontSize: "12px", color: "#718096", padding: "20px", textAlign: "center" }}>
                Select a sequence to inspect multi-step progression.
              </div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* 3. HYPOTHESIS CORRELATION SUPPORT VIEW                                    */}
      {/* ========================================================================= */}
      {activeView === "hypotheses" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {/* Hypothesis Selector */}
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "11px", fontWeight: 700 }}>Select Hypothesis:</span>
            <select
              value={selectedHypothesisId}
              onChange={(e) => {
                setSelectedHypothesisId(e.target.value);
                loadHypothesisSupport(e.target.value);
              }}
              style={{
                flex: 1,
                padding: "4px 8px",
                fontSize: "11px",
                border: "1px solid #cbd5e0",
                borderRadius: "3px",
              }}
            >
              {caseHypotheses.length === 0 ? (
                <option value="">No hypotheses recorded for this incident</option>
              ) : (
                caseHypotheses.map((h) => (
                  <option key={h.hypothesis_id} value={h.hypothesis_id}>
                    [{h.status}] {h.statement}
                  </option>
                ))
              )}
            </select>
          </div>

          {hypothesisSupport && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginTop: "6px" }}>
              <div
                style={{
                  padding: "10px",
                  background: "#f7fafc",
                  border: "1px solid #e2e8f0",
                  borderRadius: "4px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div>
                  <div style={{ fontSize: "12px", fontWeight: 700 }}>{hypothesisSupport.statement}</div>
                  <div style={{ fontSize: "10px", color: "#718096", fontFamily: "var(--font-mono, monospace)" }}>
                    ID: {hypothesisSupport.hypothesis_id}
                  </div>
                </div>
                <div
                  style={{
                    fontSize: "11px",
                    fontWeight: 700,
                    padding: "3px 8px",
                    borderRadius: "3px",
                    background: hypothesisSupport.support_status.includes("SUPPORTED")
                      ? "rgba(40, 167, 69, 0.15)"
                      : hypothesisSupport.support_status.includes("CONTRADICTED")
                      ? "rgba(220, 53, 69, 0.15)"
                      : "rgba(255, 193, 7, 0.15)",
                    color: hypothesisSupport.support_status.includes("SUPPORTED")
                      ? "#2e7d32"
                      : hypothesisSupport.support_status.includes("CONTRADICTED")
                      ? "#c53030"
                      : "#b78103",
                    border: "1px solid currentColor",
                  }}
                >
                  {hypothesisSupport.support_status}
                </div>
              </div>

              {/* Supporting vs Contradicting Matrix */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "10px" }}>
                {/* Supporting Evidence */}
                <div
                  style={{
                    padding: "10px",
                    border: "1px solid #c6f6d5",
                    background: "#f0fff4",
                    borderRadius: "4px",
                  }}
                >
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#22543d", marginBottom: "6px" }}>
                    SUPPORTING EVIDENCE ({hypothesisSupport.supporting_evidence.length})
                  </div>
                  {hypothesisSupport.supporting_evidence.length === 0 ? (
                    <div style={{ fontSize: "10px", color: "#718096" }}>No direct supporting citations recorded.</div>
                  ) : (
                    hypothesisSupport.supporting_evidence.map((ev, idx) => (
                      <div
                        key={idx}
                        style={{
                          fontSize: "10px",
                          fontFamily: "var(--font-mono, monospace)",
                          padding: "3px 0",
                          borderBottom: "1px solid #e6fffa",
                        }}
                      >
                        [{ev.citation_tag || ev.reference_id}] {ev.source_type} #{ev.source_id}
                      </div>
                    ))
                  )}
                </div>

                {/* Contradicting Evidence */}
                <div
                  style={{
                    padding: "10px",
                    border: "1px solid #fed7d7",
                    background: "#fff5f5",
                    borderRadius: "4px",
                  }}
                >
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#742a2a", marginBottom: "6px" }}>
                    CONTRADICTING EVIDENCE ({hypothesisSupport.contradicting_evidence.length})
                  </div>
                  {hypothesisSupport.contradicting_evidence.length === 0 ? (
                    <div style={{ fontSize: "10px", color: "#718096" }}>No direct contradictions detected.</div>
                  ) : (
                    hypothesisSupport.contradicting_evidence.map((ev, idx) => (
                      <div
                        key={idx}
                        style={{
                          fontSize: "10px",
                          fontFamily: "var(--font-mono, monospace)",
                          padding: "3px 0",
                          borderBottom: "1px solid #fed7d7",
                        }}
                      >
                        [{ev.citation_tag || ev.reference_id}] {ev.source_type} #{ev.source_id}
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* Missing Evidence & Unresolved Questions */}
              {(hypothesisSupport.missing_evidence_descriptions.length > 0 ||
                hypothesisSupport.unresolved_questions.length > 0) && (
                <div style={{ padding: "10px", background: "#f7fafc", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                  <div style={{ fontSize: "11px", fontWeight: 700, color: "#4a5568", marginBottom: "4px" }}>
                    EVIDENCE GAPS & UNRESOLVED QUESTIONS
                  </div>
                  <ul style={{ margin: 0, paddingLeft: "18px", fontSize: "11px", color: "#4a5568" }}>
                    {hypothesisSupport.missing_evidence_descriptions.map((m, idx) => (
                      <li key={`m-${idx}`}>Missing: {m}</li>
                    ))}
                    {hypothesisSupport.unresolved_questions.map((q, idx) => (
                      <li key={`q-${idx}`}>Question: {q}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 4. EVIDENCE GAPS VIEW                                                     */}
      {/* ========================================================================= */}
      {activeView === "gaps" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
          <div style={{ fontSize: "11px", color: "#718096" }}>
            Deterministic gaps identified across telemetry coverage, unresolved entities, and missing corroboration:
          </div>
          {gaps.length === 0 ? (
            <div style={{ fontSize: "12px", color: "#718096", padding: "16px", textAlign: "center" }}>
              No critical evidence gaps detected.
            </div>
          ) : (
            gaps.map((g) => (
              <div
                key={g.gap_id}
                style={{
                  padding: "10px 12px",
                  background: "#ffffff",
                  border: "1px solid #e2e8f0",
                  borderRadius: "4px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "4px",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span style={{ fontSize: "12px", fontWeight: 700, color: "#2d3748" }}>{g.title}</span>
                  <span
                    style={{
                      fontSize: "10px",
                      fontFamily: "var(--font-mono, monospace)",
                      padding: "2px 6px",
                      background: "#edf2f7",
                      borderRadius: "3px",
                      color: "#4a5568",
                    }}
                  >
                    {g.gap_type}
                  </span>
                </div>
                <div style={{ fontSize: "11px", color: "#4a5568" }}>{g.description}</div>
                <div style={{ fontSize: "10px", color: "#718096", marginTop: "2px" }}>
                  <strong>Remedy:</strong> {g.resolution_remedy}
                </div>
                {g.affected_entities.length > 0 && (
                  <div style={{ fontSize: "10px", color: "#718096" }}>
                    Affected entities: {g.affected_entities.join(", ")}
                  </div>
                )}
                {g.recommended_governed_query && (
                  <div
                    style={{
                      marginTop: "4px",
                      padding: "4px 8px",
                      background: "#f7fafc",
                      border: "1px dashed #cbd5e0",
                      borderRadius: "3px",
                      fontSize: "10px",
                      fontFamily: "var(--font-mono, monospace)",
                      color: "#2b6cb0",
                    }}
                  >
                    Governed Hunt Query Intent: {g.recommended_governed_query.intent}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* 5. ENTITY WORKBENCH VIEW                                                  */}
      {/* ========================================================================= */}
      {activeView === "workbench" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
          {/* Entity Search Input */}
          <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
            <select
              value={wbEntityType}
              onChange={(e) => setWbEntityType(e.target.value)}
              style={{ padding: "4px 8px", fontSize: "11px", border: "1px solid #cbd5e0", borderRadius: "3px" }}
            >
              <option value="user">User</option>
              <option value="host">Host</option>
              <option value="ip">IP</option>
              <option value="process">Process</option>
              <option value="file">File</option>
              <option value="service">Service</option>
              <option value="container">Container</option>
            </select>
            <input
              type="text"
              className="input-field"
              placeholder="e.g. alice, 192.168.1.50, powershell.exe"
              value={wbEntityVal}
              onChange={(e) => setWbEntityVal(e.target.value)}
              style={{ flex: 1, padding: "4px 8px", fontSize: "11px" }}
              onKeyDown={(e) => {
                if (e.key === "Enter") handleEntityWorkbenchSearch();
              }}
            />
            <button
              className="btn btn-primary"
              style={{ fontSize: "11px", padding: "4px 10px" }}
              onClick={handleEntityWorkbenchSearch}
              disabled={wbLoading || !wbEntityVal.trim()}
            >
              <SearchIcon /> {wbLoading ? "Searching..." : "Pivot"}
            </button>
          </div>

          {workbenchDossier ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "10px", marginTop: "6px" }}>
              <div
                style={{
                  padding: "10px",
                  background: "#f7fafc",
                  border: "1px solid #e2e8f0",
                  borderRadius: "4px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                }}
              >
                <div>
                  <div style={{ fontSize: "14px", fontWeight: 700 }}>{workbenchDossier.display_name}</div>
                  <div style={{ fontSize: "10px", color: "#718096", fontFamily: "var(--font-mono, monospace)" }}>
                    {workbenchDossier.entity_key}
                  </div>
                </div>
                <div style={{ fontSize: "11px", color: "#4a5568" }}>
                  Clusters: {workbenchDossier.related_clusters.length} • Evidence: {workbenchDossier.evidence_references.length}
                </div>
              </div>

              {/* Related Clusters */}
              <div>
                <div style={{ fontSize: "11px", fontWeight: 700, color: "#4a5568", marginBottom: "4px" }}>
                  Related Evidence Clusters ({workbenchDossier.related_clusters.length})
                </div>
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  {workbenchDossier.related_clusters.map((c) => (
                    <div
                      key={c.cluster_id}
                      style={{
                        padding: "6px 8px",
                        background: "#ffffff",
                        border: "1px solid #e2e8f0",
                        borderRadius: "3px",
                        fontSize: "10px",
                      }}
                    >
                      <strong>{c.title}</strong> [{c.cluster_type}]
                    </div>
                  ))}
                </div>
              </div>

              {/* Adjacent Graph Neighbors */}
              <div>
                <div style={{ fontSize: "11px", fontWeight: 700, color: "#4a5568", marginBottom: "4px" }}>
                  Adjacent Graph Entities ({workbenchDossier.adjacent_graph_entities.length})
                </div>
                <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                  {workbenchDossier.adjacent_graph_entities.map((adj, idx) => (
                    <span
                      key={idx}
                      style={{
                        padding: "2px 6px",
                        background: "#edf2f7",
                        borderRadius: "3px",
                        fontSize: "10px",
                        fontFamily: "var(--font-mono, monospace)",
                      }}
                    >
                      {adj}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "#718096", padding: "20px", textAlign: "center" }}>
              Enter an entity type and value above to assemble an investigation workbench dossier.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
