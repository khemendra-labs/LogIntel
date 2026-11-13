import React, { useEffect, useState } from "react";
import {
  fetchFindingsWorkbench,
  createCaseFindingM74,
  updateCaseFindingM74,
  deleteCaseFindingM74,
  reviewCaseFindingM74,
  addFindingEvidenceM74,
  removeFindingEvidenceM74,
  createHypothesisM74,
  updateHypothesisM74,
  deleteHypothesisM74,
  addHypothesisGapM74,
  exportFindingsWorkbenchM74,
  compareHypothesesM74,
} from "../lib/api";
import {
  Finding,
  FindingReviewStatus,
  HypothesisAssessmentView,
  EvidenceGapM74,
  HypothesisComparisonResponse,
  EpistemicStatus,
} from "../types/investigation";

interface InvestigationFindingsWorkbenchProps {
  caseId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function InvestigationFindingsWorkbench({
  caseId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}: InvestigationFindingsWorkbenchProps) {
  const [activeTab, setActiveTab] = useState<"findings" | "hypotheses" | "compare">("findings");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Workbench State
  const [findings, setFindings] = useState<Finding[]>([]);
  const [hypotheses, setHypotheses] = useState<HypothesisAssessmentView[]>([]);
  const [evidenceGaps, setEvidenceGaps] = useState<EvidenceGapM74[]>([]);
  const [comparison, setComparison] = useState<HypothesisComparisonResponse | null>(null);

  // Selected State
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedHypothesis, setSelectedHypothesis] = useState<HypothesisAssessmentView | null>(null);

  // Finding Creation / Edit Modal
  const [showCreateFinding, setShowCreateFinding] = useState(false);
  const [newFindingTitle, setNewFindingTitle] = useState("");
  const [newFindingStatement, setNewFindingStatement] = useState("");
  const [newFindingEpistemic, setNewFindingEpistemic] = useState<EpistemicStatus>("INFERRED");
  const [newFindingSeverity, setNewFindingSeverity] = useState<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL">("MEDIUM");

  // Review Finding Modal
  const [showReviewModal, setShowReviewModal] = useState(false);
  const [reviewStatusChoice, setReviewStatusChoice] = useState<FindingReviewStatus>("ACCEPTED");
  const [reviewNotes, setReviewNotes] = useState("");

  // Add Evidence Modal
  const [showAddEvidence, setShowAddEvidence] = useState(false);
  const [evidenceSourceType, setEvidenceSourceType] = useState("event");
  const [evidenceSourceId, setEvidenceSourceId] = useState("");
  const [evidenceRole, setEvidenceRole] = useState<"SUPPORTING" | "CONTRADICTING">("SUPPORTING");
  const [evidenceNote, setEvidenceNote] = useState("");

  // Hypothesis Creation
  const [showCreateHyp, setShowCreateHyp] = useState(false);
  const [newHypStatement, setNewHypStatement] = useState("");

  // Add Gap Modal
  const [showAddGap, setShowAddGap] = useState(false);
  const [gapType, setGapType] = useState("NO_EVENT_OBSERVED");
  const [gapDesc, setGapDesc] = useState("");

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await fetchFindingsWorkbench(caseId);
      setFindings(data.findings);
      setHypotheses(data.hypotheses);
      setEvidenceGaps(data.evidence_gaps);
      if (data.findings.length > 0 && !selectedFinding) {
        setSelectedFinding(data.findings[0]);
      }
      if (data.hypotheses.length > 0 && !selectedHypothesis) {
        setSelectedHypothesis(data.hypotheses[0]);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load findings workbench");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [caseId]);

  const handleCreateFinding = async () => {
    if (!newFindingTitle.trim() || !newFindingStatement.trim()) return;
    try {
      const created = await createCaseFindingM74(caseId, {
        title: newFindingTitle,
        statement: newFindingStatement,
        epistemic_status: newFindingEpistemic,
        severity: newFindingSeverity,
      });
      setShowCreateFinding(false);
      setNewFindingTitle("");
      setNewFindingStatement("");
      await loadData();
      setSelectedFinding(created);
    } catch (err: any) {
      alert(`Error creating finding: ${err.message}`);
    }
  };

  const handleReviewFinding = async () => {
    if (!selectedFinding) return;
    try {
      const updated = await reviewCaseFindingM74(
        caseId,
        selectedFinding.finding_id,
        reviewStatusChoice,
        reviewNotes
      );
      setShowReviewModal(false);
      setReviewNotes("");
      setSelectedFinding(updated);
      await loadData();
    } catch (err: any) {
      alert(`Error reviewing finding: ${err.message}`);
    }
  };

  const handleAddEvidence = async () => {
    if (!selectedFinding || !evidenceSourceId.trim()) return;
    try {
      const updated = await addFindingEvidenceM74(caseId, selectedFinding.finding_id, {
        source_type: evidenceSourceType,
        source_id: evidenceSourceId,
        role: evidenceRole,
        analyst_note: evidenceNote || undefined,
      });
      setShowAddEvidence(false);
      setEvidenceSourceId("");
      setEvidenceNote("");
      setSelectedFinding(updated);
      await loadData();
    } catch (err: any) {
      alert(`Error adding evidence: ${err.message}`);
    }
  };

  const handleRemoveEvidence = async (sourceId: string) => {
    if (!selectedFinding) return;
    try {
      const updated = await removeFindingEvidenceM74(caseId, selectedFinding.finding_id, sourceId);
      setSelectedFinding(updated);
      await loadData();
    } catch (err: any) {
      alert(`Error removing evidence: ${err.message}`);
    }
  };

  const handleDeleteFinding = async (findingId: string) => {
    if (!confirm("Delete this analyst finding? (All underlying evidence will remain preserved)")) return;
    try {
      await deleteCaseFindingM74(caseId, findingId);
      setSelectedFinding(null);
      await loadData();
    } catch (err: any) {
      alert(`Error deleting finding: ${err.message}`);
    }
  };

  const handleCreateHypothesis = async () => {
    if (!newHypStatement.trim()) return;
    try {
      await createHypothesisM74(caseId, {
        statement: newHypStatement,
      });
      setShowCreateHyp(false);
      setNewHypStatement("");
      await loadData();
    } catch (err: any) {
      alert(`Error creating hypothesis: ${err.message}`);
    }
  };

  const handleAddGap = async () => {
    if (!selectedHypothesis || !gapDesc.trim()) return;
    try {
      await addHypothesisGapM74(caseId, selectedHypothesis.hypothesis_id, {
        gap_type: gapType,
        description: gapDesc,
      });
      setShowAddGap(false);
      setGapDesc("");
      await loadData();
    } catch (err: any) {
      alert(`Error adding evidence gap: ${err.message}`);
    }
  };

  const handleLoadComparison = async () => {
    try {
      const comp = await compareHypothesesM74(caseId);
      setComparison(comp);
      setActiveTab("compare");
    } catch (err: any) {
      alert(`Error loading comparison: ${err.message}`);
    }
  };

  const handleExport = async (format: "json" | "csv") => {
    try {
      const content = await exportFindingsWorkbenchM74(caseId, format);
      const blob = new Blob([content], { type: format === "csv" ? "text/csv" : "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case_${caseId}_findings_workbench.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert(`Export failed: ${err.message}`);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%", background: "var(--bg-app)", color: "var(--text-primary)", fontFamily: "var(--font-sans)" }}>
      {/* Top Header */}
      <div style={{ padding: "12px 16px", background: "var(--bg-surface)", borderBottom: "1px solid var(--border-subtle)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h3 style={{ margin: 0, fontSize: "15px", fontWeight: 700, color: "var(--text-primary)" }}>
            Findings & Hypothesis Workbench
          </h3>
          <span style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
            Case #{caseId} · Epistemic Truth Decoupled from Analyst Review · Zero Duplicate Evidence
          </span>
        </div>
        <div style={{ display: "flex", gap: "8px" }}>
          <button
            className="btn btn-secondary"
            style={{ fontSize: "11px", padding: "4px 10px" }}
            onClick={() => handleExport("json")}
          >
            Export JSON
          </button>
          <button
            className="btn btn-secondary"
            style={{ fontSize: "11px", padding: "4px 10px" }}
            onClick={() => handleExport("csv")}
          >
            Export CSV
          </button>
          <button
            className="btn btn-primary"
            style={{ fontSize: "11px", padding: "4px 10px" }}
            onClick={() => setShowCreateFinding(true)}
          >
            + Create Finding
          </button>
        </div>
      </div>

      {/* Sub-Tabs */}
      <div style={{ display: "flex", background: "var(--bg-subtle)", padding: "6px 16px", borderBottom: "1px solid var(--border-subtle)", gap: "8px" }}>
        <button
          className={activeTab === "findings" ? "btn btn-primary" : "btn btn-secondary"}
          style={{ fontSize: "11px", padding: "4px 12px" }}
          onClick={() => setActiveTab("findings")}
        >
          Analyst Findings ({findings.length})
        </button>
        <button
          className={activeTab === "hypotheses" ? "btn btn-primary" : "btn btn-secondary"}
          style={{ fontSize: "11px", padding: "4px 12px" }}
          onClick={() => setActiveTab("hypotheses")}
        >
          Hypotheses & Gaps ({hypotheses.length})
        </button>
        <button
          className={activeTab === "compare" ? "btn btn-primary" : "btn btn-secondary"}
          style={{ fontSize: "11px", padding: "4px 12px" }}
          onClick={handleLoadComparison}
        >
          Competing Hypotheses Matrix
        </button>
      </div>

      {loading && (
        <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontSize: "13px" }}>
          Loading findings & hypothesis workbench state...
        </div>
      )}

      {error && (
        <div style={{ padding: "20px", margin: "16px", background: "var(--badge-alert-bg)", border: "1px solid var(--badge-alert-border)", borderRadius: "4px", color: "var(--badge-alert-text)", fontSize: "12px" }}>
          {error}
        </div>
      )}

      {/* Content Area */}
      {!loading && !error && (
        <div style={{ flex: 1, display: "flex", overflow: "hidden" }}>
          {/* TAB 1: FINDINGS */}
          {activeTab === "findings" && (
            <>
              {/* Left Pane: Findings List */}
              <div style={{ width: "360px", borderRight: "1px solid var(--border-subtle)", background: "var(--bg-surface)", overflowY: "auto", display: "flex", flexDirection: "column" }}>
                <div style={{ padding: "10px 14px", borderBottom: "1px solid var(--border-subtle)", fontWeight: 600, fontSize: "12px", color: "var(--text-secondary)" }}>
                  Recorded Findings
                </div>
                {findings.length === 0 ? (
                  <div style={{ padding: "30px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                    No findings recorded yet. Click "+ Create Finding" to begin.
                  </div>
                ) : (
                  findings.map((f) => (
                    <div
                      key={f.finding_id}
                      onClick={() => setSelectedFinding(f)}
                      style={{
                        padding: "12px 14px",
                        borderBottom: "1px solid var(--border-subtle)",
                        cursor: "pointer",
                        background: selectedFinding?.finding_id === f.finding_id ? "var(--bg-selected)" : "transparent",
                        borderLeft: selectedFinding?.finding_id === f.finding_id ? "3px solid var(--accent-cyan)" : "3px solid transparent",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                        <span style={{ fontSize: "12px", fontWeight: 700, color: "var(--text-primary)" }}>{f.title}</span>
                        <span style={{ fontSize: "10px", padding: "1px 5px", borderRadius: "3px", background: f.severity === "CRITICAL" ? "var(--badge-critical-bg)" : "var(--badge-neutral-bg, rgba(255,255,255,0.05))", color: f.severity === "CRITICAL" ? "var(--badge-critical-text)" : "var(--text-secondary)" }}>
                          {f.severity}
                        </span>
                      </div>
                      <div style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "4px" }}>
                        <span style={{ fontSize: "10px", padding: "1px 6px", borderRadius: "3px", background: f.epistemic_status === "OBSERVED" ? "rgba(0, 210, 255, 0.12)" : "rgba(245, 158, 11, 0.12)", color: f.epistemic_status === "OBSERVED" ? "var(--accent-cyan)" : "var(--accent-amber)" }}>
                          {f.epistemic_status}
                        </span>
                        <span style={{ fontSize: "10px", padding: "1px 6px", borderRadius: "3px", background: f.review_status === "ACCEPTED" ? "rgba(16, 185, 129, 0.12)" : "rgba(255,255,255,0.05)", color: f.review_status === "ACCEPTED" ? "#10b981" : "var(--text-muted)" }}>
                          {f.review_status}
                        </span>
                        <span style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                          v{f.version}
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Right Pane: Selected Finding Detail */}
              <div style={{ flex: 1, padding: "20px", overflowY: "auto", background: "var(--bg-app)" }}>
                {selectedFinding ? (
                  <div style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "6px", padding: "20px" }}>
                    {/* Header */}
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "16px", borderBottom: "1px solid var(--border-subtle)", paddingBottom: "12px" }}>
                      <div>
                        <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "4px" }}>
                          <h2 style={{ margin: 0, fontSize: "16px", fontWeight: 700, color: "var(--text-primary)" }}>{selectedFinding.title}</h2>
                          <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>({selectedFinding.finding_id})</span>
                        </div>
                        <div style={{ display: "flex", gap: "8px", alignItems: "center", marginTop: "6px" }}>
                          <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "4px", background: "rgba(0, 210, 255, 0.12)", color: "var(--accent-cyan)", fontWeight: 600 }}>
                            Epistemic: {selectedFinding.epistemic_status}
                          </span>
                          <span style={{ fontSize: "11px", padding: "2px 8px", borderRadius: "4px", background: selectedFinding.review_status === "ACCEPTED" ? "rgba(16, 185, 129, 0.15)" : "rgba(255, 255, 255, 0.05)", color: selectedFinding.review_status === "ACCEPTED" ? "#10b981" : "var(--text-secondary)", fontWeight: 600 }}>
                            Review: {selectedFinding.review_status}
                          </span>
                          <span style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                            Version {selectedFinding.version} · Created by {selectedFinding.created_by}
                          </span>
                        </div>
                      </div>
                      <div style={{ display: "flex", gap: "8px" }}>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: "11px", padding: "4px 10px" }}
                          onClick={() => setShowReviewModal(true)}
                        >
                          Review Finding
                        </button>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: "11px", padding: "4px 10px" }}
                          onClick={() => setShowAddEvidence(true)}
                        >
                          + Attach Evidence
                        </button>
                        <button
                          className="btn btn-secondary"
                          style={{ fontSize: "11px", padding: "4px 10px", color: "var(--badge-alert-text)" }}
                          onClick={() => handleDeleteFinding(selectedFinding.finding_id)}
                        >
                          Delete Finding
                        </button>
                      </div>
                    </div>

                    {/* Statement */}
                    <div style={{ marginBottom: "20px" }}>
                      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>ANALYTICAL STATEMENT</div>
                      <p style={{ margin: 0, fontSize: "13px", lineHeight: 1.6, color: "var(--text-primary)", background: "var(--bg-subtle)", padding: "12px", borderRadius: "4px", border: "1px solid var(--border-subtle)" }}>
                        {selectedFinding.statement}
                      </p>
                    </div>

                    {/* Supporting Evidence */}
                    <div style={{ marginBottom: "20px" }}>
                      <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--badge-normal-text, #10b981)", marginBottom: "6px" }}>
                        SUPPORTING EVIDENCE ({selectedFinding.supporting_evidence.length})
                      </div>
                      {selectedFinding.supporting_evidence.length === 0 ? (
                        <div style={{ fontSize: "12px", color: "var(--text-muted)", fontStyle: "italic" }}>No supporting evidence attached.</div>
                      ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                          {selectedFinding.supporting_evidence.map((ev) => (
                            <div key={ev.reference_id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.25)", borderRadius: "4px" }}>
                              <div>
                                <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700, color: "#10b981", marginRight: "8px" }}>
                                  [{ev.source_type.toUpperCase()}:{ev.source_id}]
                                </span>
                                <span style={{ fontSize: "11px", color: "var(--text-primary)" }}>{ev.citation_tag}</span>
                                {ev.analyst_note && <span style={{ fontSize: "11px", color: "var(--text-secondary)", marginLeft: "10px" }}>— {ev.analyst_note}</span>}
                              </div>
                              <div style={{ display: "flex", gap: "6px" }}>
                                {onSelectEventId && ev.source_type === "event" && (
                                  <button className="btn btn-secondary" style={{ fontSize: "10px", padding: "2px 6px" }} onClick={() => onSelectEventId(ev.source_id)}>
                                    Jump Timeline
                                  </button>
                                )}
                                {onSelectEntityKey && (
                                  <button className="btn btn-secondary" style={{ fontSize: "10px", padding: "2px 6px" }} onClick={() => onSelectEntityKey(ev.source_id)}>
                                    Jump Graph
                                  </button>
                                )}
                                <button className="btn btn-secondary" style={{ fontSize: "10px", padding: "2px 6px", color: "#b91c1c" }} onClick={() => handleRemoveEvidence(ev.source_id)}>
                                  Detach
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Contradicting Evidence */}
                    <div style={{ marginBottom: "20px" }}>
                      <div style={{ fontSize: "11px", fontWeight: 600, color: "#991b1b", marginBottom: "6px" }}>
                        CONTRADICTING EVIDENCE ({selectedFinding.contradicting_evidence.length})
                      </div>
                      {selectedFinding.contradicting_evidence.length === 0 ? (
                        <div style={{ fontSize: "12px", color: "#94a3b8", fontStyle: "italic" }}>No contradicting evidence noted.</div>
                      ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                          {selectedFinding.contradicting_evidence.map((ev) => (
                            <div key={ev.reference_id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", background: "#fef2f2", border: "1px solid #fecaca", borderRadius: "4px" }}>
                              <div>
                                <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700, color: "#991b1b", marginRight: "8px" }}>
                                  [{ev.source_type.toUpperCase()}:{ev.source_id}]
                                </span>
                                <span style={{ fontSize: "11px", color: "#b91c1c" }}>{ev.citation_tag}</span>
                                {ev.analyst_note && <span style={{ fontSize: "11px", color: "#475569", marginLeft: "10px" }}>— {ev.analyst_note}</span>}
                              </div>
                              <div style={{ display: "flex", gap: "6px" }}>
                                {onSelectEventId && ev.source_type === "event" && (
                                  <button className="btn btn-secondary" style={{ fontSize: "10px", padding: "2px 6px" }} onClick={() => onSelectEventId(ev.source_id)}>
                                    Jump Timeline
                                  </button>
                                )}
                                <button className="btn btn-secondary" style={{ fontSize: "10px", padding: "2px 6px", color: "#b91c1c" }} onClick={() => handleRemoveEvidence(ev.source_id)}>
                                  Detach
                                </button>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Version History */}
                    {selectedFinding.version_history.length > 0 && (
                      <div>
                        <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "6px" }}>
                          VERSION HISTORY ({selectedFinding.version_history.length})
                        </div>
                        <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                          {selectedFinding.version_history.map((vh) => (
                            <div key={vh.version} style={{ padding: "8px 12px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", borderRadius: "4px", fontSize: "11px" }}>
                              <div style={{ display: "flex", justifyContent: "space-between", color: "var(--text-muted)", marginBottom: "4px" }}>
                                <span style={{ fontWeight: 700, color: "var(--text-primary)" }}>Version {vh.version}: {vh.title}</span>
                                <span>{vh.updated_at} by {vh.updated_by}</span>
                              </div>
                              <div style={{ color: "var(--text-secondary)" }}>{vh.statement}</div>
                              {vh.change_summary && <div style={{ color: "var(--text-muted)", fontStyle: "italic", marginTop: "2px" }}>Note: {vh.change_summary}</div>}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div style={{ padding: "40px", textAlign: "center", color: "#94a3b8" }}>
                    Select a finding to inspect statement and evidence references.
                  </div>
                )}
              </div>
            </>
          )}

          {/* TAB 2: HYPOTHESES */}
          {activeTab === "hypotheses" && (
            <div style={{ flex: 1, padding: "20px", overflowY: "auto" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
                <div>
                  <h4 style={{ margin: 0, fontSize: "14px", fontWeight: 700, color: "#0f172a" }}>Investigative Hypotheses & Evidence Gaps</h4>
                  <span style={{ fontSize: "11px", color: "#64748b" }}>Explicitly models supporting facts, contradicting facts, and missing telemetry</span>
                </div>
                <button className="btn btn-primary" style={{ fontSize: "11px", padding: "4px 10px" }} onClick={() => setShowCreateHyp(true)}>
                  + Formulate Hypothesis
                </button>
              </div>

              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(340px, 1fr))", gap: "16px" }}>
                {hypotheses.map((h) => (
                  <div key={h.hypothesis_id} style={{ background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "6px", padding: "16px", display: "flex", flexDirection: "column", justifyContent: "space-between" }}>
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                        <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700, color: "var(--text-primary)" }}>{h.hypothesis_id}</span>
                        <span style={{ fontSize: "10px", padding: "2px 6px", borderRadius: "3px", background: "rgba(255,255,255,0.06)", fontWeight: 600, color: "var(--text-secondary)" }}>
                          {h.status}
                        </span>
                      </div>
                      <p style={{ fontSize: "12px", lineHeight: 1.5, color: "var(--text-primary)", margin: "0 0 12px 0" }}>
                        {h.statement}
                      </p>

                      <div style={{ display: "flex", gap: "10px", padding: "8px 0", borderTop: "1px solid var(--border-subtle)", borderBottom: "1px solid var(--border-subtle)", marginBottom: "12px" }}>
                        <div style={{ fontSize: "11px" }}>
                          <span style={{ color: "#10b981", fontWeight: 700 }}>SUPPORTING:</span> {h.supporting_evidence.length}
                        </div>
                        <div style={{ fontSize: "11px" }}>
                          <span style={{ color: "var(--badge-alert-text)", fontWeight: 700 }}>CONTRADICTING:</span> {h.contradicting_evidence.length}
                        </div>
                        <div style={{ fontSize: "11px" }}>
                          <span style={{ color: "var(--accent-amber)", fontWeight: 700 }}>GAPS:</span> {h.evidence_gaps.length}
                        </div>
                      </div>

                      {h.evidence_gaps.length > 0 && (
                        <div style={{ marginBottom: "12px" }}>
                          <div style={{ fontSize: "10px", fontWeight: 700, color: "var(--accent-amber)", marginBottom: "4px" }}>MISSING TELEMETRY GAPS</div>
                          {h.evidence_gaps.map((g) => (
                            <div key={g.gap_id} style={{ fontSize: "11px", color: "var(--text-primary)", background: "rgba(245, 158, 11, 0.12)", border: "1px solid rgba(245, 158, 11, 0.3)", padding: "4px 8px", borderRadius: "3px", marginBottom: "4px" }}>
                              {g.description}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "6px" }}>
                      <button
                        className="btn btn-secondary"
                        style={{ fontSize: "10px", padding: "3px 8px" }}
                        onClick={() => {
                          setSelectedHypothesis(h);
                          setShowAddGap(true);
                        }}
                      >
                        + Record Gap
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 3: COMPARE HYPOTHESES MATRIX */}
          {activeTab === "compare" && (
            <div style={{ flex: 1, padding: "20px", overflowY: "auto" }}>
              <div style={{ marginBottom: "16px" }}>
                <h4 style={{ margin: 0, fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>Competing Hypotheses Categorical Comparison</h4>
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Zero fabricated confidence percentages. Evaluates hypotheses via descriptive evidence categories.</span>
              </div>

              {comparison && (
                <table style={{ width: "100%", borderCollapse: "collapse", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", fontSize: "12px" }}>
                  <thead>
                    <tr style={{ background: "var(--bg-surface-subtle)", textAlign: "left" }}>
                      <th style={{ padding: "8px 12px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>Hypothesis</th>
                      <th style={{ padding: "8px 12px", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-secondary)" }}>Status</th>
                      <th style={{ padding: "8px 12px", borderBottom: "1px solid var(--border-subtle)", color: "var(--badge-success-text)" }}>Supporting Count</th>
                      <th style={{ padding: "8px 12px", borderBottom: "1px solid var(--border-subtle)", color: "var(--badge-alert-text)" }}>Contradicting Count</th>
                      <th style={{ padding: "8px 12px", borderBottom: "1px solid var(--border-subtle)", color: "var(--badge-warn-text)" }}>Gaps Count</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparison.hypotheses.map((h) => (
                      <tr key={h.hypothesis_id} style={{ borderBottom: "1px solid var(--border-subtle)" }}>
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontWeight: 700, color: "var(--text-primary)" }}>{h.title}</div>
                          <div style={{ color: "var(--text-secondary)", fontSize: "11px", marginTop: "2px" }}>{h.statement}</div>
                        </td>
                        <td style={{ padding: "10px 12px", fontWeight: 600, color: "var(--accent-cyan)" }}>{h.status}</td>
                        <td style={{ padding: "10px 12px", fontWeight: 700, color: "var(--badge-success-text)" }}>{h.supporting_count}</td>
                        <td style={{ padding: "10px 12px", fontWeight: 700, color: "var(--badge-alert-text)" }}>{h.contradicting_count}</td>
                        <td style={{ padding: "10px 12px", fontWeight: 700, color: "var(--badge-warn-text)" }}>{h.gaps_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}
        </div>
      )}

      {/* MODAL: CREATE FINDING */}
      {showCreateFinding && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0, 0, 0, 0.7)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
          <div style={{ background: "var(--bg-surface)", borderRadius: "6px", width: "480px", padding: "20px", border: "1px solid var(--border-strong)", boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.8)" }}>
            <h4 style={{ margin: "0 0 12px 0", fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>Create Analyst Finding</h4>
            <div style={{ marginBottom: "10px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Title</label>
              <input
                type="text"
                className="input-field"
                style={{ width: "100%", padding: "6px 8px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={newFindingTitle}
                onChange={(e) => setNewFindingTitle(e.target.value)}
                placeholder="e.g. Unauthorized Sudo Execution by Non-Admin User"
              />
            </div>
            <div style={{ marginBottom: "10px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Analytical Statement</label>
              <textarea
                className="input-field"
                style={{ width: "100%", padding: "6px 8px", fontSize: "12px", marginTop: "4px", minHeight: "80px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={newFindingStatement}
                onChange={(e) => setNewFindingStatement(e.target.value)}
                placeholder="Explicit analytical inference detailing observed evidence and causal interpretation..."
              />
            </div>
            <div style={{ display: "flex", gap: "12px", marginBottom: "16px" }}>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Epistemic Status</label>
                <select
                  className="input-field"
                  style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                  value={newFindingEpistemic}
                  onChange={(e) => setNewFindingEpistemic(e.target.value as any)}
                >
                  <option value="INFERRED">INFERRED</option>
                  <option value="OBSERVED">OBSERVED</option>
                  <option value="UNKNOWN">UNKNOWN</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Severity</label>
                <select
                  className="input-field"
                  style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                  value={newFindingSeverity}
                  onChange={(e) => setNewFindingSeverity(e.target.value as any)}
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFORMATIONAL">INFORMATIONAL</option>
                </select>
              </div>
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
              <button className="btn btn-secondary" onClick={() => setShowCreateFinding(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleCreateFinding}>Create Finding</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: REVIEW FINDING */}
      {showReviewModal && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0, 0, 0, 0.7)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
          <div style={{ background: "var(--bg-surface)", borderRadius: "6px", width: "420px", padding: "20px", border: "1px solid var(--border-strong)", boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.8)" }}>
            <h4 style={{ margin: "0 0 12px 0", fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>Review Finding: {selectedFinding?.title}</h4>
            <div style={{ marginBottom: "12px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Review Decision</label>
              <select
                className="input-field"
                style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={reviewStatusChoice}
                onChange={(e) => setReviewStatusChoice(e.target.value as any)}
              >
                <option value="ACCEPTED">ACCEPTED</option>
                <option value="DISPUTED">DISPUTED</option>
                <option value="REJECTED">REJECTED</option>
                <option value="UNREVIEWED">UNREVIEWED</option>
              </select>
            </div>
            <div style={{ marginBottom: "16px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Reviewer Notes</label>
              <textarea
                className="input-field"
                style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", minHeight: "60px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={reviewNotes}
                onChange={(e) => setReviewNotes(e.target.value)}
                placeholder="Rationale for accepting or rejecting this finding..."
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
              <button className="btn btn-secondary" onClick={() => setShowReviewModal(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleReviewFinding}>Submit Review</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: ATTACH EVIDENCE */}
      {showAddEvidence && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0, 0, 0, 0.7)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
          <div style={{ background: "var(--bg-surface)", borderRadius: "6px", width: "420px", padding: "20px", border: "1px solid var(--border-strong)", boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.8)" }}>
            <h4 style={{ margin: "0 0 12px 0", fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>Attach Evidence to Finding</h4>
            <div style={{ display: "flex", gap: "10px", marginBottom: "10px" }}>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Source Type</label>
                <select
                  className="input-field"
                  style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                  value={evidenceSourceType}
                  onChange={(e) => setEvidenceSourceType(e.target.value)}
                >
                  <option value="event">Canonical Event</option>
                  <option value="alert">Operational Alert</option>
                  <option value="detection">Detection Rule</option>
                  <option value="timeline_item">Timeline Item</option>
                  <option value="host_telemetry">Host Telemetry</option>
                  <option value="graph_relationship">Graph Relationship</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Role</label>
                <select
                  className="input-field"
                  style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                  value={evidenceRole}
                  onChange={(e) => setEvidenceRole(e.target.value as any)}
                >
                  <option value="SUPPORTING">SUPPORTING</option>
                  <option value="CONTRADICTING">CONTRADICTING</option>
                </select>
              </div>
            </div>
            <div style={{ marginBottom: "10px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Source ID / Identifier</label>
              <input
                type="text"
                className="input-field"
                style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={evidenceSourceId}
                onChange={(e) => setEvidenceSourceId(e.target.value)}
                placeholder="e.g. 101 or alert-44"
              />
            </div>
            <div style={{ marginBottom: "16px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Analyst Annotation (Optional)</label>
              <input
                type="text"
                className="input-field"
                style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={evidenceNote}
                onChange={(e) => setEvidenceNote(e.target.value)}
                placeholder="e.g. Corroborates timestamp match at 14:02 UTC"
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
              <button className="btn btn-secondary" onClick={() => setShowAddEvidence(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleAddEvidence}>Attach</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: CREATE HYPOTHESIS */}
      {showCreateHyp && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0, 0, 0, 0.7)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
          <div style={{ background: "var(--bg-surface)", borderRadius: "6px", width: "420px", padding: "20px", border: "1px solid var(--border-strong)", boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.8)" }}>
            <h4 style={{ margin: "0 0 12px 0", fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>Formulate Hypothesis</h4>
            <div style={{ marginBottom: "16px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Hypothesis Statement</label>
              <textarea
                className="input-field"
                style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", minHeight: "80px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={newHypStatement}
                onChange={(e) => setNewHypStatement(e.target.value)}
                placeholder="e.g. The observed SSH login was authorized administrative activity performed under change ticket CHG-102."
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
              <button className="btn btn-secondary" onClick={() => setShowCreateHyp(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleCreateHypothesis}>Save Hypothesis</button>
            </div>
          </div>
        </div>
      )}

      {/* MODAL: ADD EVIDENCE GAP */}
      {showAddGap && (
        <div style={{ position: "fixed", inset: 0, background: "rgba(0, 0, 0, 0.7)", display: "flex", justifyContent: "center", alignItems: "center", zIndex: 1000 }}>
          <div style={{ background: "var(--bg-surface)", borderRadius: "6px", width: "420px", padding: "20px", border: "1px solid var(--border-strong)", boxShadow: "0 10px 25px -5px rgba(0, 0, 0, 0.8)" }}>
            <h4 style={{ margin: "0 0 12px 0", fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>Record Evidence Gap</h4>
            <div style={{ marginBottom: "10px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Gap Classification</label>
              <select
                className="input-field"
                style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={gapType}
                onChange={(e) => setGapType(e.target.value)}
              >
                <option value="NO_EVENT_OBSERVED">NO_EVENT_OBSERVED</option>
                <option value="AUDIT_RULE_NOT_CONFIGURED">AUDIT_RULE_NOT_CONFIGURED</option>
                <option value="SOURCE_UNAVAILABLE">SOURCE_UNAVAILABLE</option>
                <option value="TELEMETRY_DROPPED">TELEMETRY_DROPPED</option>
                <option value="UNKNOWN">UNKNOWN</option>
              </select>
            </div>
            <div style={{ marginBottom: "16px" }}>
              <label style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Gap Description</label>
              <input
                type="text"
                className="input-field"
                style={{ width: "100%", padding: "6px", fontSize: "12px", marginTop: "4px", background: "var(--bg-surface-subtle)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
                value={gapDesc}
                onChange={(e) => setGapDesc(e.target.value)}
                placeholder="e.g. Auditd syscall auditing not enabled on host-prod-02"
              />
            </div>
            <div style={{ display: "flex", justifyContent: "flex-end", gap: "8px" }}>
              <button className="btn btn-secondary" onClick={() => setShowAddGap(false)}>Cancel</button>
              <button className="btn btn-primary" onClick={handleAddGap}>Record Gap</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
