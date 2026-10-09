import React, { useState, useEffect } from "react";
import {
  CaseReviewSnapshot,
  ReviewBlocker,
  ReviewGateResult,
  BlockerResolutionState,
  BlockerSeverity,
  ForensicClosureReadinessState,
} from "../types/investigation";
import {
  fetchCaseReview,
  runCaseReview,
  acknowledgeCaseReviewBlocker,
  closeCaseWithReview,
  reopenCaseWithReview,
  generateCaseReviewAISummary,
  exportCaseReview,
} from "../lib/api";

interface InvestigationQualityReviewWorkbenchProps {
  caseId: number;
  caseStatus?: string;
  onCaseUpdated?: () => void;
}

export default function InvestigationQualityReviewWorkbench({
  caseId,
  caseStatus,
  onCaseUpdated,
}: InvestigationQualityReviewWorkbenchProps) {
  const [snapshot, setSnapshot] = useState<CaseReviewSnapshot | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"gates" | "blockers" | "coverage" | "history">("gates");

  // Filter state for blockers
  const [severityFilter, setSeverityFilter] = useState<string>("ALL");
  const [unresolvedOnly, setUnresolvedOnly] = useState<boolean>(false);

  // Blocker Acknowledgment Modal
  const [selectedBlocker, setSelectedBlocker] = useState<ReviewBlocker | null>(null);
  const [ackState, setAckState] = useState<BlockerResolutionState>("ACKNOWLEDGED");
  const [ackNotes, setAckNotes] = useState<string>("");
  const [ackLoading, setAckLoading] = useState<boolean>(false);

  // Close Case Modal
  const [showCloseModal, setShowCloseModal] = useState<boolean>(false);
  const [closureNotes, setClosureNotes] = useState<string>("");
  const [overrideWarnings, setOverrideWarnings] = useState<boolean>(false);
  const [closeLoading, setCloseLoading] = useState<boolean>(false);

  // Reopen Case Modal
  const [showReopenModal, setShowReopenModal] = useState<boolean>(false);
  const [reopenReason, setReopenReason] = useState<string>("");
  const [reopenLoading, setReopenLoading] = useState<boolean>(false);

  // AI Summary Modal
  const [showAIModal, setShowAIModal] = useState<boolean>(false);
  const [aiSummary, setAISummary] = useState<string | null>(null);
  const [aiLoading, setAILoading] = useState<boolean>(false);

  // Export State
  const [exportLoading, setExportLoading] = useState<boolean>(false);

  useEffect(() => {
    loadReview();
  }, [caseId]);

  const loadReview = async () => {
    setLoading(true);
    setError(null);
    try {
      const snap = await fetchCaseReview(caseId);
      setSnapshot(snap);
    } catch (err: any) {
      setError(err.message || "Failed to load case review");
    } finally {
      setLoading(false);
    }
  };

  const handleRunReview = async () => {
    setLoading(true);
    setError(null);
    try {
      const snap = await runCaseReview(caseId);
      setSnapshot(snap);
      if (onCaseUpdated) onCaseUpdated();
    } catch (err: any) {
      setError(err.message || "Failed to run review");
    } finally {
      setLoading(false);
    }
  };

  const handleAcknowledgeBlocker = async () => {
    if (!selectedBlocker || !ackNotes.trim()) return;
    setAckLoading(true);
    try {
      const updated = await acknowledgeCaseReviewBlocker(caseId, selectedBlocker.blocker_id, {
        resolution_state: ackState,
        notes: ackNotes,
      });
      setSnapshot(updated);
      setSelectedBlocker(null);
      setAckNotes("");
      if (onCaseUpdated) onCaseUpdated();
    } catch (err: any) {
      setError(err.message || "Failed to acknowledge blocker");
    } finally {
      setAckLoading(false);
    }
  };

  const handleCloseCase = async () => {
    if (!closureNotes.trim()) return;
    setCloseLoading(true);
    try {
      const updated = await closeCaseWithReview(caseId, {
        closure_notes: closureNotes,
        override_warnings: overrideWarnings,
      });
      setSnapshot(updated);
      setShowCloseModal(false);
      setClosureNotes("");
      if (onCaseUpdated) onCaseUpdated();
    } catch (err: any) {
      setError(err.message || "Failed to close case");
    } finally {
      setCloseLoading(false);
    }
  };

  const handleReopenCase = async () => {
    if (!reopenReason.trim()) return;
    setReopenLoading(true);
    try {
      const updated = await reopenCaseWithReview(caseId, {
        reopen_reason: reopenReason,
      });
      setSnapshot(updated);
      setShowReopenModal(false);
      setReopenReason("");
      if (onCaseUpdated) onCaseUpdated();
    } catch (err: any) {
      setError(err.message || "Failed to reopen case");
    } finally {
      setReopenLoading(false);
    }
  };

  const handleAISummary = async () => {
    setShowAIModal(true);
    setAILoading(true);
    try {
      const res = await generateCaseReviewAISummary(caseId);
      setAISummary(res.summary);
    } catch (err: any) {
      setAISummary("Failed to generate advisory AI review summary: " + err.message);
    } finally {
      setAILoading(false);
    }
  };

  const handleExport = async (format: "json" | "csv" | "markdown") => {
    setExportLoading(true);
    try {
      const content = await exportCaseReview(caseId, format);
      const blob = new Blob([content], {
        type: format === "json" ? "application/json" : format === "csv" ? "text/csv" : "text/markdown",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `logintel_case_${caseId}_review.${format === "markdown" ? "md" : format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setError("Failed to export review: " + err.message);
    } finally {
      setExportLoading(false);
    }
  };

  const getReadinessBadge = (state: ForensicClosureReadinessState) => {
    switch (state) {
      case "READY_FOR_CLOSURE":
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-100 text-emerald-800 border border-emerald-300">READY FOR CLOSURE</span>;
      case "READY_FOR_REVIEW":
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-blue-100 text-blue-800 border border-blue-300">READY FOR REVIEW</span>;
      case "REVIEW_REQUIRED":
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-100 text-amber-800 border border-amber-300">REVIEW REQUIRED</span>;
      case "NOT_READY":
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-100 text-rose-800 border border-rose-300">NOT READY (BLOCKERS)</span>;
      case "CLOSED":
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-neutral-200 text-neutral-800 border border-neutral-300">CLOSED</span>;
      case "REOPENED":
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-indigo-100 text-indigo-800 border border-indigo-300">REOPENED</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-neutral-100 text-neutral-600">{state}</span>;
    }
  };

  const getGateBadge = (status: string) => {
    switch (status) {
      case "PASS":
        return <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-emerald-100 text-emerald-800 border border-emerald-200">PASS</span>;
      case "NEEDS_REVIEW":
        return <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-amber-100 text-amber-800 border border-amber-200">NEEDS REVIEW</span>;
      case "BLOCKED":
        return <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-rose-100 text-rose-800 border border-rose-200">BLOCKED</span>;
      default:
        return <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-neutral-100 text-neutral-600 border border-neutral-200">{status}</span>;
    }
  };

  const getSeverityBadge = (sev: BlockerSeverity) => {
    switch (sev) {
      case "BLOCKER":
        return <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-rose-100 text-rose-800 border border-rose-300">BLOCKER</span>;
      case "WARNING":
        return <span className="px-1.5 py-0.5 text-[10px] font-semibold rounded bg-amber-100 text-amber-800 border border-amber-300">WARNING</span>;
      case "INFO":
        return <span className="px-1.5 py-0.5 text-[10px] font-medium rounded bg-neutral-100 text-neutral-700 border border-neutral-200">INFO</span>;
    }
  };

  const filteredBlockers = (snapshot?.blockers || []).filter((b) => {
    if (severityFilter !== "ALL" && b.severity !== severityFilter) return false;
    if (unresolvedOnly && b.resolution_state !== "UNRESOLVED") return false;
    return true;
  });

  return (
    <div className="flex flex-col h-full bg-[#fbfbfa] text-[#2c3036] font-sans text-xs">
      {/* Top Banner & Actions Header */}
      <div className="p-3 bg-white border-b border-[#e5e5e3] flex items-center justify-between shadow-sm">
        <div className="flex items-center space-x-3">
          <div>
            <span className="font-mono text-sm font-bold text-[#1a1d20]">
              CASE #{caseId} QUALITY & CLOSURE WORKBENCH
            </span>
            <div className="text-[11px] text-[#606770] flex items-center space-x-2 mt-0.5">
              <span>Status: <strong className="font-mono text-black">{snapshot?.case_status || caseStatus || "OPEN"}</strong></span>
              <span>•</span>
              <span>Version: <strong className="font-mono text-black">v{snapshot?.case_version || 1}</strong></span>
              <span>•</span>
              <span>Last Review: <span className="font-mono text-[10px]">{snapshot?.reviewed_at ? new Date(snapshot.reviewed_at).toLocaleTimeString() : "Never"}</span></span>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          {snapshot && getReadinessBadge(snapshot.closure_readiness)}

          <button
            onClick={handleRunReview}
            disabled={loading}
            className="px-2.5 py-1 text-xs font-medium bg-[#1e2329] hover:bg-[#2c333c] text-white rounded shadow-sm disabled:opacity-50"
          >
            {loading ? "Evaluating..." : "Run Forensic Review"}
          </button>

          <button
            onClick={handleAISummary}
            className="px-2.5 py-1 text-xs font-medium bg-white hover:bg-neutral-50 text-[#333942] border border-[#d2d5d8] rounded shadow-sm"
          >
            AI Advisory
          </button>

          {snapshot?.case_status === "CLOSED" ? (
            <button
              onClick={() => setShowReopenModal(true)}
              className="px-2.5 py-1 text-xs font-medium bg-indigo-50 hover:bg-indigo-100 text-indigo-700 border border-indigo-300 rounded shadow-sm"
            >
              Reopen Case
            </button>
          ) : (
            <button
              onClick={() => setShowCloseModal(true)}
              className="px-2.5 py-1 text-xs font-semibold bg-emerald-600 hover:bg-emerald-700 text-white rounded shadow-sm"
            >
              Close Investigation
            </button>
          )}

          <div className="relative inline-block text-left">
            <select
              onChange={(e) => {
                if (e.target.value) handleExport(e.target.value as any);
                e.target.value = "";
              }}
              defaultValue=""
              disabled={exportLoading}
              className="px-2 py-1 text-xs bg-white border border-[#d2d5d8] rounded shadow-sm text-[#333942] cursor-pointer"
            >
              <option value="" disabled>Export Review...</option>
              <option value="json">Export JSON</option>
              <option value="csv">Export CSV</option>
              <option value="markdown">Export Markdown</option>
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div className="p-2 bg-rose-50 border-b border-rose-200 text-rose-700 text-xs flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="font-bold text-rose-800">✕</button>
        </div>
      )}

      {/* Navigation Sub-Tabs */}
      <div className="px-3 pt-2 bg-white border-b border-[#e5e5e3] flex space-x-4">
        {[
          { id: "gates", label: `Review Gates (${snapshot?.gates.length || 12})` },
          { id: "blockers", label: `Closure Blockers (${snapshot?.blockers.length || 0})` },
          { id: "coverage", label: `Evidence Coverage` },
          { id: "history", label: `Audit & Review History` },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`pb-2 text-xs font-medium border-b-2 transition-colors ${
              activeTab === tab.id
                ? "border-[#1e2329] text-[#1e2329] font-bold"
                : "border-transparent text-[#606770] hover:text-[#1e2329]"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Main Tab Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {loading && !snapshot ? (
          <div className="p-8 text-center text-neutral-500">Evaluating forensic review gates...</div>
        ) : !snapshot ? (
          <div className="p-8 text-center text-neutral-500">No review snapshot available. Click "Run Forensic Review".</div>
        ) : activeTab === "gates" ? (
          /* 12-Gate Overview */
          <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {snapshot.gates.map((gate) => (
                <div key={gate.gate_type} className="bg-white border border-[#e5e5e3] rounded p-3 shadow-xs flex flex-col justify-between">
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="font-mono text-[11px] font-bold text-[#1e2329]">
                        {gate.title}
                      </span>
                      {getGateBadge(gate.status)}
                    </div>
                    <p className="text-[11px] text-[#4b525d] mb-2">{gate.summary}</p>
                    {gate.blockers.length > 0 && (
                      <div className="space-y-1 mb-2">
                        {gate.blockers.map((b) => (
                          <div key={b.blocker_id} className="text-[10px] p-1 bg-neutral-50 border border-neutral-200 rounded flex items-center justify-between">
                            <span className="truncate pr-1">{b.description}</span>
                            {getSeverityBadge(b.severity)}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                  {gate.recommendations.length > 0 && (
                    <div className="pt-2 border-t border-neutral-100 text-[10px] text-amber-800">
                      <strong>Recommendation:</strong> {gate.recommendations[0]}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Provenance Box */}
            <div className="p-2.5 bg-neutral-100 border border-neutral-300 rounded font-mono text-[10px] text-neutral-700 flex items-center justify-between">
              <div>
                <span>Blake2b Provenance Root Digest: <strong>{snapshot.provenance.root_digest}</strong></span>
              </div>
              <div>
                <span>Gates Digest: {snapshot.provenance.gates_digest.slice(0, 16)}...</span>
              </div>
            </div>
          </div>
        ) : activeTab === "blockers" ? (
          /* Blockers Management */
          <div className="space-y-3">
            <div className="flex items-center justify-between bg-white p-2.5 border border-[#e5e5e3] rounded">
              <div className="flex items-center space-x-3">
                <span className="text-[11px] font-semibold text-neutral-700">Filter Severity:</span>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="px-2 py-0.5 text-xs border border-neutral-300 rounded bg-white text-neutral-800"
                >
                  <option value="ALL">All Severities</option>
                  <option value="BLOCKER">BLOCKER Only</option>
                  <option value="WARNING">WARNING Only</option>
                  <option value="INFO">INFO Only</option>
                </select>

                <label className="flex items-center space-x-1.5 text-[11px] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={unresolvedOnly}
                    onChange={(e) => setUnresolvedOnly(e.target.checked)}
                    className="rounded border-neutral-300"
                  />
                  <span>Unresolved Only</span>
                </label>
              </div>
              <span className="text-[11px] text-neutral-500 font-mono">
                Showing {filteredBlockers.length} of {snapshot.blockers.length} items
              </span>
            </div>

            {filteredBlockers.length === 0 ? (
              <div className="p-8 text-center text-neutral-500 bg-white border border-[#e5e5e3] rounded">
                Zero blockers matching current filter criteria.
              </div>
            ) : (
              <div className="bg-white border border-[#e5e5e3] rounded overflow-hidden">
                <table className="w-full text-left text-[11px]">
                  <thead className="bg-neutral-50 border-b border-neutral-200 font-mono text-neutral-600">
                    <tr>
                      <th className="p-2">ID</th>
                      <th className="p-2">Gate</th>
                      <th className="p-2">Severity</th>
                      <th className="p-2">Description</th>
                      <th className="p-2">Status</th>
                      <th className="p-2">Reference</th>
                      <th className="p-2 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-neutral-100">
                    {filteredBlockers.map((b) => (
                      <tr key={b.blocker_id} className="hover:bg-neutral-50">
                        <td className="p-2 font-mono text-[10px] text-neutral-500">{b.blocker_id}</td>
                        <td className="p-2 font-mono text-[10px]">{b.gate_type}</td>
                        <td className="p-2">{getSeverityBadge(b.severity)}</td>
                        <td className="p-2 text-neutral-800 font-medium">
                          {b.description}
                          {b.resolution_notes && (
                            <div className="text-[10px] text-neutral-500 mt-0.5">
                              <em>Notes: {b.resolution_notes}</em> ({b.resolved_by})
                            </div>
                          )}
                        </td>
                        <td className="p-2">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                            b.resolution_state === "UNRESOLVED"
                              ? "bg-rose-50 text-rose-700 border border-rose-200"
                              : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                          }`}>
                            {b.resolution_state}
                          </span>
                        </td>
                        <td className="p-2 font-mono text-[10px] text-neutral-600">{b.source_reference || "-"}</td>
                        <td className="p-2 text-right">
                          <button
                            onClick={() => {
                              setSelectedBlocker(b);
                              setAckState(b.resolution_state === "UNRESOLVED" ? "ACKNOWLEDGED" : b.resolution_state);
                              setAckNotes(b.resolution_notes || "");
                            }}
                            className="px-2 py-0.5 text-[10px] font-medium bg-neutral-100 hover:bg-neutral-200 text-neutral-800 rounded border border-neutral-300"
                          >
                            Review / Waive
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        ) : activeTab === "coverage" ? (
          /* Evidence Coverage & Visibility Gaps */
          <div className="space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <div className="bg-white p-3 border border-[#e5e5e3] rounded shadow-xs">
                <span className="text-[10px] font-mono text-neutral-500 uppercase">Total Evidence References</span>
                <div className="text-xl font-bold font-mono text-neutral-800 mt-1">{snapshot.coverage.total_references}</div>
                <div className="text-[10px] text-emerald-700 mt-1">{snapshot.coverage.available_references} resolvable</div>
              </div>

              <div className="bg-white p-3 border border-[#e5e5e3] rounded shadow-xs">
                <span className="text-[10px] font-mono text-neutral-500 uppercase">Missing / Unresolved</span>
                <div className="text-xl font-bold font-mono text-rose-700 mt-1">
                  {snapshot.coverage.missing_references + snapshot.coverage.unresolved_references}
                </div>
                <div className="text-[10px] text-neutral-500 mt-1">require source re-indexing</div>
              </div>

              <div className="bg-white p-3 border border-[#e5e5e3] rounded shadow-xs">
                <span className="text-[10px] font-mono text-neutral-500 uppercase">Observed vs Inferred</span>
                <div className="text-xl font-bold font-mono text-neutral-800 mt-1">
                  {snapshot.coverage.observed_evidence_count} / {snapshot.coverage.inferred_evidence_count}
                </div>
                <div className="text-[10px] text-neutral-500 mt-1">epistemic classification</div>
              </div>

              <div className="bg-white p-3 border border-[#e5e5e3] rounded shadow-xs">
                <span className="text-[10px] font-mono text-neutral-500 uppercase">Telemetry Gaps</span>
                <div className="text-xl font-bold font-mono text-amber-700 mt-1">{snapshot.coverage.telemetry_gaps_count}</div>
                <div className="text-[10px] text-rose-700 mt-1">{snapshot.coverage.critical_gaps_count} critical</div>
              </div>
            </div>

            <div className="bg-white border border-[#e5e5e3] rounded p-4 text-[11px] space-y-2">
              <h4 className="font-bold text-neutral-800 text-xs">Forensic Telemetry Immutability & Epistemic Separation</h4>
              <p className="text-neutral-600">
                Authoritative event telemetry in <code>logintel.db</code> is read-only. Forensic reviews evaluate coverage against pinned evidence references and hypothesis gap assessments. Epistemic status (<code>OBSERVED</code> vs <code>INFERRED</code>) is strictly preserved and never mutated during case review or closure.
              </p>
            </div>
          </div>
        ) : (
          /* Audit History */
          <div className="bg-white border border-[#e5e5e3] rounded p-4 text-[11px] space-y-3">
            <h4 className="font-bold text-neutral-800 text-xs">Append-Only Case Review & Lifecycle Audit Trail</h4>
            <p className="text-neutral-500">All closure gate evaluations, blocker waivers, status transitions, and exports append to immutable SQLite storage.</p>
            <div className="border border-neutral-200 rounded p-2.5 bg-neutral-50 font-mono text-[10px] text-neutral-700">
              Audit log records are permanently anchored with actor identification and ISO 8601 timestamps.
            </div>
          </div>
        )}
      </div>

      {/* Blocker Acknowledgment Modal */}
      {selectedBlocker && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-neutral-300 rounded shadow-lg max-w-md w-full p-4 space-y-3">
            <div className="flex items-center justify-between border-b pb-2">
              <h3 className="font-bold text-xs text-neutral-900">Review Blocker: {selectedBlocker.blocker_id}</h3>
              <button onClick={() => setSelectedBlocker(null)} className="text-neutral-500 hover:text-black">✕</button>
            </div>

            <div className="text-xs text-neutral-700 bg-neutral-50 p-2.5 rounded border border-neutral-200">
              <p><strong>Description:</strong> {selectedBlocker.description}</p>
              <p className="mt-1"><strong>Gate:</strong> {selectedBlocker.gate_type} | <strong>Severity:</strong> {selectedBlocker.severity}</p>
            </div>

            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-neutral-700">Resolution Decision:</label>
              <select
                value={ackState}
                onChange={(e) => setAckState(e.target.value as any)}
                className="w-full text-xs p-1.5 border border-neutral-300 rounded bg-white"
              >
                <option value="ACKNOWLEDGED">ACKNOWLEDGED (Accepted by Analyst)</option>
                <option value="WAIVED">WAIVED (Explicit Risk Waiver)</option>
                <option value="RESOLVED">RESOLVED (Resolved in Telemetry)</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-neutral-700">Analyst Justification / Forensic Notes:</label>
              <textarea
                value={ackNotes}
                onChange={(e) => setAckNotes(e.target.value)}
                placeholder="Document forensic rationale for acknowledging or waiving this item..."
                rows={3}
                className="w-full text-xs p-2 border border-neutral-300 rounded font-sans"
              />
            </div>

            <div className="flex justify-end space-x-2 pt-2 border-t">
              <button
                onClick={() => setSelectedBlocker(null)}
                className="px-3 py-1 text-xs border border-neutral-300 rounded hover:bg-neutral-100"
              >
                Cancel
              </button>
              <button
                onClick={handleAcknowledgeBlocker}
                disabled={ackLoading || !ackNotes.trim()}
                className="px-3 py-1 text-xs font-semibold bg-[#1e2329] text-white rounded hover:bg-[#2c333c] disabled:opacity-50"
              >
                {ackLoading ? "Saving..." : "Record Decision"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Case Closure Modal */}
      {showCloseModal && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-neutral-300 rounded shadow-lg max-w-md w-full p-4 space-y-3">
            <div className="flex items-center justify-between border-b pb-2">
              <h3 className="font-bold text-xs text-neutral-900">Formally Close Investigation Case #{caseId}</h3>
              <button onClick={() => setShowCloseModal(false)} className="text-neutral-500 hover:text-black">✕</button>
            </div>

            <p className="text-xs text-neutral-600">
              Closing a case marks all investigative hypotheses, timelines, and findings as concluded. It requires documented analyst justification and verifies that all mandatory review gates pass.
            </p>

            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-neutral-700">Final Closure Notes:</label>
              <textarea
                value={closureNotes}
                onChange={(e) => setClosureNotes(e.target.value)}
                placeholder="Summarize investigation outcome and final forensic disposition..."
                rows={3}
                className="w-full text-xs p-2 border border-neutral-300 rounded font-sans"
              />
            </div>

            <label className="flex items-center space-x-2 text-[11px] cursor-pointer pt-1">
              <input
                type="checkbox"
                checked={overrideWarnings}
                onChange={(e) => setOverrideWarnings(e.target.checked)}
                className="rounded border-neutral-300"
              />
              <span className="text-neutral-700">Acknowledge non-critical advisory warnings during closure</span>
            </label>

            <div className="flex justify-end space-x-2 pt-2 border-t">
              <button
                onClick={() => setShowCloseModal(false)}
                className="px-3 py-1 text-xs border border-neutral-300 rounded hover:bg-neutral-100"
              >
                Cancel
              </button>
              <button
                onClick={handleCloseCase}
                disabled={closeLoading || !closureNotes.trim()}
                className="px-3 py-1 text-xs font-semibold bg-emerald-600 text-white rounded hover:bg-emerald-700 disabled:opacity-50"
              >
                {closeLoading ? "Closing Case..." : "Confirm Formal Closure"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Case Reopen Modal */}
      {showReopenModal && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-neutral-300 rounded shadow-lg max-w-md w-full p-4 space-y-3">
            <div className="flex items-center justify-between border-b pb-2">
              <h3 className="font-bold text-xs text-neutral-900">Reopen Investigation Case #{caseId}</h3>
              <button onClick={() => setShowReopenModal(false)} className="text-neutral-500 hover:text-black">✕</button>
            </div>

            <p className="text-xs text-neutral-600">
              Reopening a closed investigation restores its active status for supplemental telemetry collection or hypothesis refinement. Historical review records remain permanently preserved.
            </p>

            <div className="space-y-1">
              <label className="text-[11px] font-semibold text-neutral-700">Reopen Justification:</label>
              <textarea
                value={reopenReason}
                onChange={(e) => setReopenReason(e.target.value)}
                placeholder="State forensic grounds for reopening this investigation..."
                rows={3}
                className="w-full text-xs p-2 border border-neutral-300 rounded font-sans"
              />
            </div>

            <div className="flex justify-end space-x-2 pt-2 border-t">
              <button
                onClick={() => setShowReopenModal(false)}
                className="px-3 py-1 text-xs border border-neutral-300 rounded hover:bg-neutral-100"
              >
                Cancel
              </button>
              <button
                onClick={handleReopenCase}
                disabled={reopenLoading || !reopenReason.trim()}
                className="px-3 py-1 text-xs font-semibold bg-indigo-600 text-white rounded hover:bg-indigo-700 disabled:opacity-50"
              >
                {reopenLoading ? "Reopening..." : "Confirm Reopen"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Advisory AI Summary Modal */}
      {showAIModal && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-neutral-300 rounded shadow-lg max-w-lg w-full p-4 space-y-3">
            <div className="flex items-center justify-between border-b pb-2">
              <h3 className="font-bold text-xs text-neutral-900">Local AI Advisory Review Briefing</h3>
              <button onClick={() => setShowAIModal(false)} className="text-neutral-500 hover:text-black">✕</button>
            </div>

            <div className="p-1 bg-amber-50 border border-amber-200 rounded text-[10px] text-amber-800">
              <strong>Advisory Only:</strong> Generated via local boundary without autonomous closure authority.
            </div>

            <div className="max-h-60 overflow-y-auto p-2.5 bg-neutral-50 border border-neutral-200 rounded font-mono text-[11px] text-neutral-800 whitespace-pre-wrap">
              {aiLoading ? "Synthesizing advisory review briefing..." : aiSummary}
            </div>

            <div className="flex justify-end pt-2 border-t">
              <button
                onClick={() => setShowAIModal(false)}
                className="px-3 py-1 text-xs border border-neutral-300 rounded hover:bg-neutral-100"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
