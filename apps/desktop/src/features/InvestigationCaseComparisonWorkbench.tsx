import React, { useState, useEffect } from "react";
import type {
  CampaignCorrelationCandidate,
  CaseComparisonResult,
  ComparisonAISummaryResponse,
  CorrelationReviewStatus,
  CorroborationNature,
} from "../types/investigation";
import {
  createCaseComparison,
  fetchCaseComparison,
  reviewCorrelationCandidate,
  generateComparisonAISummary,
  exportCaseComparison,
} from "../lib/api";

interface InvestigationCaseComparisonWorkbenchProps {
  primaryCaseId: number;
  onNavigateToEvidence?: (sourceType: string, sourceId: string) => void;
  onClose?: () => void;
}

export const InvestigationCaseComparisonWorkbench: React.FC<InvestigationCaseComparisonWorkbenchProps> = ({
  primaryCaseId,
  onNavigateToEvidence,
  onClose,
}) => {
  const [targetCaseIdsInput, setTargetCaseIdsInput] = useState<string>("");
  const [selectedDimensions, setSelectedDimensions] = useState<string[]>([
    "ENTITIES",
    "TIMELINE",
    "FINDINGS",
    "HUNTS",
    "MITRE",
    "EVIDENCE_GAPS",
  ]);
  const [analystNotes, setAnalystNotes] = useState<string>("");
  const [activeComparison, setActiveComparison] = useState<CaseComparisonResult | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "entities" | "correlations" | "timeline" | "findings_hunts" | "gaps">("overview");
  const [aiSummary, setAiSummary] = useState<ComparisonAISummaryResponse | null>(null);
  const [aiLoading, setAiLoading] = useState<boolean>(false);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  const handleExecuteComparison = async () => {
    setError(null);
    const parsedIds = targetCaseIdsInput
      .split(/[,;\s]+/)
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => !isNaN(n) && n > 0 && n !== primaryCaseId);

    if (parsedIds.length === 0) {
      setError("Please provide at least one valid comparison case ID distinct from primary case.");
      return;
    }
    if (parsedIds.length > 4) {
      setError("Maximum 4 comparison cases allowed (5 cases total limit).");
      return;
    }

    setLoading(true);
    try {
      const res = await createCaseComparison(primaryCaseId, {
        compared_case_ids: parsedIds,
        dimensions: selectedDimensions,
        analyst_notes: analystNotes || undefined,
      });
      setActiveComparison(res);
      setAiSummary(null);
    } catch (err: any) {
      setError(err.message || "Failed to execute multi-case comparison");
    } finally {
      setLoading(false);
    }
  };

  const handleReviewCandidate = async (
    candidateId: string,
    newStatus: CorrelationReviewStatus,
    nature?: CorroborationNature
  ) => {
    if (!activeComparison) return;
    try {
      const updated = await reviewCorrelationCandidate(
        primaryCaseId,
        activeComparison.comparison_id,
        candidateId,
        {
          status: newStatus,
          corroboration_nature: nature,
          review_notes: `Analyst reviewed as ${newStatus}`,
        }
      );
      // Update local state
      setActiveComparison({
        ...activeComparison,
        correlation_candidates: activeComparison.correlation_candidates.map((c) =>
          c.candidate_id === candidateId ? updated : c
        ),
      });
    } catch (err: any) {
      setError(err.message || "Failed to update review status");
    }
  };

  const handleRequestAISummary = async () => {
    if (!activeComparison) return;
    setAiLoading(true);
    try {
      const res = await generateComparisonAISummary(primaryCaseId, activeComparison.comparison_id);
      setAiSummary(res);
    } catch (err: any) {
      setError(err.message || "Failed to generate AI advisory summary");
    } finally {
      setAiLoading(false);
    }
  };

  const handleExport = async (format: "json" | "csv" | "markdown") => {
    if (!activeComparison) return;
    try {
      const content = await exportCaseComparison(primaryCaseId, activeComparison.comparison_id, format);
      const blob = new Blob([content], {
        type: format === "json" ? "application/json" : format === "csv" ? "text/csv" : "text/markdown",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case_comparison_${activeComparison.comparison_id}.${format === "markdown" ? "md" : format}`;
      a.click();
      URL.revokeObjectURL(url);
      setExportNotice(`Exported as ${format.toUpperCase()}`);
      setTimeout(() => setExportNotice(null), 3000);
    } catch (err: any) {
      setError(err.message || "Export failed");
    }
  };

  const toggleDimension = (dim: string) => {
    if (selectedDimensions.includes(dim)) {
      if (selectedDimensions.length > 1) {
        setSelectedDimensions(selectedDimensions.filter((d) => d !== dim));
      }
    } else {
      setSelectedDimensions([...selectedDimensions, dim]);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#fcfbfa] text-[#1c1d1f] font-sans border border-[#e5e3df] rounded text-sm">
      {/* Top Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-[#f5f3ef] border-b border-[#e5e3df]">
        <div>
          <span className="font-semibold text-base text-[#1c1d1f]">
            Cross-Investigation Analysis & Campaign Correlation
          </span>
          <span className="ml-3 text-xs text-[#6e6b66] font-mono">
            Primary Case: #{primaryCaseId}
          </span>
        </div>
        {onClose && (
          <button
            onClick={onClose}
            className="text-xs px-2 py-1 bg-[#edeae4] hover:bg-[#e2ded6] border border-[#d6d2ca] rounded text-[#3b3a36]"
          >
            Close
          </button>
        )}
      </div>

      {/* Control / Configurator Bar */}
      <div className="p-3 bg-[#faf8f5] border-b border-[#e5e3df] flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-2">
          <label className="text-xs font-semibold text-[#5a5752]">Compared Case IDs:</label>
          <input
            type="text"
            placeholder="e.g. 2, 4"
            value={targetCaseIdsInput}
            onChange={(e) => setTargetCaseIdsInput(e.target.value)}
            className="px-2 py-1 text-xs bg-white border border-[#d6d2ca] rounded w-36 font-mono text-[#1c1d1f]"
          />
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-semibold text-[#5a5752]">Dimensions:</span>
          {["ENTITIES", "TIMELINE", "FINDINGS", "HUNTS", "MITRE", "EVIDENCE_GAPS"].map((dim) => (
            <label key={dim} className="flex items-center gap-1 text-xs text-[#4a4742] cursor-pointer">
              <input
                type="checkbox"
                checked={selectedDimensions.includes(dim)}
                onChange={() => toggleDimension(dim)}
                className="rounded border-[#d6d2ca] text-[#2c4e6f]"
              />
              {dim}
            </label>
          ))}
        </div>

        <div className="flex items-center gap-2 ml-auto">
          <button
            onClick={handleExecuteComparison}
            disabled={loading}
            className="px-3 py-1.5 bg-[#2c4e6f] hover:bg-[#233f5b] text-white font-medium text-xs rounded border border-[#1b344d] disabled:opacity-50"
          >
            {loading ? "Analyzing..." : "Compare Investigations"}
          </button>
        </div>
      </div>

      {error && (
        <div className="mx-4 my-2 p-2 bg-[#fdf2f2] border border-[#f5c6cb] text-[#721c24] text-xs rounded">
          {error}
        </div>
      )}

      {exportNotice && (
        <div className="mx-4 my-2 p-2 bg-[#edf7ed] border border-[#c3e6cb] text-[#155724] text-xs rounded">
          {exportNotice}
        </div>
      )}

      {/* Active Comparison View */}
      {activeComparison ? (
        <div className="flex flex-col flex-1 overflow-hidden">
          {/* Navigation Tabs */}
          <div className="flex border-b border-[#e5e3df] bg-[#f7f5f1] px-4 gap-4 text-xs font-medium">
            <button
              onClick={() => setActiveTab("overview")}
              className={`py-2 border-b-2 ${activeTab === "overview" ? "border-[#2c4e6f] text-[#2c4e6f]" : "border-transparent text-[#6e6b66]"}`}
            >
              Overview & Scope
            </button>
            <button
              onClick={() => setActiveTab("entities")}
              className={`py-2 border-b-2 ${activeTab === "entities" ? "border-[#2c4e6f] text-[#2c4e6f]" : "border-transparent text-[#6e6b66]"}`}
            >
              Shared Entities ({activeComparison.shared_entities.length})
            </button>
            <button
              onClick={() => setActiveTab("correlations")}
              className={`py-2 border-b-2 ${activeTab === "correlations" ? "border-[#2c4e6f] text-[#2c4e6f]" : "border-transparent text-[#6e6b66]"}`}
            >
              Campaign Correlations ({activeComparison.correlation_candidates.length})
            </button>
            <button
              onClick={() => setActiveTab("timeline")}
              className={`py-2 border-b-2 ${activeTab === "timeline" ? "border-[#2c4e6f] text-[#2c4e6f]" : "border-transparent text-[#6e6b66]"}`}
            >
              Comparative Timeline ({activeComparison.temporal_overlap.relationship})
            </button>
            <button
              onClick={() => setActiveTab("findings_hunts")}
              className={`py-2 border-b-2 ${activeTab === "findings_hunts" ? "border-[#2c4e6f] text-[#2c4e6f]" : "border-transparent text-[#6e6b66]"}`}
            >
              Findings & Hunts ({activeComparison.shared_findings.length + activeComparison.shared_hunts.length})
            </button>
            <button
              onClick={() => setActiveTab("gaps")}
              className={`py-2 border-b-2 ${activeTab === "gaps" ? "border-[#2c4e6f] text-[#2c4e6f]" : "border-transparent text-[#6e6b66]"}`}
            >
              Evidence Gaps ({activeComparison.evidence_gaps.length})
            </button>

            {/* Action Exports */}
            <div className="ml-auto flex items-center gap-1.5 py-1">
              <button
                onClick={() => handleExport("json")}
                className="px-2 py-0.5 text-xs bg-white border border-[#d6d2ca] hover:bg-[#edeae4] rounded text-[#4a4742]"
              >
                JSON
              </button>
              <button
                onClick={() => handleExport("csv")}
                className="px-2 py-0.5 text-xs bg-white border border-[#d6d2ca] hover:bg-[#edeae4] rounded text-[#4a4742]"
              >
                CSV
              </button>
              <button
                onClick={() => handleExport("markdown")}
                className="px-2 py-0.5 text-xs bg-white border border-[#d6d2ca] hover:bg-[#edeae4] rounded text-[#4a4742]"
              >
                Markdown
              </button>
            </div>
          </div>

          {/* Tab Content Area */}
          <div className="flex-1 overflow-y-auto p-4 bg-[#fcfbfa]">
            {activeTab === "overview" && (
              <div className="space-y-4 max-w-4xl">
                <div className="p-3 bg-white border border-[#e5e3df] rounded">
                  <h4 className="font-semibold text-xs text-[#5a5752] uppercase tracking-wide mb-2">
                    Comparison Metadata
                  </h4>
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div>
                      <span className="text-[#6e6b66]">Comparison ID:</span>{" "}
                      <span className="font-mono text-[#1c1d1f]">{activeComparison.comparison_id}</span>
                    </div>
                    <div>
                      <span className="text-[#6e6b66]">Created At:</span>{" "}
                      <span className="text-[#1c1d1f]">{activeComparison.created_at}</span>
                    </div>
                    <div>
                      <span className="text-[#6e6b66]">Evaluated Cases:</span>{" "}
                      <span className="font-mono text-[#1c1d1f]">
                        Case #{activeComparison.primary_case_id} vs Case(s) #{activeComparison.compared_case_ids.join(", #")}
                      </span>
                    </div>
                    <div>
                      <span className="text-[#6e6b66]">Provenance Digest (Blake2b):</span>{" "}
                      <span className="font-mono text-xs text-[#2c4e6f]">
                        {activeComparison.provenance_manifest.provenance_digest.substring(0, 24)}...
                      </span>
                    </div>
                  </div>
                </div>

                {/* AI Advisory Summary */}
                <div className="p-3 bg-[#fdfcfa] border border-[#e2ded6] rounded">
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-semibold text-xs text-[#5a5752] uppercase tracking-wide">
                      Local AI Advisory Synthesis (Ollama Local-First)
                    </span>
                    <button
                      onClick={handleRequestAISummary}
                      disabled={aiLoading}
                      className="px-2 py-1 text-xs bg-white border border-[#d6d2ca] hover:bg-[#f5f3ef] rounded text-[#2c4e6f] font-medium"
                    >
                      {aiLoading ? "Synthesizing..." : "Generate AI Advisory"}
                    </button>
                  </div>

                  {aiSummary ? (
                    <div className="text-xs text-[#333] space-y-2">
                      <div className="p-2 bg-[#f4f2ee] rounded border border-[#dedad2] italic">
                        {aiSummary.draft_narrative}
                      </div>
                      <div className="text-[11px] text-[#7a7771]">
                        ⚠️ {aiSummary.content_origin} — ADVISORY ONLY. Correlation does NOT equal definitive threat actor attribution.
                      </div>
                    </div>
                  ) : (
                    <div className="text-xs text-[#7a7771] italic">
                      Click generate to obtain local advisory synthesis of shared evidence and suggested pivoting paths.
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab === "entities" && (
              <div className="space-y-3">
                <div className="overflow-x-auto border border-[#e5e3df] rounded bg-white">
                  <table className="w-full text-left text-xs border-collapse">
                    <thead className="bg-[#f5f3ef] border-b border-[#e5e3df] text-[#5a5752] font-semibold">
                      <tr>
                        <th className="p-2 border-r border-[#e5e3df]">Type</th>
                        <th className="p-2 border-r border-[#e5e3df]">Entity Value</th>
                        <th className="p-2 border-r border-[#e5e3df]">Case Occurrences</th>
                        <th className="p-2 border-r border-[#e5e3df]">Epistemic State</th>
                        <th className="p-2">Nature</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeComparison.shared_entities.map((ent, idx) => (
                        <tr key={idx} className="border-b border-[#f0eee9] hover:bg-[#faf9f7]">
                          <td className="p-2 border-r border-[#f0eee9] font-mono text-[#5a5752]">
                            {ent.entity_type}
                          </td>
                          <td className="p-2 border-r border-[#f0eee9] font-mono font-medium text-[#1c1d1f]">
                            {ent.entity_value}
                          </td>
                          <td className="p-2 border-r border-[#f0eee9] text-[#4a4742]">
                            {Object.entries(ent.case_occurrences).map(([c, refs]) => (
                              <span key={c} className="mr-2 inline-block px-1.5 py-0.5 bg-[#f0eee9] rounded text-[11px]">
                                Case #{c} ({refs.length} refs)
                              </span>
                            ))}
                          </td>
                          <td className="p-2 border-r border-[#f0eee9]">
                            <span className="px-1.5 py-0.5 bg-[#eaf2e8] text-[#276722] rounded text-[10px] font-semibold">
                              {ent.epistemic_status}
                            </span>
                          </td>
                          <td className="p-2 text-[#5a5752] text-[11px]">
                            {ent.corroboration_nature}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === "correlations" && (
              <div className="space-y-3">
                {activeComparison.correlation_candidates.map((cand) => (
                  <div key={cand.candidate_id} className="p-3 bg-white border border-[#e5e3df] rounded space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-semibold text-[#1c1d1f]">
                          {cand.candidate_id}
                        </span>
                        <span className="px-2 py-0.5 bg-[#eaf0f6] text-[#2c4e6f] rounded text-[11px] font-semibold">
                          {cand.correlation_type}
                        </span>
                        <span className="px-2 py-0.5 bg-[#f5f3ef] text-[#5a5752] rounded text-[11px]">
                          Basis: {cand.correlation_basis}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-[#6e6b66]">Review Status:</span>
                        <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                          cand.analyst_review_status === "CORROBORATED"
                            ? "bg-[#eaf2e8] text-[#276722]"
                            : cand.analyst_review_status === "DISPUTED" || cand.analyst_review_status === "REJECTED"
                            ? "bg-[#fdf2f2] text-[#721c24]"
                            : "bg-[#f5f3ef] text-[#5a5752]"
                        }`}>
                          {cand.analyst_review_status}
                        </span>
                      </div>
                    </div>

                    <div className="text-xs text-[#4a4742]">
                      <span className="text-[#7a7771]">Participating Cases:</span> #{cand.case_ids.join(", #")}
                    </div>

                    {cand.shared_entities.length > 0 && (
                      <div className="text-xs font-mono text-[#333] bg-[#faf9f7] p-2 rounded border border-[#edeae4]">
                        {cand.shared_entities.map((e, idx) => (
                          <span key={idx} className="mr-3">
                            {e.type}: <strong>{e.value}</strong>
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Review Action Controls */}
                    <div className="flex items-center gap-2 pt-1 border-t border-[#f0eee9]">
                      <span className="text-[11px] text-[#7a7771]">Mark Review:</span>
                      <button
                        onClick={() => handleReviewCandidate(cand.candidate_id, "CORROBORATED" as CorrelationReviewStatus, "CORROBORATING" as CorroborationNature)}
                        className="px-2 py-0.5 text-[11px] bg-[#eaf2e8] hover:bg-[#d5ebd0] text-[#276722] rounded border border-[#b8dcaf]"
                      >
                        Corroborate
                      </button>
                      <button
                        onClick={() => handleReviewCandidate(cand.candidate_id, "WEAKENED" as CorrelationReviewStatus)}
                        className="px-2 py-0.5 text-[11px] bg-[#fff8e7] hover:bg-[#ffefc2] text-[#8a6d3b] rounded border border-[#faebcc]"
                      >
                        Weaken
                      </button>
                      <button
                        onClick={() => handleReviewCandidate(cand.candidate_id, "DISPUTED" as CorrelationReviewStatus, "CONTRADICTING" as CorroborationNature)}
                        className="px-2 py-0.5 text-[11px] bg-[#fdf2f2] hover:bg-[#fadbd8] text-[#721c24] rounded border border-[#f5c6cb]"
                      >
                        Dispute
                      </button>
                      <button
                        onClick={() => handleReviewCandidate(cand.candidate_id, "REJECTED" as CorrelationReviewStatus)}
                        className="px-2 py-0.5 text-[11px] bg-[#f5f3ef] hover:bg-[#e8e6e1] text-[#5a5752] rounded border border-[#d6d2ca]"
                      >
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "timeline" && (
              <div className="p-3 bg-white border border-[#e5e3df] rounded space-y-3">
                <h4 className="font-semibold text-xs text-[#5a5752] uppercase tracking-wide">
                  Temporal Alignment Analysis
                </h4>
                <div className="p-2.5 bg-[#f8f7f5] rounded border border-[#e5e3df] text-xs">
                  <div className="font-semibold text-[#1c1d1f] mb-1">
                    Relationship: <span className="font-mono text-[#2c4e6f]">{activeComparison.temporal_overlap.relationship}</span>
                  </div>
                  {activeComparison.temporal_overlap.overlap_start && (
                    <div className="text-[#5a5752]">
                      Overlap Window: {activeComparison.temporal_overlap.overlap_start} to {activeComparison.temporal_overlap.overlap_end} (Delta: {activeComparison.temporal_overlap.delta_seconds}s)
                    </div>
                  )}
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-semibold text-[#5a5752]">Case Time Windows:</span>
                  {activeComparison.temporal_overlap.case_windows.map((cw) => (
                    <div key={cw.case_id} className="p-2 border border-[#edeae4] rounded text-xs flex justify-between">
                      <span className="font-semibold">Case #{cw.case_id}</span>
                      <span className="font-mono text-[#4a4742]">
                        {cw.start_time || "N/A"} → {cw.end_time || "N/A"} ({cw.event_count} items)
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {activeTab === "findings_hunts" && (
              <div className="space-y-4">
                {/* Findings Overlap */}
                <div className="p-3 bg-white border border-[#e5e3df] rounded space-y-2">
                  <h4 className="font-semibold text-xs text-[#5a5752] uppercase tracking-wide">
                    Finding Patterns ({activeComparison.shared_findings.length})
                  </h4>
                  {activeComparison.shared_findings.length === 0 ? (
                    <div className="text-xs text-[#7a7771] italic">No shared finding patterns detected.</div>
                  ) : (
                    activeComparison.shared_findings.map((f, idx) => (
                      <div key={idx} className="p-2 border border-[#edeae4] rounded text-xs flex justify-between items-center">
                        <div>
                          <span className="font-semibold text-[#1c1d1f]">{f.description}</span>
                          <span className="ml-2 text-[11px] text-[#7a7771]">Type: {f.pattern_type}</span>
                        </div>
                        <span className="text-[11px] text-[#5a5752]">Cases: #{f.cases_involved.join(", #")}</span>
                      </div>
                    ))
                  )}
                </div>

                {/* Threat Hunt Overlap */}
                <div className="p-3 bg-white border border-[#e5e3df] rounded space-y-2">
                  <h4 className="font-semibold text-xs text-[#5a5752] uppercase tracking-wide">
                    Threat Hunting Query Overlap ({activeComparison.shared_hunts.length})
                  </h4>
                  {activeComparison.shared_hunts.length === 0 ? (
                    <div className="text-xs text-[#7a7771] italic">No common threat hunting query templates executed.</div>
                  ) : (
                    activeComparison.shared_hunts.map((h, idx) => (
                      <div key={idx} className="p-2 border border-[#edeae4] rounded text-xs flex justify-between items-center">
                        <div>
                          <span className="font-mono font-semibold text-[#2c4e6f]">{h.query_template_id}</span>
                          <span className="ml-2 text-[#4a4742]">{h.intent}</span>
                        </div>
                        <span className="text-[11px] text-[#5a5752]">Cases: #{h.cases_involved.join(", #")}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {activeTab === "gaps" && (
              <div className="p-3 bg-white border border-[#e5e3df] rounded space-y-2">
                <h4 className="font-semibold text-xs text-[#5a5752] uppercase tracking-wide">
                  Negative Evidence & Missing Telemetry Gaps
                </h4>
                <div className="text-[11px] text-[#6e6b66] mb-2">
                  Preserves explicit distinction between absence of telemetry and evidence of absence.
                </div>
                {activeComparison.evidence_gaps.length === 0 ? (
                  <div className="text-xs text-[#7a7771] italic">No comparative evidence gaps recorded.</div>
                ) : (
                  activeComparison.evidence_gaps.map((g, idx) => (
                    <div key={idx} className="p-2 border border-[#edeae4] rounded text-xs space-y-1">
                      <div className="font-medium text-[#1c1d1f]">{g.description}</div>
                      <div className="flex gap-2 text-[11px]">
                        {Object.entries(g.case_status).map(([c, status]) => (
                          <span key={c} className="px-1.5 py-0.5 bg-[#f5f3ef] rounded font-mono">
                            Case #{c}: {status}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      ) : (
        <div className="flex-1 flex items-center justify-center text-xs text-[#7a7771] p-6 text-center">
          <div>
            <div className="font-medium text-[#5a5752] mb-1">No Active Multi-Case Comparison</div>
            <div>Enter target comparison case IDs above and click "Compare Investigations" to detect shared entities, timeline overlap, and campaign candidates.</div>
          </div>
        </div>
      )}
    </div>
  );
};
