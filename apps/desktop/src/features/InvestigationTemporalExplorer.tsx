import React, { useEffect, useState, useMemo } from "react";
import {
  TemporalReconstructionDossier,
  TemporalEpisode,
  TemporalTransition,
  TemporalGap,
  IncidentCampaignCorrelation,
  AttackSequenceReconstruction,
  MultiHostTrace,
  EntityContinuity,
  TemporalEvidenceChain,
  TemporalExplanationResponse,
  TransitionReviewState,
  EpistemicStatus,
  GraphEvidenceItem,
} from "../types/investigation";
import {
  fetchTemporalReconstruction,
  fetchTemporalEpisodes,
  fetchTemporalTransitions,
  fetchTemporalGaps,
  fetchTemporalSequences,
  fetchCampaignCorrelations,
  reviewTemporalTransition,
  explainTemporalReconstruction,
  exportTemporalReconstruction,
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

interface InvestigationTemporalExplorerProps {
  caseId: number;
  incidentId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function InvestigationTemporalExplorer({
  caseId,
  incidentId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}: InvestigationTemporalExplorerProps) {
  // Navigation mode
  const [activeTab, setActiveTab] = useState<
    "overview" | "episodes" | "transitions" | "multihost" | "campaigns" | "gaps"
  >("overview");

  // General state
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successNotice, setSuccessNotice] = useState<string | null>(null);

  // Dossier data
  const [dossier, setDossier] = useState<TemporalReconstructionDossier | null>(null);

  // Filters
  const [epistemicFilter, setEpistemicFilter] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [selectedTransition, setSelectedTransition] = useState<TemporalTransition | null>(null);
  const [selectedEpisode, setSelectedEpisode] = useState<TemporalEpisode | null>(null);

  // Review interaction
  const [reviewingTransitionId, setReviewingTransitionId] = useState<string | null>(null);
  const [reviewNotes, setReviewNotes] = useState<string>("");
  const [reviewLoading, setReviewLoading] = useState<boolean>(false);

  // AI Explanation state
  const [aiExplanation, setAiExplanation] = useState<TemporalExplanationResponse | null>(null);
  const [aiExplaining, setAiExplaining] = useState<boolean>(false);
  const [aiQuestion, setAiQuestion] = useState<string>("");

  // Export state
  const [exportFormat, setExportFormat] = useState<"json" | "csv" | "graphml">("json");
  const [exportLoading, setExportLoading] = useState<boolean>(false);

  useEffect(() => {
    loadDossier();
  }, [caseId]);

  async function loadDossier() {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchTemporalReconstruction(caseId);
      setDossier(data);
      if (data.transitions.length > 0) {
        setSelectedTransition(data.transitions[0]);
      }
      if (data.episodes.length > 0) {
        setSelectedEpisode(data.episodes[0]);
      }
    } catch (err: any) {
      console.error("Failed to load temporal reconstruction:", err);
      setError(err?.message || "Failed to load temporal reconstruction dossier.");
    } finally {
      setLoading(false);
    }
  }

  // Filtered transitions
  const filteredTransitions = useMemo(() => {
    if (!dossier) return [];
    return dossier.transitions.filter((t) => {
      if (epistemicFilter !== "ALL" && t.epistemic_status !== epistemicFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesEntity =
          t.from_entity.toLowerCase().includes(q) || t.to_entity.toLowerCase().includes(q);
        const matchesType = t.transition_type.toLowerCase().includes(q);
        const matchesReason = t.reason.toLowerCase().includes(q);
        if (!matchesEntity && !matchesType && !matchesReason) return false;
      }
      return true;
    });
  }, [dossier, epistemicFilter, searchQuery]);

  // Filtered episodes
  const filteredEpisodes = useMemo(() => {
    if (!dossier) return [];
    return dossier.episodes.filter((ep) => {
      if (epistemicFilter !== "ALL" && ep.epistemic_status !== epistemicFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesTitle = ep.title.toLowerCase().includes(q);
        const matchesEntities = ep.entities.some((e) => e.toLowerCase().includes(q));
        if (!matchesTitle && !matchesEntities) return false;
      }
      return true;
    });
  }, [dossier, epistemicFilter, searchQuery]);

  // Review handler
  async function handleReview(transitionId: string, state: TransitionReviewState) {
    setReviewLoading(true);
    setError(null);
    try {
      await reviewTemporalTransition(
        caseId,
        transitionId,
        state,
        "SecAnalyst-1",
        reviewNotes.trim() ? reviewNotes.trim() : undefined
      );
      setSuccessNotice(`Transition marked as ${state}. Epistemic status remains unchanged.`);
      setTimeout(() => setSuccessNotice(null), 4000);
      setReviewingTransitionId(null);
      setReviewNotes("");
      await loadDossier();
    } catch (err: any) {
      console.error("Failed to review transition:", err);
      setError(err?.message || "Failed to save transition review.");
    } finally {
      setReviewLoading(false);
    }
  }

  // AI Explanation handler
  async function handleExplain(targetId: string) {
    setAiExplaining(true);
    setAiExplanation(null);
    try {
      const resp = await explainTemporalReconstruction(
        caseId,
        targetId,
        aiQuestion.trim() ? aiQuestion.trim() : undefined
      );
      setAiExplanation(resp);
    } catch (err: any) {
      console.error("AI explanation failed:", err);
      setError(err?.message || "Failed to generate temporal explanation.");
    } finally {
      setAiExplaining(false);
    }
  }

  // Export handler
  async function handleExport() {
    setExportLoading(true);
    try {
      const res = await exportTemporalReconstruction(caseId, exportFormat);
      const blob = new Blob([res.content], {
        type:
          exportFormat === "json"
            ? "application/json"
            : exportFormat === "csv"
            ? "text/csv"
            : "application/xml",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `case_${caseId}_temporal_reconstruction.${exportFormat === "graphml" ? "graphml" : exportFormat}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      console.error("Export failed:", err);
      setError(err?.message || "Failed to export temporal reconstruction.");
    } finally {
      setExportLoading(false);
    }
  }

  // Render Epistemic Badge
  function renderEpistemicBadge(status: EpistemicStatus) {
    switch (status) {
      case "OBSERVED":
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-800/80 rounded">
            OBSERVED
          </span>
        );
      case "INFERRED":
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium bg-amber-950/60 text-amber-300 border border-amber-800/80 rounded">
            INFERRED
          </span>
        );
      case "UNKNOWN":
      default:
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium bg-zinc-800 text-zinc-300 border border-zinc-700 rounded">
            UNKNOWN
          </span>
        );
    }
  }

  // Render Review Badge
  function renderReviewBadge(state: TransitionReviewState) {
    switch (state) {
      case "ACCEPTED":
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium bg-blue-950/60 text-blue-300 border border-blue-800/80 rounded">
            ACCEPTED
          </span>
        );
      case "REJECTED":
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium bg-rose-950/60 text-rose-300 border border-rose-800/80 rounded">
            REJECTED
          </span>
        );
      case "DISPUTED":
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium bg-orange-950/60 text-orange-300 border border-orange-800/80 rounded">
            DISPUTED
          </span>
        );
      case "UNREVIEWED":
      default:
        return (
          <span className="inline-flex items-center px-1.5 py-0.5 text-xs font-mono font-medium bg-zinc-900 text-zinc-400 border border-zinc-800 rounded">
            UNREVIEWED
          </span>
        );
    }
  }

  return (
    <div className="flex flex-col h-full bg-[#121316] text-[#D8D9DA] font-sans">
      {/* Top Banner / Controls */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#17181C] border-b border-[#2A2B30]">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2">
            <TimelineIcon className="w-4 h-4 text-[#8B949E]" />
            <span className="text-sm font-semibold tracking-wide uppercase text-zinc-200">
              Temporal Reconstruction & Campaign Correlation
            </span>
          </div>
          {dossier && (
            <span className="text-xs font-mono px-2 py-0.5 bg-[#202227] text-zinc-400 border border-[#31343C] rounded">
              {dossier.episodes.length} Episodes | {dossier.transitions.length} Transitions | {dossier.gaps.length} Gaps
            </span>
          )}
        </div>

        <div className="flex items-center space-x-2">
          {/* Export Controls */}
          <div className="flex items-center bg-[#202227] border border-[#31343C] rounded px-1.5 py-0.5">
            <span className="text-xs text-zinc-400 mr-1.5">Export:</span>
            <select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as any)}
              className="bg-transparent text-xs text-zinc-200 focus:outline-none"
            >
              <option value="json" className="bg-[#1C1E23] text-zinc-200">JSON</option>
              <option value="csv" className="bg-[#1C1E23] text-zinc-200">CSV</option>
              <option value="graphml" className="bg-[#1C1E23] text-zinc-200">GraphML</option>
            </select>
            <button
              onClick={handleExport}
              disabled={exportLoading || !dossier}
              className="ml-2 text-xs text-zinc-300 hover:text-white font-mono px-1.5 py-0.5 bg-[#2A2B30] hover:bg-[#383A42] rounded disabled:opacity-50"
            >
              {exportLoading ? "..." : "Download"}
            </button>
          </div>

          <button
            onClick={loadDossier}
            disabled={loading}
            className="flex items-center space-x-1 px-2.5 py-1 text-xs font-medium text-zinc-300 hover:text-white bg-[#202227] hover:bg-[#282A30] border border-[#31343C] rounded transition-colors"
          >
            <RefreshIcon className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Reload</span>
          </button>
        </div>
      </div>

      {/* Subtab Navigation */}
      <div className="flex items-center justify-between px-4 bg-[#141519] border-b border-[#24262B]">
        <div className="flex space-x-1">
          {[
            { id: "overview", label: "Attack Reconstruction" },
            { id: "episodes", label: `Episodes (${dossier?.episodes.length || 0})` },
            { id: "transitions", label: `Transitions (${dossier?.transitions.length || 0})` },
            { id: "multihost", label: `Multi-Host & Continuity (${dossier?.multi_host_traces.length || 0})` },
            { id: "campaigns", label: `Campaign Correlation (${dossier?.campaign_correlations.length || 0})` },
            { id: "gaps", label: `Evidence Gaps (${dossier?.gaps.length || 0})` },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors ${
                activeTab === tab.id
                  ? "border-[#4C75A3] text-zinc-100 bg-[#1C1E24]"
                  : "border-transparent text-zinc-400 hover:text-zinc-200 hover:bg-[#18191E]"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Global Filters */}
        <div className="flex items-center space-x-2 py-1">
          <div className="flex items-center space-x-1 bg-[#1A1C21] border border-[#2B2D33] px-2 py-1 rounded text-xs">
            <FilterIcon className="w-3 h-3 text-zinc-500" />
            <span className="text-zinc-400">Epistemic:</span>
            <select
              value={epistemicFilter}
              onChange={(e) => setEpistemicFilter(e.target.value)}
              className="bg-transparent text-zinc-200 focus:outline-none"
            >
              <option value="ALL" className="bg-[#1C1E23] text-zinc-200">ALL</option>
              <option value="OBSERVED" className="bg-[#1C1E23] text-zinc-200">OBSERVED</option>
              <option value="INFERRED" className="bg-[#1C1E23] text-zinc-200">INFERRED</option>
              <option value="UNKNOWN" className="bg-[#1C1E23] text-zinc-200">UNKNOWN</option>
            </select>
          </div>

          <div className="relative">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search entity, type, reason..."
              className="bg-[#1A1C21] border border-[#2B2D33] text-xs text-zinc-200 placeholder-zinc-500 px-2 py-1 pl-6 rounded focus:outline-none focus:border-[#4C75A3]"
            />
            <SearchIcon className="w-3 h-3 text-zinc-500 absolute left-2 top-2" />
          </div>
        </div>
      </div>

      {/* Notices */}
      {error && (
        <div className="mx-4 mt-2 px-3 py-1.5 text-xs bg-rose-950/70 border border-rose-800 text-rose-200 rounded flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-rose-400 hover:text-white">✕</button>
        </div>
      )}
      {successNotice && (
        <div className="mx-4 mt-2 px-3 py-1.5 text-xs bg-blue-950/70 border border-blue-800 text-blue-200 rounded flex items-center justify-between">
          <span>{successNotice}</span>
          <button onClick={() => setSuccessNotice(null)} className="text-blue-400 hover:text-white">✕</button>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 overflow-hidden p-4">
        {loading && !dossier ? (
          <div className="flex items-center justify-center h-full text-xs text-zinc-400">
            Reconstructing temporal investigation layer...
          </div>
        ) : !dossier ? (
          <div className="flex items-center justify-center h-full text-xs text-zinc-500">
            No temporal reconstruction available.
          </div>
        ) : (
          <>
            {/* VIEW: OVERVIEW / ATTACK RECONSTRUCTION */}
            {activeTab === "overview" && (
              <div className="grid grid-cols-12 gap-4 h-full overflow-y-auto">
                {/* Left: Sequence List */}
                <div className="col-span-8 flex flex-col space-y-4">
                  <div className="bg-[#17181C] border border-[#26282E] rounded p-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                      Attack Sequence Reconstruction
                    </h3>
                    <p className="text-xs text-zinc-400 mb-3">
                      Deterministic behavioral progression derived from verified telemetry and MITRE ATT&amp;CK mappings.
                    </p>

                    {dossier.attack_sequences.length === 0 ? (
                      <div className="p-4 text-xs text-zinc-500 italic bg-[#131417] rounded border border-[#222429]">
                        No multi-stage attack sequence identified from current evidence.
                      </div>
                    ) : (
                      dossier.attack_sequences.map((seq) => (
                        <div key={seq.sequence_id} className="mb-4 bg-[#141518] border border-[#222429] rounded p-3">
                          <div className="flex items-center justify-between border-b border-[#222429] pb-2 mb-2">
                            <div>
                              <span className="text-sm font-medium text-zinc-200">{seq.name}</span>
                              <span className="text-xs text-zinc-400 ml-2">({seq.total_steps} steps)</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              {renderEpistemicBadge(seq.epistemic_status)}
                              <span className="text-xs font-mono text-zinc-400">
                                {new Date(seq.start_time).toLocaleTimeString()} - {new Date(seq.end_time).toLocaleTimeString()}
                              </span>
                            </div>
                          </div>

                          <div className="space-y-2 mt-2">
                            {seq.steps.map((st) => (
                              <div
                                key={st.step_number}
                                className="flex items-start justify-between p-2 bg-[#191B20] border border-[#292B32] rounded text-xs"
                              >
                                <div className="flex items-start space-x-2">
                                  <span className="font-mono text-xs px-1.5 py-0.5 bg-[#252830] text-zinc-300 rounded">
                                    #{st.step_number}
                                  </span>
                                  <div>
                                    <div className="font-medium text-zinc-200">
                                      {st.stage_name} — <span className="font-mono text-[#8BB9E0]">{st.entity}</span>
                                    </div>
                                    <div className="text-zinc-400 text-xs mt-0.5">{st.reason}</div>
                                    {st.mitre_technique_id && (
                                      <div className="mt-1 flex items-center space-x-1.5">
                                        <span className="font-mono text-[10px] px-1 py-0.2 bg-[#2B231D] text-amber-300 border border-amber-900 rounded">
                                          {st.mitre_technique_id}
                                        </span>
                                        <span className="text-[11px] text-zinc-400">{st.mitre_technique_name}</span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                                <div className="flex flex-col items-end space-y-1">
                                  {renderEpistemicBadge(st.epistemic_status)}
                                  <span className="font-mono text-[11px] text-zinc-400">{st.evidence_citation}</span>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Evidence Chains */}
                  <div className="bg-[#17181C] border border-[#26282E] rounded p-3">
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                      Evidence Chains
                    </h3>
                    <div className="space-y-2">
                      {dossier.evidence_chains.length === 0 ? (
                        <div className="text-xs text-zinc-500 italic">No evidence chains constructed.</div>
                      ) : (
                        dossier.evidence_chains.map((chain) => (
                          <div key={chain.chain_id} className="p-2.5 bg-[#141518] border border-[#222429] rounded">
                            <div className="flex items-center justify-between text-xs mb-1">
                              <span className="font-medium text-zinc-200">{chain.name}</span>
                              {renderEpistemicBadge(chain.epistemic_status)}
                            </div>
                            <div className="text-xs text-zinc-400 mb-2">{chain.description}</div>
                            <div className="flex flex-wrap gap-1">
                              {chain.steps.map((st, idx) => (
                                <span
                                  key={idx}
                                  className="text-[11px] font-mono px-1.5 py-0.5 bg-[#1B1D22] border border-[#2D2F36] text-zinc-300 rounded"
                                >
                                  {st.citation_tag} ({st.action_or_relation})
                                </span>
                              ))}
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>

                {/* Right: AI Advisory Panel & Provenance */}
                <div className="col-span-4 flex flex-col space-y-4">
                  {/* Advisory Panel */}
                  <div className="bg-[#17181C] border border-[#26282E] rounded p-3 flex flex-col">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                        Local AI Advisory Explanation
                      </h4>
                      <span className="text-[10px] font-mono px-1.5 py-0.2 bg-[#232018] text-amber-300 border border-amber-800 rounded">
                        NON-AUTHORITATIVE
                      </span>
                    </div>
                    <p className="text-xs text-zinc-400 mb-2">
                      Request structured natural language explanation of the timeline reconstruction.
                    </p>

                    <input
                      type="text"
                      value={aiQuestion}
                      onChange={(e) => setAiQuestion(e.target.value)}
                      placeholder="Ask timeline question (optional)..."
                      className="bg-[#131417] border border-[#282A31] text-xs text-zinc-200 px-2 py-1.5 rounded mb-2 focus:outline-none focus:border-[#4C75A3]"
                    />

                    <button
                      onClick={() => handleExplain(dossier.reconstruction_id)}
                      disabled={aiExplaining}
                      className="w-full py-1.5 text-xs font-medium text-zinc-200 bg-[#242730] hover:bg-[#30333E] border border-[#3A3D48] rounded transition-colors disabled:opacity-50"
                    >
                      {aiExplaining ? "Explaining timeline..." : "Explain Reconstruction"}
                    </button>

                    {aiExplanation && (
                      <div className="mt-3 p-2.5 bg-[#141518] border border-[#2A2B32] rounded text-xs space-y-2">
                        <div className="flex items-center justify-between text-[11px] text-zinc-400">
                          <span>Generator: {aiExplanation.generated_by}</span>
                          {renderEpistemicBadge(aiExplanation.epistemic_status)}
                        </div>
                        <div className="text-zinc-200 whitespace-pre-wrap leading-relaxed">
                          {aiExplanation.explanation_text}
                        </div>
                        {aiExplanation.referenced_citations.length > 0 && (
                          <div className="pt-2 border-t border-[#22242A]">
                            <div className="text-[11px] text-zinc-400 mb-1">Citations:</div>
                            <div className="flex flex-wrap gap-1">
                              {aiExplanation.referenced_citations.map((c, i) => (
                                <span key={i} className="text-[10px] font-mono px-1 bg-[#202227] text-zinc-300 rounded">
                                  {c}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Provenance Box */}
                  <div className="bg-[#17181C] border border-[#26282E] rounded p-3 text-xs space-y-2">
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                      Forensic Provenance
                    </h4>
                    <div className="flex justify-between text-zinc-400">
                      <span>Dossier ID:</span>
                      <span className="font-mono text-zinc-200">{dossier.reconstruction_id}</span>
                    </div>
                    <div className="flex justify-between text-zinc-400">
                      <span>Provenance Hash:</span>
                      <span className="font-mono text-[11px] text-zinc-300 truncate max-w-[160px]">
                        {dossier.provenance_hash}
                      </span>
                    </div>
                    <div className="flex justify-between text-zinc-400">
                      <span>Generated At:</span>
                      <span className="font-mono text-zinc-300">
                        {new Date(dossier.generated_at).toLocaleString()}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* VIEW: EPISODES */}
            {activeTab === "episodes" && (
              <div className="grid grid-cols-12 gap-4 h-full overflow-hidden">
                <div className="col-span-5 flex flex-col space-y-2 overflow-y-auto pr-1">
                  {filteredEpisodes.map((ep) => (
                    <div
                      key={ep.episode_id}
                      onClick={() => setSelectedEpisode(ep)}
                      className={`p-3 rounded border cursor-pointer transition-colors ${
                        selectedEpisode?.episode_id === ep.episode_id
                          ? "bg-[#1C1F26] border-[#4C75A3]"
                          : "bg-[#16171B] border-[#25272D] hover:bg-[#1A1C22]"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-xs font-mono font-medium text-[#8BB9E0]">
                          {ep.episode_type}
                        </span>
                        {renderEpistemicBadge(ep.epistemic_status)}
                      </div>
                      <div className="text-xs font-medium text-zinc-200">{ep.title}</div>
                      <div className="text-[11px] text-zinc-400 mt-1 line-clamp-2">{ep.summary}</div>
                      <div className="flex items-center justify-between mt-2 pt-2 border-t border-[#23252B] text-[10px] text-zinc-500 font-mono">
                        <span>Duration: {ep.duration_seconds}s</span>
                        <span>{ep.entities.length} Entities</span>
                      </div>
                    </div>
                  ))}
                  {filteredEpisodes.length === 0 && (
                    <div className="p-4 text-xs text-zinc-500 italic">No episodes match criteria.</div>
                  )}
                </div>

                {/* Episode Detail */}
                <div className="col-span-7 bg-[#17181C] border border-[#26282E] rounded p-4 overflow-y-auto">
                  {selectedEpisode ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between border-b border-[#24262C] pb-3">
                        <div>
                          <div className="text-xs font-mono text-[#8BB9E0] uppercase tracking-wide">
                            {selectedEpisode.episode_type}
                          </div>
                          <div className="text-sm font-semibold text-zinc-200">{selectedEpisode.title}</div>
                        </div>
                        {renderEpistemicBadge(selectedEpisode.epistemic_status)}
                      </div>

                      <div className="text-xs text-zinc-300 leading-relaxed bg-[#131417] p-3 rounded border border-[#222429]">
                        {selectedEpisode.summary}
                      </div>

                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                          Participating Entities ({selectedEpisode.entities.length})
                        </h4>
                        <div className="flex flex-wrap gap-1.5">
                          {selectedEpisode.entities.map((ent, idx) => (
                            <button
                              key={idx}
                              onClick={() => onSelectEntityKey && onSelectEntityKey(ent)}
                              className="text-xs font-mono px-2 py-0.5 bg-[#202227] hover:bg-[#2A2C33] border border-[#31343C] text-[#8BB9E0] rounded"
                            >
                              {ent}
                            </button>
                          ))}
                        </div>
                      </div>

                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                          Supporting Evidence Citations ({selectedEpisode.evidence_references.length})
                        </h4>
                        <div className="space-y-1.5">
                          {selectedEpisode.evidence_references.map((ev, idx) => (
                            <div
                              key={idx}
                              className="flex items-center justify-between p-2 bg-[#131417] border border-[#23252B] rounded text-xs"
                            >
                              <div className="flex items-center space-x-2">
                                <span className="font-mono text-zinc-300">{ev.citation_tag}</span>
                                <span className="text-zinc-400">[{ev.source_type}:{ev.source_id}]</span>
                              </div>
                              <span className="text-zinc-300">{ev.summary}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-xs text-zinc-500 italic">Select an episode to view details.</div>
                  )}
                </div>
              </div>
            )}

            {/* VIEW: TRANSITIONS */}
            {activeTab === "transitions" && (
              <div className="grid grid-cols-12 gap-4 h-full overflow-hidden">
                <div className="col-span-6 flex flex-col space-y-2 overflow-y-auto pr-1">
                  {filteredTransitions.map((tr) => (
                    <div
                      key={tr.transition_id}
                      onClick={() => setSelectedTransition(tr)}
                      className={`p-3 rounded border cursor-pointer transition-colors ${
                        selectedTransition?.transition_id === tr.transition_id
                          ? "bg-[#1C1F26] border-[#4C75A3]"
                          : "bg-[#16171B] border-[#25272D] hover:bg-[#1A1C22]"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-xs font-mono font-medium text-zinc-300">
                          {tr.transition_type}
                        </span>
                        <div className="flex items-center space-x-1.5">
                          {renderReviewBadge(tr.review_state)}
                          {renderEpistemicBadge(tr.epistemic_status)}
                        </div>
                      </div>

                      <div className="flex items-center space-x-2 text-xs font-mono text-zinc-200">
                        <span className="text-[#8BB9E0] font-semibold">{tr.from_entity}</span>
                        <span className="text-zinc-500">→</span>
                        <span className="text-emerald-300 font-semibold">{tr.to_entity}</span>
                      </div>

                      <div className="text-[11px] text-zinc-400 mt-1">{tr.reason}</div>
                      <div className="text-[10px] font-mono text-zinc-500 mt-2">
                        {new Date(tr.timestamp).toLocaleString()}
                      </div>
                    </div>
                  ))}
                  {filteredTransitions.length === 0 && (
                    <div className="p-4 text-xs text-zinc-500 italic">No transitions match filter.</div>
                  )}
                </div>

                {/* Transition Detail & Review Controls */}
                <div className="col-span-6 bg-[#17181C] border border-[#26282E] rounded p-4 overflow-y-auto">
                  {selectedTransition ? (
                    <div className="space-y-4">
                      <div className="flex items-center justify-between border-b border-[#24262C] pb-3">
                        <div>
                          <div className="text-xs font-mono text-zinc-400 uppercase tracking-wide">
                            Transition Inspection
                          </div>
                          <div className="text-sm font-semibold text-zinc-200">
                            {selectedTransition.transition_type}
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          {renderReviewBadge(selectedTransition.review_state)}
                          {renderEpistemicBadge(selectedTransition.epistemic_status)}
                        </div>
                      </div>

                      {/* Transition Path Box */}
                      <div className="p-3 bg-[#131417] border border-[#222429] rounded flex items-center justify-around font-mono text-xs">
                        <div className="text-center">
                          <div className="text-[10px] text-zinc-500">FROM</div>
                          <div className="text-[#8BB9E0] font-medium">{selectedTransition.from_entity}</div>
                        </div>
                        <div className="text-zinc-500 text-lg">→</div>
                        <div className="text-center">
                          <div className="text-[10px] text-zinc-500">TO</div>
                          <div className="text-emerald-300 font-medium">{selectedTransition.to_entity}</div>
                        </div>
                      </div>

                      {/* Transition Reason & Basis */}
                      <div className="space-y-2 text-xs">
                        <div>
                          <span className="text-zinc-400">Reason: </span>
                          <span className="text-zinc-200">{selectedTransition.reason}</span>
                        </div>
                        <div>
                          <span className="text-zinc-400">Correlation Basis: </span>
                          <span className="font-mono text-zinc-300">{selectedTransition.correlation_basis}</span>
                        </div>
                        <div>
                          <span className="text-zinc-400">Timestamp: </span>
                          <span className="font-mono text-zinc-300">
                            {new Date(selectedTransition.timestamp).toLocaleString()}
                          </span>
                        </div>
                      </div>

                      {/* Supporting Evidence */}
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                          Supporting Evidence ({selectedTransition.evidence_references.length})
                        </h4>
                        <div className="space-y-1.5">
                          {selectedTransition.evidence_references.map((ev, idx) => (
                            <div
                              key={idx}
                              className="p-2 bg-[#131417] border border-[#23252B] rounded text-xs space-y-1"
                            >
                              <div className="flex items-center justify-between">
                                <span className="font-mono text-zinc-200">{ev.citation_tag}</span>
                                <span className="text-[10px] text-zinc-400">[{ev.source_type}:{ev.source_id}]</span>
                              </div>
                              <div className="text-zinc-300">{ev.summary}</div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Analyst Review Section */}
                      <div className="pt-4 border-t border-[#24262C]">
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-300 mb-2">
                          Analyst Transition Review
                        </h4>
                        <p className="text-[11px] text-zinc-400 mb-2">
                          Reviewing does not alter epistemic status (e.g. INFERRED remains INFERRED).
                        </p>

                        <textarea
                          rows={2}
                          value={reviewNotes}
                          onChange={(e) => setReviewNotes(e.target.value)}
                          placeholder="Analyst review notes / justification..."
                          className="w-full bg-[#131417] border border-[#282A31] text-xs text-zinc-200 p-2 rounded mb-2 focus:outline-none focus:border-[#4C75A3]"
                        />

                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => handleReview(selectedTransition.transition_id, "ACCEPTED")}
                            disabled={reviewLoading}
                            className="px-3 py-1 text-xs font-medium text-blue-200 bg-blue-950/80 hover:bg-blue-900 border border-blue-800 rounded disabled:opacity-50"
                          >
                            Accept Transition
                          </button>
                          <button
                            onClick={() => handleReview(selectedTransition.transition_id, "DISPUTED")}
                            disabled={reviewLoading}
                            className="px-3 py-1 text-xs font-medium text-orange-200 bg-orange-950/80 hover:bg-orange-900 border border-orange-800 rounded disabled:opacity-50"
                          >
                            Dispute Transition
                          </button>
                          <button
                            onClick={() => handleReview(selectedTransition.transition_id, "REJECTED")}
                            disabled={reviewLoading}
                            className="px-3 py-1 text-xs font-medium text-rose-200 bg-rose-950/80 hover:bg-rose-900 border border-rose-800 rounded disabled:opacity-50"
                          >
                            Reject Transition
                          </button>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-xs text-zinc-500 italic">Select a transition to inspect.</div>
                  )}
                </div>
              </div>
            )}

            {/* VIEW: MULTI-HOST & CONTINUITY */}
            {activeTab === "multihost" && (
              <div className="grid grid-cols-12 gap-4 h-full overflow-y-auto">
                {/* Multi-Host Traces */}
                <div className="col-span-6 bg-[#17181C] border border-[#26282E] rounded p-4 flex flex-col space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                    Cross-Host Activity Traces ({dossier.multi_host_traces.length})
                  </h3>
                  <div className="space-y-3">
                    {dossier.multi_host_traces.length === 0 ? (
                      <div className="p-3 text-xs text-zinc-500 italic bg-[#131417] rounded border border-[#222429]">
                        No cross-host lateral activity identified in current scope.
                      </div>
                    ) : (
                      dossier.multi_host_traces.map((trace) => (
                        <div key={trace.trace_id} className="p-3 bg-[#141518] border border-[#222429] rounded text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-zinc-200 font-medium">
                              {trace.source_host} → {trace.target_host}
                            </span>
                            {renderEpistemicBadge(trace.epistemic_status)}
                          </div>
                          <div className="text-zinc-400">Actor: <span className="font-mono text-[#8BB9E0]">{trace.actor}</span></div>
                          <div className="text-[11px] text-zinc-500">
                            {new Date(trace.start_time).toLocaleString()} - {new Date(trace.end_time).toLocaleString()}
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>

                {/* Entity Continuities */}
                <div className="col-span-6 bg-[#17181C] border border-[#26282E] rounded p-4 flex flex-col space-y-3">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                    Entity Continuities ({dossier.continuities.length})
                  </h3>
                  <div className="space-y-3">
                    {dossier.continuities.length === 0 ? (
                      <div className="p-3 text-xs text-zinc-500 italic bg-[#131417] rounded border border-[#222429]">
                        No cross-host entity continuity observed.
                      </div>
                    ) : (
                      dossier.continuities.map((cont) => (
                        <div key={cont.continuity_id} className="p-3 bg-[#141518] border border-[#222429] rounded text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-[#8BB9E0] font-medium">{cont.entity_key}</span>
                            <span className="text-[10px] font-mono px-1.5 py-0.5 bg-[#202227] text-zinc-300 border border-[#2B2D33] rounded">
                              {cont.continuity_type}
                            </span>
                          </div>
                          <div className="text-zinc-400">{cont.description}</div>
                          {cont.participating_hosts.length > 0 && (
                            <div className="flex items-center space-x-1 pt-1">
                              <span className="text-[11px] text-zinc-500">Hosts:</span>
                              {cont.participating_hosts.map((h, i) => (
                                <span key={i} className="font-mono text-[10px] px-1 bg-[#1A1C21] text-zinc-300 rounded">
                                  {h}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* VIEW: CAMPAIGN CORRELATION */}
            {activeTab === "campaigns" && (
              <div className="bg-[#17181C] border border-[#26282E] rounded p-4 h-full overflow-y-auto space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                    Incident &amp; Campaign-Level Relationships ({dossier.campaign_correlations.length})
                  </h3>
                  <span className="text-[11px] text-zinc-400">
                    Deterministic correlation based on shared artifacts, entities, and temporal alignment.
                  </span>
                </div>

                <div className="space-y-3">
                  {dossier.campaign_correlations.length === 0 ? (
                    <div className="p-4 text-xs text-zinc-500 italic bg-[#131417] rounded border border-[#222429]">
                      No related incidents identified under campaign correlation criteria.
                    </div>
                  ) : (
                    dossier.campaign_correlations.map((rel) => (
                      <div
                        key={rel.correlation_id}
                        className="p-3 bg-[#141518] border border-[#222429] rounded text-xs space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <span className="font-mono text-zinc-300 font-medium">
                              Incident #{rel.primary_incident_id} ↔ Incident #{rel.related_incident_id}
                            </span>
                            <span className="text-zinc-400">({rel.related_incident_title})</span>
                          </div>
                          <div className="flex items-center space-x-1.5">
                            <span className="font-mono text-[10px] px-1.5 py-0.5 bg-[#252830] text-zinc-300 border border-[#31343C] rounded">
                              {rel.relationship_reason}
                            </span>
                            <span className="font-mono text-[10px] px-1.5 py-0.5 bg-[#1B2636] text-blue-300 border border-blue-900 rounded">
                              {rel.correlation_status}
                            </span>
                            {renderEpistemicBadge(rel.epistemic_status)}
                          </div>
                        </div>

                        <div className="text-zinc-300">{rel.summary}</div>

                        {rel.shared_entities.length > 0 && (
                          <div className="flex items-center space-x-1.5 pt-1">
                            <span className="text-[11px] text-zinc-400">Shared Entities:</span>
                            {rel.shared_entities.map((ent, i) => (
                              <span key={i} className="font-mono text-[10px] px-1.5 py-0.2 bg-[#1E2026] text-[#8BB9E0] border border-[#2D3038] rounded">
                                {ent}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {/* VIEW: EVIDENCE GAPS */}
            {activeTab === "gaps" && (
              <div className="bg-[#17181C] border border-[#26282E] rounded p-4 h-full overflow-y-auto space-y-3">
                <div className="flex items-center justify-between">
                  <h3 className="text-xs font-semibold uppercase tracking-wider text-zinc-300">
                    Temporal Evidence Gaps ({dossier.gaps.length})
                  </h3>
                  <span className="text-[11px] text-zinc-400 italic">
                    Absence of evidence is not evidence of absence.
                  </span>
                </div>

                <div className="space-y-3">
                  {dossier.gaps.length === 0 ? (
                    <div className="p-4 text-xs text-zinc-500 italic bg-[#131417] rounded border border-[#222429]">
                      No visibility or telemetry gaps identified in this reconstruction.
                    </div>
                  ) : (
                    dossier.gaps.map((gap) => (
                      <div
                        key={gap.gap_id}
                        className="p-3 bg-[#141518] border border-[#222429] rounded text-xs space-y-2"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <AlertIcon className="w-3.5 h-3.5 text-amber-400" />
                            <span className="font-semibold text-zinc-200">{gap.title}</span>
                          </div>
                          <span className="font-mono text-[10px] px-1.5 py-0.5 bg-[#2B231D] text-amber-300 border border-amber-900 rounded">
                            {gap.gap_type}
                          </span>
                        </div>

                        <div className="text-zinc-400">{gap.description}</div>

                        <div className="p-2 bg-[#121316] border border-[#202227] rounded text-xs space-y-1">
                          <span className="text-zinc-500 font-mono text-[10px] uppercase">Remedy Action:</span>
                          <div className="text-zinc-300">{gap.remedy}</div>
                        </div>

                        {gap.affected_entities.length > 0 && (
                          <div className="flex items-center space-x-1.5 pt-1">
                            <span className="text-[11px] text-zinc-500">Affected Entities:</span>
                            {gap.affected_entities.map((e, idx) => (
                              <span key={idx} className="font-mono text-[10px] px-1.5 py-0.2 bg-[#1C1E23] text-zinc-400 rounded">
                                {e}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
