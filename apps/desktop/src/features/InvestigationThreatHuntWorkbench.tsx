import React, { useEffect, useState } from "react";
import {
  previewThreatHuntM75,
  createThreatHuntProposalM75,
  approveThreatHuntM75,
  executeThreatHuntM75,
  fetchCaseHuntsM75,
  fetchHuntDetailM75,
  pivotThreatHuntEntityM75,
  pivotThreatHuntTemporalM75,
  executeSequenceThreatHuntM75,
  executeIocThreatHuntM75,
  exportThreatHuntM75,
  aiAssistThreatHuntM75,
  convertHuntToFindingM75,
  convertHuntToHypothesisM75,
  convertHuntToCollectionM75,
} from "../lib/api";
import {
  HuntIntent,
  QueryOperator,
  HuntApprovalState,
  HuntExecutionStatus,
  EpistemicStatusM75,
  FieldFilter,
  EntityFilter,
  HuntQueryPreview,
  HuntResultItem,
  HuntExecutionResult,
  HuntSequenceProposal,
  HuntSequenceResult,
  HuntHistoryRecord,
} from "../types/investigation";

interface InvestigationThreatHuntWorkbenchProps {
  caseId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
  onPivotTimeline?: (timestamp: string) => void;
}

export function InvestigationThreatHuntWorkbench({
  caseId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
  onPivotTimeline,
}: InvestigationThreatHuntWorkbenchProps) {
  const [activeTab, setActiveTab] = useState<
    "builder" | "results" | "pivots" | "sequence" | "history"
  >("builder");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // --- 1. Query Builder State ---
  const [intent, setIntent] = useState<HuntIntent>("PROCESS_EXECUTION");
  const [question, setQuestion] = useState("");
  const [fieldFilters, setFieldFilters] = useState<FieldFilter[]>([]);
  const [entityFilters, setEntityFilters] = useState<EntityFilter[]>([]);
  const [limit, setLimit] = useState(100);

  // New filter inputs
  const [filterField, setFilterField] = useState("process_name");
  const [filterOp, setFilterOp] = useState<QueryOperator>("equals");
  const [filterVal, setFilterVal] = useState("");

  // AI Assistance
  const [aiPrompt, setAiPrompt] = useState("");
  const [aiLoading, setAiLoading] = useState(false);

  // --- 2. Preview & Governance Gate ---
  const [preview, setPreview] = useState<HuntQueryPreview | null>(null);
  const [activeHuntId, setActiveHuntId] = useState<string | null>(null);
  const [approvalState, setApprovalState] = useState<HuntApprovalState>("DRAFT");
  const [approvalRationale, setApprovalRationale] = useState("");

  // --- 3. Execution & Results State ---
  const [huntResult, setHuntResult] = useState<HuntExecutionResult | null>(null);
  const [selectedResult, setSelectedResult] = useState<HuntResultItem | null>(null);
  const [selectedResultIds, setSelectedResultIds] = useState<string[]>([]);

  // --- 4. Specialized Pivots State ---
  const [pivotEntityType, setPivotEntityType] = useState("USER");
  const [pivotEntityValue, setPivotEntityValue] = useState("");
  const [temporalAnchor, setTemporalAnchor] = useState("2026-10-07T10:00:00Z");
  const [temporalWindowMin, setTemporalWindowMin] = useState(15);
  const [temporalDirection, setTemporalDirection] = useState<"before" | "after" | "around">("around");
  const [iocValue, setIocValue] = useState("");

  // --- 5. Sequence State ---
  const [seqName, setSeqName] = useState("Multi-Stage Attack Sequence");
  const [seqDesc, setSeqDesc] = useState("Analyst sequence hypothesis");
  const [seqStep1Action, setSeqStep1Action] = useState("login");
  const [seqStep2Action, setSeqStep2Action] = useState("sudo");
  const [seqStep3Action, setSeqStep3Action] = useState("exec");
  const [sequenceResult, setSequenceResult] = useState<HuntSequenceResult | null>(null);

  // --- 6. Actions on Results (Finding / Hypothesis / Collection) ---
  const [showFindingModal, setShowFindingModal] = useState(false);
  const [findingTitle, setFindingTitle] = useState("");
  const [findingStatement, setFindingStatement] = useState("");
  const [findingSeverity, setFindingSeverity] = useState("HIGH");

  const [showHypothesisModal, setShowHypothesisModal] = useState(false);
  const [hypTargetId, setHypTargetId] = useState("");
  const [hypRole, setHypRole] = useState<"SUPPORTING" | "CONTRADICTING">("SUPPORTING");

  const [showCollectionModal, setShowCollectionModal] = useState(false);
  const [colTargetId, setColTargetId] = useState("");

  // --- 7. History ---
  const [historyRecords, setHistoryRecords] = useState<HuntHistoryRecord[]>([]);

  // Load history on mount or tab change
  const loadHistory = async () => {
    try {
      const records = await fetchCaseHuntsM75(caseId);
      setHistoryRecords(records);
    } catch (e: any) {
      console.warn("Could not load hunt history:", e);
    }
  };

  useEffect(() => {
    loadHistory();
  }, [caseId]);

  // Handler: Add field filter
  const handleAddFilter = () => {
    if (!filterField || !filterVal) return;
    setFieldFilters([...fieldFilters, { field: filterField, operator: filterOp, value: filterVal }]);
    setFilterVal("");
    setPreview(null);
    setApprovalState("DRAFT");
  };

  const handleRemoveFilter = (idx: number) => {
    setFieldFilters(fieldFilters.filter((_, i) => i !== idx));
    setPreview(null);
    setApprovalState("DRAFT");
  };

  // Handler: Local AI Proposal Assistance
  const handleAiAssist = async () => {
    if (!aiPrompt.trim()) return;
    try {
      setAiLoading(true);
      setError(null);
      const proposal = await aiAssistThreatHuntM75(caseId, aiPrompt.trim());
      setIntent(proposal.intent);
      setQuestion(proposal.question);
      setFieldFilters(proposal.field_filters || []);
      setEntityFilters(proposal.entity_filters || []);
      setSuccessMsg("AI generated structured hunt proposal (requires analyst preview and approval).");
      setPreview(null);
      setApprovalState("DRAFT");
    } catch (err: any) {
      setError(err.message || "AI Proposal Assistance failed");
    } finally {
      setAiLoading(false);
    }
  };

  // Handler: Preview Hunt
  const handlePreview = async () => {
    try {
      setLoading(true);
      setError(null);
      const prev = await previewThreatHuntM75(caseId, {
        intent,
        question: question || `Hunt for ${intent}`,
        field_filters: fieldFilters,
        entity_filters: entityFilters,
        limit,
      });
      setPreview(prev);
      setApprovalState("READY");
    } catch (err: any) {
      setError(err.message || "Query preview failed");
    } finally {
      setLoading(false);
    }
  };

  // Handler: Create & Approve Hunt
  const handleApprove = async () => {
    try {
      setLoading(true);
      setError(null);
      // 1. Create proposal
      const prop = await createThreatHuntProposalM75(caseId, {
        intent,
        question: question || `Hunt for ${intent}`,
        field_filters: fieldFilters,
        entity_filters: entityFilters,
        limit,
      });
      setActiveHuntId(prop.hunt_id);

      // 2. Approve proposal
      const app = await approveThreatHuntM75(caseId, prop.hunt_id, approvalRationale);
      setApprovalState("APPROVED");
      setSuccessMsg(`Hunt ${prop.hunt_id} approved for bounded execution.`);
    } catch (err: any) {
      setError(err.message || "Approval failed");
    } finally {
      setLoading(false);
    }
  };

  // Handler: Execute Approved Hunt
  const handleExecute = async () => {
    if (!activeHuntId) return;
    try {
      setLoading(true);
      setError(null);
      const res = await executeThreatHuntM75(caseId, activeHuntId);
      setHuntResult(res);
      setApprovalState("COMPLETED");
      if (res.results.length > 0) {
        setSelectedResult(res.results[0]);
      }
      setActiveTab("results");
      loadHistory();
      setSuccessMsg(`Execution completed: ${res.result_count} items matched in ${res.duration_ms.toFixed(1)}ms.`);
    } catch (err: any) {
      setError(err.message || "Hunt execution failed");
    } finally {
      setLoading(false);
    }
  };

  // Handler: Specialized Entity Pivot
  const handleEntityPivot = async () => {
    if (!pivotEntityValue.trim()) return;
    try {
      setLoading(true);
      setError(null);
      const res = await pivotThreatHuntEntityM75(caseId, pivotEntityType, pivotEntityValue.trim());
      setHuntResult(res);
      setActiveHuntId(res.hunt_id);
      if (res.results.length > 0) setSelectedResult(res.results[0]);
      setActiveTab("results");
      loadHistory();
    } catch (err: any) {
      setError(err.message || "Entity pivot hunt failed");
    } finally {
      setLoading(false);
    }
  };

  // Handler: Specialized Temporal Pivot
  const handleTemporalPivot = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await pivotThreatHuntTemporalM75(caseId, temporalAnchor, temporalWindowMin, temporalDirection);
      setHuntResult(res);
      setActiveHuntId(res.hunt_id);
      if (res.results.length > 0) setSelectedResult(res.results[0]);
      setActiveTab("results");
      loadHistory();
    } catch (err: any) {
      setError(err.message || "Temporal pivot hunt failed");
    } finally {
      setLoading(false);
    }
  };

  // Handler: IOC Lookup
  const handleIocHunt = async () => {
    if (!iocValue.trim()) return;
    try {
      setLoading(true);
      setError(null);
      const res = await executeIocThreatHuntM75(caseId, iocValue.trim());
      setHuntResult(res);
      setActiveHuntId(res.hunt_id);
      if (res.results.length > 0) setSelectedResult(res.results[0]);
      setActiveTab("results");
      loadHistory();
    } catch (err: any) {
      setError(err.message || "IOC hunt failed");
    } finally {
      setLoading(false);
    }
  };

  // Handler: Sequence Hunt
  const handleSequenceHunt = async () => {
    try {
      setLoading(true);
      setError(null);
      const proposal: HuntSequenceProposal = {
        case_id: caseId,
        sequence_name: seqName,
        description: seqDesc,
        steps: [
          {
            step_number: 1,
            name: `Initial Step (${seqStep1Action})`,
            action_type: seqStep1Action,
            field_filters: [{ field: "action", operator: "equals", value: seqStep1Action }],
            max_time_delta_seconds: 600,
          },
          {
            step_number: 2,
            name: `Second Step (${seqStep2Action})`,
            action_type: seqStep2Action,
            field_filters: [{ field: "action", operator: "equals", value: seqStep2Action }],
            max_time_delta_seconds: 600,
          },
          {
            step_number: 3,
            name: `Third Step (${seqStep3Action})`,
            action_type: seqStep3Action,
            field_filters: [{ field: "action", operator: "equals", value: seqStep3Action }],
            max_time_delta_seconds: 600,
          },
        ],
      };
      const res = await executeSequenceThreatHuntM75(caseId, proposal);
      setSequenceResult(res);
      setSuccessMsg(`Sequence evaluated: ${res.matched_steps}/${res.total_steps} steps matched.`);
    } catch (err: any) {
      setError(err.message || "Sequence hunt failed");
    } finally {
      setLoading(false);
    }
  };

  // Handler: Deterministic Export
  const handleExport = async (format: "json" | "csv") => {
    if (!activeHuntId) return;
    try {
      const exp = await exportThreatHuntM75(caseId, activeHuntId, format);
      const blob = new Blob([exp.export_content], {
        type: format === "json" ? "application/json" : "text/csv",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `hunt_${activeHuntId}_${caseId}.${format}`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccessMsg(`Export downloaded (Fingerprint: ${exp.fingerprint.slice(0, 12)}...)`);
    } catch (err: any) {
      setError(err.message || "Export failed");
    }
  };

  // Convert to Finding
  const handleConvertToFinding = async () => {
    if (!huntResult || selectedResultIds.length === 0) return;
    try {
      setLoading(true);
      setError(null);
      await convertHuntToFindingM75(caseId, {
        hunt_id: huntResult.hunt_id,
        title: findingTitle || `Finding from Hunt ${huntResult.hunt_id}`,
        statement: findingStatement || `Identified ${selectedResultIds.length} candidate evidence items.`,
        result_ids: selectedResultIds,
        severity: findingSeverity,
      });
      setShowFindingModal(false);
      setSuccessMsg(`Converted ${selectedResultIds.length} hunt items to new Finding.`);
      setSelectedResultIds([]);
    } catch (err: any) {
      setError(err.message || "Finding conversion failed");
    } finally {
      setLoading(false);
    }
  };

  // Convert to Collection
  const handleConvertToCollection = async () => {
    if (!huntResult || selectedResultIds.length === 0 || !colTargetId) return;
    try {
      setLoading(true);
      setError(null);
      await convertHuntToCollectionM75(caseId, {
        hunt_id: huntResult.hunt_id,
        collection_id: colTargetId,
        result_ids: selectedResultIds,
        role: "SUPPORTING",
      });
      setShowCollectionModal(false);
      setSuccessMsg(`Added ${selectedResultIds.length} hunt items to collection ${colTargetId}.`);
      setSelectedResultIds([]);
    } catch (err: any) {
      setError(err.message || "Collection addition failed");
    } finally {
      setLoading(false);
    }
  };

  // Convert to Hypothesis
  const handleConvertToHypothesis = async () => {
    if (!huntResult || selectedResultIds.length === 0 || !hypTargetId) return;
    try {
      setLoading(true);
      setError(null);
      await convertHuntToHypothesisM75(caseId, {
        hunt_id: huntResult.hunt_id,
        hypothesis_id: hypTargetId,
        result_ids: selectedResultIds,
        role: hypRole,
      });
      setShowHypothesisModal(false);
      setSuccessMsg(`Attached ${selectedResultIds.length} items to hypothesis ${hypTargetId}.`);
      setSelectedResultIds([]);
    } catch (err: any) {
      setError(err.message || "Hypothesis attachment failed");
    } finally {
      setLoading(false);
    }
  };

  const toggleSelectResult = (rid: string) => {
    if (selectedResultIds.includes(rid)) {
      setSelectedResultIds(selectedResultIds.filter((id) => id !== rid));
    } else {
      setSelectedResultIds([...selectedResultIds, rid]);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#faf9f6] text-[#1f2421] font-sans border border-[#e5e4de] text-xs">
      {/* Top Header */}
      <div className="px-4 py-2 border-b border-[#e5e4de] bg-[#f2f1ec] flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <span className="font-semibold text-sm tracking-tight text-[#1f2421]">
            THREAT HUNTING & ANALYST QUERY WORKBENCH
          </span>
          <span className="px-2 py-0.5 bg-[#e2e0d8] text-[#474e48] rounded text-[11px] font-mono">
            CASE #{caseId}
          </span>
          <span className="text-[11px] text-[#5c635d]">
            Analyst-Directed Governed Operations (Forensic Non-Authoritative)
          </span>
        </div>

        {/* Tab Switcher */}
        <div className="flex space-x-1 border border-[#d6d4cc] bg-[#e5e4de] p-0.5 rounded">
          <button
            onClick={() => setActiveTab("builder")}
            className={`px-2.5 py-1 text-[11px] font-medium rounded ${
              activeTab === "builder"
                ? "bg-white text-[#1f2421] shadow-none font-semibold"
                : "text-[#5c635d] hover:text-[#1f2421]"
            }`}
          >
            Query Builder
          </button>
          <button
            onClick={() => setActiveTab("results")}
            className={`px-2.5 py-1 text-[11px] font-medium rounded ${
              activeTab === "results"
                ? "bg-white text-[#1f2421] font-semibold"
                : "text-[#5c635d] hover:text-[#1f2421]"
            }`}
          >
            Results {huntResult ? `(${huntResult.result_count})` : ""}
          </button>
          <button
            onClick={() => setActiveTab("pivots")}
            className={`px-2.5 py-1 text-[11px] font-medium rounded ${
              activeTab === "pivots"
                ? "bg-white text-[#1f2421] font-semibold"
                : "text-[#5c635d] hover:text-[#1f2421]"
            }`}
          >
            Pivots & IOCs
          </button>
          <button
            onClick={() => setActiveTab("sequence")}
            className={`px-2.5 py-1 text-[11px] font-medium rounded ${
              activeTab === "sequence"
                ? "bg-white text-[#1f2421] font-semibold"
                : "text-[#5c635d] hover:text-[#1f2421]"
            }`}
          >
            Sequence Hunting
          </button>
          <button
            onClick={() => setActiveTab("history")}
            className={`px-2.5 py-1 text-[11px] font-medium rounded ${
              activeTab === "history"
                ? "bg-white text-[#1f2421] font-semibold"
                : "text-[#5c635d] hover:text-[#1f2421]"
            }`}
          >
            Hunt History
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="px-4 py-1.5 bg-[#fef2f2] border-b border-[#fecaca] text-[#991b1b] flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-[#991b1b] font-bold">×</button>
        </div>
      )}
      {successMsg && (
        <div className="px-4 py-1.5 bg-[#f0fdf4] border-b border-[#bbf7d0] text-[#166534] flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-[#166534] font-bold">×</button>
        </div>
      )}

      {/* Content Body */}
      <div className="flex-1 overflow-auto p-4">
        {/* ================================================================= */}
        {/* TAB 1: QUERY BUILDER & PREVIEW */}
        {/* ================================================================= */}
        {activeTab === "builder" && (
          <div className="grid grid-cols-12 gap-4">
            {/* Left Column: Form & Filters */}
            <div className="col-span-7 space-y-4">
              {/* Local AI Proposal Assistant */}
              <div className="border border-[#e5e4de] bg-white p-3 rounded">
                <div className="font-semibold text-xs text-[#1f2421] mb-1 flex items-center justify-between">
                  <span>AI Investigation Proposal Assistant</span>
                  <span className="text-[10px] text-[#854d0e] bg-[#fef9c3] px-1.5 py-0.5 rounded font-mono">
                    ADVISORY ONLY
                  </span>
                </div>
                <p className="text-[11px] text-[#5c635d] mb-2">
                  Translate natural language hypotheses into structured governed hunt proposals.
                </p>
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={aiPrompt}
                    onChange={(e) => setAiPrompt(e.target.value)}
                    placeholder="e.g., Show curl executions with outbound connections to external IPs"
                    className="flex-1 border border-[#d6d4cc] px-2 py-1 text-xs rounded bg-[#faf9f6]"
                  />
                  <button
                    onClick={handleAiAssist}
                    disabled={aiLoading}
                    className="px-3 py-1 bg-[#1e3a8a] text-white rounded text-xs hover:bg-[#1d4ed8] disabled:opacity-50"
                  >
                    {aiLoading ? "Proposing..." : "Generate Proposal"}
                  </button>
                </div>
              </div>

              {/* Hunt Definition */}
              <div className="border border-[#e5e4de] bg-white p-3 rounded space-y-3">
                <div className="font-semibold text-xs text-[#1f2421]">1. Structured Hunt Intent & Scope</div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-[#5c635d] mb-0.5">Intent Category</label>
                    <select
                      value={intent}
                      onChange={(e) => setIntent(e.target.value as HuntIntent)}
                      className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                    >
                      <option value="PROCESS_EXECUTION">PROCESS_EXECUTION</option>
                      <option value="AUTHENTICATION_ACTIVITY">AUTHENTICATION_ACTIVITY</option>
                      <option value="PRIVILEGE_ESCALATION">PRIVILEGE_ESCALATION</option>
                      <option value="NETWORK_CONNECTION">NETWORK_CONNECTION</option>
                      <option value="FILE_ACTIVITY">FILE_ACTIVITY</option>
                      <option value="PERSISTENCE">PERSISTENCE</option>
                      <option value="SYSTEMD_SERVICE_ACTIVITY">SYSTEMD_SERVICE_ACTIVITY</option>
                      <option value="CONTAINER_ACTIVITY">CONTAINER_ACTIVITY</option>
                      <option value="USER_SESSION">USER_SESSION</option>
                      <option value="CROSS_HOST_ACTIVITY">CROSS_HOST_ACTIVITY</option>
                      <option value="IOC_LOOKUP">IOC_LOOKUP</option>
                      <option value="ENTITY_ACTIVITY">ENTITY_ACTIVITY</option>
                      <option value="TEMPORAL_SEQUENCE">TEMPORAL_SEQUENCE</option>
                      <option value="CORRELATION">CORRELATION</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-[11px] text-[#5c635d] mb-0.5">Max Bounded Limit</label>
                    <input
                      type="number"
                      value={limit}
                      onChange={(e) => setLimit(Number(e.target.value))}
                      min={1}
                      max={1000}
                      className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[11px] text-[#5c635d] mb-0.5">Analyst Question / Hypothesis</label>
                  <input
                    type="text"
                    value={question}
                    onChange={(e) => setQuestion(e.target.value)}
                    placeholder="e.g., Identify anomalous root executions following interactive SSH session"
                    className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                  />
                </div>

                {/* Field Filters */}
                <div>
                  <div className="font-semibold text-xs text-[#1f2421] mb-1">2. Controlled Field Filters</div>
                  <div className="flex space-x-2 mb-2">
                    <select
                      value={filterField}
                      onChange={(e) => setFilterField(e.target.value)}
                      className="border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                    >
                      <option value="process_name">process_name</option>
                      <option value="username">username</option>
                      <option value="host">host</option>
                      <option value="src_ip">src_ip</option>
                      <option value="dst_ip">dst_ip</option>
                      <option value="action">action</option>
                      <option value="outcome">outcome</option>
                      <option value="event_type">event_type</option>
                      <option value="summary">summary</option>
                      <option value="raw_message">raw_message</option>
                    </select>
                    <select
                      value={filterOp}
                      onChange={(e) => setFilterOp(e.target.value as QueryOperator)}
                      className="border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                    >
                      <option value="equals">equals</option>
                      <option value="not_equals">not_equals</option>
                      <option value="contains">contains</option>
                      <option value="prefix">prefix</option>
                      <option value="suffix">suffix</option>
                      <option value="exists">exists</option>
                    </select>
                    <input
                      type="text"
                      value={filterVal}
                      onChange={(e) => setFilterVal(e.target.value)}
                      placeholder="Value"
                      className="flex-1 border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                    />
                    <button
                      onClick={handleAddFilter}
                      className="px-3 py-1 bg-[#2e3430] text-white text-xs rounded hover:bg-[#1f2421]"
                    >
                      Add Filter
                    </button>
                  </div>

                  {fieldFilters.length > 0 ? (
                    <div className="space-y-1">
                      {fieldFilters.map((f, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between bg-[#f2f1ec] px-2 py-1 rounded text-[11px] font-mono border border-[#e5e4de]"
                        >
                          <span>
                            <strong className="text-[#1f2421]">{f.field}</strong> {f.operator}{" "}
                            <span className="text-[#1e3a8a]">"{f.value}"</span>
                          </span>
                          <button
                            onClick={() => handleRemoveFilter(i)}
                            className="text-[#991b1b] font-bold hover:underline"
                          >
                            ×
                          </button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-[11px] text-[#808782] italic">No field filters added (broad query).</p>
                  )}
                </div>

                {/* Preview Trigger Button */}
                <div className="pt-2 border-t border-[#e5e4de] flex justify-end">
                  <button
                    onClick={handlePreview}
                    disabled={loading}
                    className="px-4 py-1.5 bg-[#2563eb] text-white text-xs rounded hover:bg-[#1d4ed8] disabled:opacity-50"
                  >
                    {loading ? "Validating..." : "Preview Hunt Plan"}
                  </button>
                </div>
              </div>
            </div>

            {/* Right Column: Preview & Approval Gate */}
            <div className="col-span-5 space-y-4">
              <div className="border border-[#e5e4de] bg-white p-3 rounded space-y-3">
                <div className="font-semibold text-xs text-[#1f2421] flex items-center justify-between border-b border-[#e5e4de] pb-1">
                  <span>Query Preview & Governance</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono ${
                      approvalState === "APPROVED"
                        ? "bg-[#dcfce7] text-[#166534]"
                        : approvalState === "READY"
                        ? "bg-[#fef9c3] text-[#854d0e]"
                        : "bg-[#f3f4f6] text-[#4b5563]"
                    }`}
                  >
                    STATE: {approvalState}
                  </span>
                </div>

                {preview ? (
                  <div className="space-y-2 text-[11px]">
                    <div className="grid grid-cols-2 gap-2 bg-[#fbfbfa] p-2 rounded border border-[#e5e4de]">
                      <div>
                        <span className="text-[#5c635d]">Validation: </span>
                        <strong className="text-[#166534] font-mono">{preview.validation_status}</strong>
                      </div>
                      <div>
                        <span className="text-[#5c635d]">Filters: </span>
                        <strong className="font-mono">{preview.filter_count}</strong>
                      </div>
                      <div>
                        <span className="text-[#5c635d]">Complexity: </span>
                        <strong className="font-mono">{preview.estimated_complexity}/10</strong>
                      </div>
                      <div>
                        <span className="text-[#5c635d]">Bounded Limit: </span>
                        <strong className="font-mono">{preview.resource_limits.max_result_count} items</strong>
                      </div>
                    </div>

                    <div>
                      <div className="font-semibold text-[#5c635d] mb-0.5">Execution Summary Plan:</div>
                      <div className="p-2 bg-[#1f2421] text-[#a7f3d0] font-mono text-[10px] rounded overflow-x-auto whitespace-pre">
                        {preview.preview_sql_summary}
                      </div>
                    </div>

                    <div className="border-t border-[#e5e4de] pt-2 space-y-2">
                      <div className="font-semibold text-xs text-[#1f2421]">Analyst Approval Gate</div>
                      <input
                        type="text"
                        value={approvalRationale}
                        onChange={(e) => setApprovalRationale(e.target.value)}
                        placeholder="Rationale for executing this hunt"
                        className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                      />
                      <div className="flex space-x-2">
                        <button
                          onClick={handleApprove}
                          disabled={approvalState === "APPROVED" || loading}
                          className="flex-1 px-3 py-1.5 bg-[#854d0e] text-white rounded text-xs hover:bg-[#713f12] disabled:opacity-50"
                        >
                          Approve Hunt
                        </button>
                        <button
                          onClick={handleExecute}
                          disabled={approvalState !== "APPROVED" || loading}
                          className="flex-1 px-3 py-1.5 bg-[#166534] text-white rounded text-xs hover:bg-[#14532d] disabled:opacity-50"
                        >
                          {loading ? "Executing..." : "Execute Approved Hunt"}
                        </button>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-center py-8 text-[#808782] text-[11px]">
                    No preview generated. Configure filters and click "Preview Hunt Plan" to validate and approve.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* TAB 2: HUNT RESULTS & EVIDENCE WORKFLOW */}
        {/* ================================================================= */}
        {activeTab === "results" && (
          <div className="space-y-3">
            {huntResult ? (
              <>
                {/* Result Metadata Banner */}
                <div className="p-2.5 bg-white border border-[#e5e4de] rounded flex items-center justify-between text-xs">
                  <div className="flex items-center space-x-4">
                    <div>
                      <span className="text-[#5c635d]">Hunt ID: </span>
                      <strong className="font-mono">{huntResult.hunt_id}</strong>
                    </div>
                    <div>
                      <span className="text-[#5c635d]">Status: </span>
                      <strong className="font-mono text-[#166534]">{huntResult.status}</strong>
                    </div>
                    <div>
                      <span className="text-[#5c635d]">Matches: </span>
                      <strong className="font-mono">{huntResult.result_count} items</strong>
                    </div>
                    <div>
                      <span className="text-[#5c635d]">Latency: </span>
                      <strong className="font-mono">{huntResult.duration_ms.toFixed(1)}ms</strong>
                    </div>
                    <div>
                      <span className="text-[#5c635d]">Fingerprint: </span>
                      <span className="font-mono text-[10px] bg-[#f2f1ec] px-1 py-0.5 rounded">
                        {huntResult.query_fingerprint.slice(0, 16)}...
                      </span>
                    </div>
                  </div>

                  {/* Actions & Export */}
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => handleExport("json")}
                      className="px-2.5 py-1 bg-[#f2f1ec] border border-[#d6d4cc] rounded text-[11px] hover:bg-[#e5e4de]"
                    >
                      Export JSON
                    </button>
                    <button
                      onClick={() => handleExport("csv")}
                      className="px-2.5 py-1 bg-[#f2f1ec] border border-[#d6d4cc] rounded text-[11px] hover:bg-[#e5e4de]"
                    >
                      Export CSV
                    </button>
                    {selectedResultIds.length > 0 && (
                      <>
                        <button
                          onClick={() => setShowFindingModal(true)}
                          className="px-2.5 py-1 bg-[#1e3a8a] text-white rounded text-[11px] hover:bg-[#1d4ed8]"
                        >
                          → Finding ({selectedResultIds.length})
                        </button>
                        <button
                          onClick={() => setShowCollectionModal(true)}
                          className="px-2.5 py-1 bg-[#854d0e] text-white rounded text-[11px] hover:bg-[#713f12]"
                        >
                          → Collection ({selectedResultIds.length})
                        </button>
                        <button
                          onClick={() => setShowHypothesisModal(true)}
                          className="px-2.5 py-1 bg-[#166534] text-white rounded text-[11px] hover:bg-[#14532d]"
                        >
                          → Hypothesis ({selectedResultIds.length})
                        </button>
                      </>
                    )}
                  </div>
                </div>

                {/* Results Table & Inspector */}
                <div className="grid grid-cols-12 gap-3">
                  <div className="col-span-8 border border-[#e5e4de] bg-white rounded overflow-hidden">
                    <table className="w-full text-left border-collapse text-[11px]">
                      <thead className="bg-[#f2f1ec] border-b border-[#e5e4de] text-[#5c635d]">
                        <tr>
                          <th className="p-2 w-8 text-center">
                            <input
                              type="checkbox"
                              checked={
                                selectedResultIds.length === huntResult.results.length &&
                                huntResult.results.length > 0
                              }
                              onChange={(e) => {
                                if (e.target.checked) {
                                  setSelectedResultIds(huntResult.results.map((r) => r.result_id));
                                } else {
                                  setSelectedResultIds([]);
                                }
                              }}
                            />
                          </th>
                          <th className="p-2">Timestamp</th>
                          <th className="p-2">Host</th>
                          <th className="p-2">Action / Process</th>
                          <th className="p-2">Epistemic</th>
                          <th className="p-2">Summary</th>
                        </tr>
                      </thead>
                      <tbody>
                        {huntResult.results.map((r) => (
                          <tr
                            key={r.result_id}
                            onClick={() => setSelectedResult(r)}
                            className={`border-b border-[#f2f1ec] cursor-pointer hover:bg-[#fbfbfa] ${
                              selectedResult?.result_id === r.result_id ? "bg-[#f0f4ff]" : ""
                            }`}
                          >
                            <td className="p-2 text-center" onClick={(e) => e.stopPropagation()}>
                              <input
                                type="checkbox"
                                checked={selectedResultIds.includes(r.result_id)}
                                onChange={() => toggleSelectResult(r.result_id)}
                              />
                            </td>
                            <td className="p-2 font-mono whitespace-nowrap text-[#474e48]">
                              {r.timestamp.slice(0, 19)}
                            </td>
                            <td className="p-2 font-mono text-[#1f2421]">{r.host}</td>
                            <td className="p-2 font-mono">
                              <span className="text-[#1e3a8a]">{r.action}</span>{" "}
                              {r.process_name ? `(${r.process_name})` : ""}
                            </td>
                            <td className="p-2">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                                  r.epistemic_status === "OBSERVED"
                                    ? "bg-[#dcfce7] text-[#166534]"
                                    : "bg-[#fef9c3] text-[#854d0e]"
                                }`}
                              >
                                {r.epistemic_status}
                              </span>
                            </td>
                            <td className="p-2 truncate max-w-xs">{r.summary}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* Inspector Panel */}
                  <div className="col-span-4 border border-[#e5e4de] bg-white p-3 rounded space-y-3">
                    <div className="font-semibold text-xs text-[#1f2421] border-b border-[#e5e4de] pb-1">
                      Evidence Item Lineage
                    </div>
                    {selectedResult ? (
                      <div className="space-y-2 text-[11px]">
                        <div>
                          <span className="text-[#5c635d]">Result Ref: </span>
                          <strong className="font-mono">{selectedResult.result_id}</strong>
                        </div>
                        <div>
                          <span className="text-[#5c635d]">Source Layer: </span>
                          <strong className="font-mono">{selectedResult.source_type} #{selectedResult.source_id}</strong>
                        </div>
                        <div>
                          <span className="text-[#5c635d]">Citation Tag: </span>
                          <strong className="font-mono text-[#1e3a8a]">{selectedResult.citation_tag}</strong>
                        </div>
                        <div>
                          <span className="text-[#5c635d]">Provenance Hash: </span>
                          <div className="font-mono text-[10px] bg-[#f2f1ec] p-1 rounded break-all">
                            {selectedResult.provenance_hash}
                          </div>
                        </div>
                        <div>
                          <span className="text-[#5c635d]">Raw Telemetry Payload: </span>
                          <pre className="p-2 bg-[#1f2421] text-[#a7f3d0] font-mono text-[10px] rounded overflow-x-auto whitespace-pre-wrap mt-1">
                            {selectedResult.raw_preview}
                          </pre>
                        </div>

                        {/* Pivot Buttons */}
                        <div className="pt-2 border-t border-[#e5e4de] flex flex-wrap gap-1">
                          {onSelectEventId && (
                            <button
                              onClick={() => onSelectEventId(selectedResult.source_id)}
                              className="px-2 py-1 bg-[#f2f1ec] border border-[#d6d4cc] rounded text-[10px] hover:bg-[#e5e4de]"
                            >
                              Open Raw Event
                            </button>
                          )}
                          {onPivotTimeline && (
                            <button
                              onClick={() => onPivotTimeline(selectedResult.timestamp)}
                              className="px-2 py-1 bg-[#f2f1ec] border border-[#d6d4cc] rounded text-[10px] hover:bg-[#e5e4de]"
                            >
                              Timeline Replay
                            </button>
                          )}
                          {selectedResult.username && onSelectEntityKey && (
                            <button
                              onClick={() => onSelectEntityKey(`USER:${selectedResult.username}`)}
                              className="px-2 py-1 bg-[#f2f1ec] border border-[#d6d4cc] rounded text-[10px] hover:bg-[#e5e4de]"
                            >
                              Pivot User
                            </button>
                          )}
                          {selectedResult.host && onSelectEntityKey && (
                            <button
                              onClick={() => onSelectEntityKey(`HOST:${selectedResult.host}`)}
                              className="px-2 py-1 bg-[#f2f1ec] border border-[#d6d4cc] rounded text-[10px] hover:bg-[#e5e4de]"
                            >
                              Pivot Host
                            </button>
                          )}
                        </div>
                      </div>
                    ) : (
                      <p className="text-[11px] text-[#808782] italic">Select a result item to inspect forensic details.</p>
                    )}
                  </div>
                </div>
              </>
            ) : (
              <div className="text-center py-12 text-[#808782] text-xs">
                No active hunt results. Configure and execute a query in Query Builder or run an entity pivot.
              </div>
            )}
          </div>
        )}

        {/* ================================================================= */}
        {/* TAB 3: PIVOTS & IOC LOOKUP */}
        {/* ================================================================= */}
        {activeTab === "pivots" && (
          <div className="grid grid-cols-3 gap-4">
            {/* Entity Pivot Card */}
            <div className="border border-[#e5e4de] bg-white p-3 rounded space-y-3">
              <div className="font-semibold text-xs text-[#1f2421]">Entity-Centric Hunt</div>
              <p className="text-[11px] text-[#5c635d]">
                Investigate all telemetry associated with a specific identity, host, or network entity.
              </p>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Entity Type</label>
                <select
                  value={pivotEntityType}
                  onChange={(e) => setPivotEntityType(e.target.value)}
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                >
                  <option value="USER">USER</option>
                  <option value="HOST">HOST</option>
                  <option value="IP">IP</option>
                  <option value="PROCESS">PROCESS</option>
                </select>
              </div>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Entity Value</label>
                <input
                  type="text"
                  value={pivotEntityValue}
                  onChange={(e) => setPivotEntityValue(e.target.value)}
                  placeholder="e.g., admin or srv-web-01"
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                />
              </div>
              <button
                onClick={handleEntityPivot}
                disabled={loading}
                className="w-full px-3 py-1.5 bg-[#1e3a8a] text-white rounded text-xs hover:bg-[#1d4ed8] disabled:opacity-50"
              >
                Execute Entity Pivot
              </button>
            </div>

            {/* Temporal Window Card */}
            <div className="border border-[#e5e4de] bg-white p-3 rounded space-y-3">
              <div className="font-semibold text-xs text-[#1f2421]">Temporal Window Hunt</div>
              <p className="text-[11px] text-[#5c635d]">
                Scan bounded intervals surrounding an anchor incident timestamp.
              </p>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Anchor Timestamp (UTC)</label>
                <input
                  type="text"
                  value={temporalAnchor}
                  onChange={(e) => setTemporalAnchor(e.target.value)}
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-[11px] text-[#5c635d] mb-0.5">Window (Minutes)</label>
                  <input
                    type="number"
                    value={temporalWindowMin}
                    onChange={(e) => setTemporalWindowMin(Number(e.target.value))}
                    min={1}
                    max={1440}
                    className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                  />
                </div>
                <div>
                  <label className="block text-[11px] text-[#5c635d] mb-0.5">Direction</label>
                  <select
                    value={temporalDirection}
                    onChange={(e) => setTemporalDirection(e.target.value as any)}
                    className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                  >
                    <option value="around">around (±)</option>
                    <option value="before">before</option>
                    <option value="after">after</option>
                  </select>
                </div>
              </div>
              <button
                onClick={handleTemporalPivot}
                disabled={loading}
                className="w-full px-3 py-1.5 bg-[#854d0e] text-white rounded text-xs hover:bg-[#713f12] disabled:opacity-50"
              >
                Execute Temporal Scan
              </button>
            </div>

            {/* IOC Lookup Card */}
            <div className="border border-[#e5e4de] bg-white p-3 rounded space-y-3">
              <div className="font-semibold text-xs text-[#1f2421]">Forensic IOC Lookup</div>
              <p className="text-[11px] text-[#5c635d]">
                Exact-match search across forensic telemetry for suspect IP, command, or file indicator.
              </p>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Indicator Value</label>
                <input
                  type="text"
                  value={iocValue}
                  onChange={(e) => setIocValue(e.target.value)}
                  placeholder="e.g., 198.51.100.22 or /tmp/loader"
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                />
              </div>
              <div className="text-[11px] text-[#808782]">
                *Matching an indicator does NOT automatically classify an incident malicious.
              </div>
              <button
                onClick={handleIocHunt}
                disabled={loading}
                className="w-full px-3 py-1.5 bg-[#166534] text-white rounded text-xs hover:bg-[#14532d] disabled:opacity-50"
              >
                Execute IOC Lookup
              </button>
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* TAB 4: SEQUENCE HUNTING */}
        {/* ================================================================= */}
        {activeTab === "sequence" && (
          <div className="grid grid-cols-12 gap-4">
            <div className="col-span-5 border border-[#e5e4de] bg-white p-3 rounded space-y-3">
              <div className="font-semibold text-xs text-[#1f2421]">Sequence Proposal Builder</div>
              <p className="text-[11px] text-[#5c635d]">
                Define expected stages in a candidate attack chain to verify sequential progression.
              </p>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Sequence Name</label>
                <input
                  type="text"
                  value={seqName}
                  onChange={(e) => setSeqName(e.target.value)}
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                />
              </div>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Step 1 Action (e.g., login)</label>
                <input
                  type="text"
                  value={seqStep1Action}
                  onChange={(e) => setSeqStep1Action(e.target.value)}
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                />
              </div>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Step 2 Action (e.g., sudo)</label>
                <input
                  type="text"
                  value={seqStep2Action}
                  onChange={(e) => setSeqStep2Action(e.target.value)}
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                />
              </div>
              <div>
                <label className="block text-[11px] text-[#5c635d] mb-0.5">Step 3 Action (e.g., exec)</label>
                <input
                  type="text"
                  value={seqStep3Action}
                  onChange={(e) => setSeqStep3Action(e.target.value)}
                  className="w-full border border-[#d6d4cc] p-1 text-xs rounded bg-[#faf9f6]"
                />
              </div>
              <button
                onClick={handleSequenceHunt}
                disabled={loading}
                className="w-full px-3 py-1.5 bg-[#1e3a8a] text-white rounded text-xs hover:bg-[#1d4ed8] disabled:opacity-50"
              >
                Evaluate Attack Sequence
              </button>
            </div>

            <div className="col-span-7 border border-[#e5e4de] bg-white p-3 rounded space-y-3">
              <div className="font-semibold text-xs text-[#1f2421] border-b border-[#e5e4de] pb-1">
                Sequence Evaluation Breakdown
              </div>
              {sequenceResult ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-3 gap-2 bg-[#fbfbfa] p-2 rounded border border-[#e5e4de] text-[11px]">
                    <div>
                      <span className="text-[#5c635d]">Matched Steps: </span>
                      <strong className="font-mono text-[#166534]">
                        {sequenceResult.matched_steps}/{sequenceResult.total_steps}
                      </strong>
                    </div>
                    <div>
                      <span className="text-[#5c635d]">Missing Steps: </span>
                      <strong className="font-mono text-[#991b1b]">{sequenceResult.missing_steps}</strong>
                    </div>
                    <div>
                      <span className="text-[#5c635d]">Classification: </span>
                      <span className="font-mono bg-[#f2f1ec] px-1 py-0.5 rounded">
                        {sequenceResult.epistemic_classification}
                      </span>
                    </div>
                  </div>

                  <div className="space-y-2">
                    {sequenceResult.step_evaluations.map((step) => (
                      <div
                        key={step.step_number}
                        className={`p-2.5 rounded border text-[11px] ${
                          step.status === "MATCHED"
                            ? "bg-[#f0fdf4] border-[#bbf7d0]"
                            : "bg-[#fef2f2] border-[#fecaca]"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <strong className="font-mono">
                            STEP {step.step_number}: {step.name}
                          </strong>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                              step.status === "MATCHED"
                                ? "bg-[#dcfce7] text-[#166534]"
                                : "bg-[#fee2e2] text-[#991b1b]"
                            }`}
                          >
                            {step.status}
                          </span>
                        </div>
                        {step.status === "MATCHED" ? (
                          <div className="text-[10px] space-y-0.5 text-[#474e48]">
                            <div>
                              <span>Event: </span>
                              <strong className="font-mono">{step.matched_event_id}</strong> on{" "}
                              <strong className="font-mono">{step.host}</strong> ({step.timestamp?.slice(0, 19)})
                            </div>
                            <div className="truncate">{step.evidence_summary}</div>
                          </div>
                        ) : (
                          <p className="text-[10px] text-[#991b1b] italic">
                            Missing telemetry or unobserved sequence step.
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-12 text-[#808782] text-xs">
                  Configure sequence steps and click "Evaluate Attack Sequence" to inspect multi-stage correlation.
                </div>
              )}
            </div>
          </div>
        )}

        {/* ================================================================= */}
        {/* TAB 5: HUNT HISTORY */}
        {/* ================================================================= */}
        {activeTab === "history" && (
          <div className="border border-[#e5e4de] bg-white rounded overflow-hidden">
            <div className="p-2.5 bg-[#f2f1ec] border-b border-[#e5e4de] font-semibold text-xs flex justify-between items-center">
              <span>Immutable Hunt Query Audit History for Case #{caseId}</span>
              <button
                onClick={loadHistory}
                className="text-[11px] text-[#1e3a8a] hover:underline"
              >
                Refresh
              </button>
            </div>
            <table className="w-full text-left border-collapse text-[11px]">
              <thead className="bg-[#fbfbfa] border-b border-[#e5e4de] text-[#5c635d]">
                <tr>
                  <th className="p-2">Query ID</th>
                  <th className="p-2">Executed At</th>
                  <th className="p-2">Executed By</th>
                  <th className="p-2">Rationale</th>
                  <th className="p-2">Status</th>
                  <th className="p-2 text-right">Result Count</th>
                </tr>
              </thead>
              <tbody>
                {historyRecords.length > 0 ? (
                  historyRecords.map((rec) => (
                    <tr key={rec.query_id} className="border-b border-[#f2f1ec] hover:bg-[#faf9f6]">
                      <td className="p-2 font-mono font-medium text-[#1e3a8a]">{rec.query_id}</td>
                      <td className="p-2 font-mono text-[#474e48]">{rec.executed_at.slice(0, 19)}</td>
                      <td className="p-2 font-mono">{rec.executed_by}</td>
                      <td className="p-2 truncate max-w-sm">{rec.rationale}</td>
                      <td className="p-2">
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-[#dcfce7] text-[#166534]">
                          {rec.execution_status}
                        </span>
                      </td>
                      <td className="p-2 text-right font-mono font-semibold">{rec.result_count}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="p-6 text-center text-[#808782] italic">
                      No hunt query executions recorded yet for this case.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ================================================================= */}
      {/* MODALS: FORMULATE FINDING / ADD TO COLLECTION / HYPOTHESIS */}
      {/* ================================================================= */}
      {showFindingModal && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-[#d6d4cc] rounded p-4 w-full max-w-md space-y-3">
            <div className="font-semibold text-sm text-[#1f2421]">Formulate Finding from Hunt Results</div>
            <p className="text-xs text-[#5c635d]">
              Converts {selectedResultIds.length} selected hunt results into a structured M7.4 analyst finding.
            </p>
            <div>
              <label className="block text-[11px] text-[#5c635d] mb-0.5">Finding Title</label>
              <input
                type="text"
                value={findingTitle}
                onChange={(e) => setFindingTitle(e.target.value)}
                placeholder="e.g., Suspicious Shell Invocation via Sudo"
                className="w-full border border-[#d6d4cc] p-1.5 text-xs rounded bg-[#faf9f6]"
              />
            </div>
            <div>
              <label className="block text-[11px] text-[#5c635d] mb-0.5">Statement / Analytical Claim</label>
              <textarea
                value={findingStatement}
                onChange={(e) => setFindingStatement(e.target.value)}
                rows={3}
                placeholder="Analyst interpretation of observed hunt evidence..."
                className="w-full border border-[#d6d4cc] p-1.5 text-xs rounded bg-[#faf9f6]"
              />
            </div>
            <div>
              <label className="block text-[11px] text-[#5c635d] mb-0.5">Severity</label>
              <select
                value={findingSeverity}
                onChange={(e) => setFindingSeverity(e.target.value)}
                className="w-full border border-[#d6d4cc] p-1.5 text-xs rounded bg-[#faf9f6]"
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
                <option value="INFORMATIONAL">INFORMATIONAL</option>
              </select>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setShowFindingModal(false)}
                className="px-3 py-1 border border-[#d6d4cc] rounded text-xs hover:bg-[#f2f1ec]"
              >
                Cancel
              </button>
              <button
                onClick={handleConvertToFinding}
                disabled={loading}
                className="px-4 py-1 bg-[#1e3a8a] text-white rounded text-xs hover:bg-[#1d4ed8] disabled:opacity-50"
              >
                Create Finding
              </button>
            </div>
          </div>
        </div>
      )}

      {showCollectionModal && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-[#d6d4cc] rounded p-4 w-full max-w-md space-y-3">
            <div className="font-semibold text-sm text-[#1f2421]">Add to Logical Evidence Collection</div>
            <p className="text-xs text-[#5c635d]">
              Adds {selectedResultIds.length} selected items to an existing logical collection (M7.3).
            </p>
            <div>
              <label className="block text-[11px] text-[#5c635d] mb-0.5">Collection ID</label>
              <input
                type="text"
                value={colTargetId}
                onChange={(e) => setColTargetId(e.target.value)}
                placeholder="e.g., col-alpha-123"
                className="w-full border border-[#d6d4cc] p-1.5 text-xs rounded bg-[#faf9f6]"
              />
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setShowCollectionModal(false)}
                className="px-3 py-1 border border-[#d6d4cc] rounded text-xs hover:bg-[#f2f1ec]"
              >
                Cancel
              </button>
              <button
                onClick={handleConvertToCollection}
                disabled={loading || !colTargetId}
                className="px-4 py-1 bg-[#854d0e] text-white rounded text-xs hover:bg-[#713f12] disabled:opacity-50"
              >
                Add to Collection
              </button>
            </div>
          </div>
        </div>
      )}

      {showHypothesisModal && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
          <div className="bg-white border border-[#d6d4cc] rounded p-4 w-full max-w-md space-y-3">
            <div className="font-semibold text-sm text-[#1f2421]">Attach to Hypothesis Evaluation</div>
            <p className="text-xs text-[#5c635d]">
              Attaches {selectedResultIds.length} selected items as evidence to evaluate a candidate hypothesis.
            </p>
            <div>
              <label className="block text-[11px] text-[#5c635d] mb-0.5">Hypothesis ID</label>
              <input
                type="text"
                value={hypTargetId}
                onChange={(e) => setHypTargetId(e.target.value)}
                placeholder="e.g., HYP-1"
                className="w-full border border-[#d6d4cc] p-1.5 text-xs rounded bg-[#faf9f6]"
              />
            </div>
            <div>
              <label className="block text-[11px] text-[#5c635d] mb-0.5">Evidence Role</label>
              <select
                value={hypRole}
                onChange={(e) => setHypRole(e.target.value as any)}
                className="w-full border border-[#d6d4cc] p-1.5 text-xs rounded bg-[#faf9f6]"
              >
                <option value="SUPPORTING">SUPPORTING</option>
                <option value="CONTRADICTING">CONTRADICTING</option>
              </select>
            </div>
            <div className="flex justify-end space-x-2 pt-2">
              <button
                onClick={() => setShowHypothesisModal(false)}
                className="px-3 py-1 border border-[#d6d4cc] rounded text-xs hover:bg-[#f2f1ec]"
              >
                Cancel
              </button>
              <button
                onClick={handleConvertToHypothesis}
                disabled={loading || !hypTargetId}
                className="px-4 py-1 bg-[#166534] text-white rounded text-xs hover:bg-[#14532d] disabled:opacity-50"
              >
                Attach Evidence
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
