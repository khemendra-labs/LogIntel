import React, { useEffect, useState } from "react";
import { SearchIcon, RefreshIcon, AlertIcon, CheckIcon } from "../components/Icons";
import {
  askInvestigationQuestion,
  getInvestigationEvidenceBundle,
  previewInvestigationQuery,
  getInvestigationWorkspace,
  updateInvestigationState,
  fetchInvestigationHypotheses,
  createInvestigationHypothesis,
  updateInvestigationHypothesis,
  executeApprovedInvestigationQuery,
  fetchInvestigationSummary,
  generateInvestigationReportDraft,
  traceClaimExplainability,
  createInvestigationNote,
  createOrOpenCase,
  updateCaseStatus,
  handoffCase,
  fetchCaseReports,
  generateCaseReportDraft,
  compareCaseReportVersions,
  fetchCaseAuditLog,
} from "../lib/api";
import {
  AIInvestigationResponse,
  AnalystHypothesis,
  ClaimTrace,
  HypothesisStatus,
  InvestigationEvidenceBundle,
  InvestigationState,
  InvestigationSummary,
  InvestigationWorkspace,
  QueryPreviewResponse,
  QueryProposal,
  ReportDraft,
  InvestigationCase,
  CaseStatus,
  CaseReportVersion,
  CaseAuditRecord,
} from "../types/investigation";
import { InvestigationGraphExplorer } from "./InvestigationGraphExplorer";
import { InvestigationCorrelationExplorer } from "./InvestigationCorrelationExplorer";
import { InvestigationTemporalExplorer } from "./InvestigationTemporalExplorer";
import { InvestigationAssessmentExplorer } from "./InvestigationAssessmentExplorer";

interface InvestigationIntelligencePanelProps {
  incidentId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function InvestigationIntelligencePanel({
  incidentId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}: InvestigationIntelligencePanelProps) {
  // Navigation sub-tabs for M5.4, M5.5, M5.8, M5.9, M5.10 & M5.11
  const [subTab, setSubTab] = useState<"ask" | "hypotheses" | "queries" | "summary" | "report" | "audit" | "graph" | "correlation" | "timeline" | "assessment">("ask");

  // Persistent Case State (M5.5 Continuity)
  const [caseData, setCaseData] = useState<InvestigationCase | null>(null);
  const [caseLoading, setCaseLoading] = useState(false);
  const [handoffModalOpen, setHandoffModalOpen] = useState(false);
  const [handoffOwner, setHandoffOwner] = useState("");
  const [handoffNotes, setHandoffNotes] = useState("");
  const [handoffLoading, setHandoffLoading] = useState(false);
  const [reportVersions, setReportVersions] = useState<CaseReportVersion[]>([]);
  const [selectedReportVersion, setSelectedReportVersion] = useState<CaseReportVersion | null>(null);
  const [comparingVersions, setComparingVersions] = useState(false);
  const [versionDiff, setVersionDiff] = useState<any | null>(null);
  const [auditLog, setAuditLog] = useState<CaseAuditRecord[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  // Workspace state (M5.4)
  const [workspace, setWorkspace] = useState<InvestigationWorkspace | null>(null);
  const [wsLoading, setWsLoading] = useState(false);
  const [stateTransitioning, setStateTransitioning] = useState(false);

  // Q&A state
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<AIInvestigationResponse | null>(null);
  const [bundle, setBundle] = useState<InvestigationEvidenceBundle | null>(null);
  const [bundleLoading, setBundleLoading] = useState(false);

  // Hypotheses state
  const [hypotheses, setHypotheses] = useState<AnalystHypothesis[]>([]);
  const [newHypStatement, setNewHypStatement] = useState("");
  const [newHypTags, setNewHypTags] = useState("");
  const [creatingHyp, setCreatingHyp] = useState(false);

  // Query execution state
  const [previewProposalId, setPreviewProposalId] = useState<string | null>(null);
  const [previewResult, setPreviewResult] = useState<QueryPreviewResponse | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [executingQuery, setExecutingQuery] = useState(false);
  const [queryExecutionResult, setQueryExecutionResult] = useState<any | null>(null);

  // Summary & Report state
  const [summaryData, setSummaryData] = useState<InvestigationSummary | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [reportDraft, setReportDraft] = useState<ReportDraft | null>(null);
  const [reportLoading, setReportLoading] = useState(false);

  // Explainability trace state
  const [activeTraceClaim, setActiveTraceClaim] = useState<string | null>(null);
  const [activeTraces, setActiveTraces] = useState<ClaimTrace[]>([]);
  const [tracingLoading, setTracingLoading] = useState(false);

  // Note saving notice
  const [noteSavedNotice, setNoteSavedNotice] = useState<string | null>(null);

  useEffect(() => {
    loadCase();
    loadWorkspace();
    loadHypotheses();
  }, [incidentId]);

  const loadCase = async () => {
    setCaseLoading(true);
    try {
      const c = await createOrOpenCase(incidentId);
      setCaseData(c);
      if (c.report_versions && c.report_versions.length > 0) {
        setReportVersions(c.report_versions);
        setSelectedReportVersion(c.report_versions[c.report_versions.length - 1]);
      }
      if (c.audit_history) {
        setAuditLog(c.audit_history);
      }
    } catch (err: any) {
      // Non-fatal fallback
    } finally {
      setCaseLoading(false);
    }
  };

  const loadWorkspace = async () => {
    setWsLoading(true);
    try {
      const ws = await getInvestigationWorkspace(incidentId);
      setWorkspace(ws);
    } catch (err: any) {
      // Non-fatal fallback
    } finally {
      setWsLoading(false);
    }
  };

  const loadHypotheses = async () => {
    try {
      const res = await fetchInvestigationHypotheses(incidentId);
      setHypotheses(res.items);
    } catch (err) {
      // Non-fatal
    }
  };

  const handleCaseTransition = async (newStatus: CaseStatus) => {
    setStateTransitioning(true);
    setError(null);
    try {
      const updated = await updateCaseStatus(incidentId, newStatus, `Analyst manual transition to ${newStatus}`);
      setCaseData(updated);
      if (["OPEN", "ACTIVE", "PAUSED", "READY_FOR_REVIEW", "CLOSED"].includes(newStatus)) {
        try {
          const ws = await updateInvestigationState(incidentId, newStatus as any, "SecAnalyst-1", `Case transition to ${newStatus}`);
          setWorkspace(ws);
        } catch (_) {}
      }
    } catch (err: any) {
      setError(err.message || `Failed to transition case state to ${newStatus}`);
    } finally {
      setStateTransitioning(false);
    }
  };

  const handleHandoff = async () => {
    if (!handoffOwner.trim()) return;
    setHandoffLoading(true);
    setError(null);
    try {
      const updated = await handoffCase(incidentId, handoffOwner.trim(), handoffNotes.trim() || undefined);
      setCaseData(updated);
      setHandoffModalOpen(false);
      setHandoffOwner("");
      setHandoffNotes("");
      setNoteSavedNotice(`Case successfully transferred to analyst ${updated.owner}`);
      setTimeout(() => setNoteSavedNotice(null), 4000);
      loadCase();
    } catch (err: any) {
      setError(err.message || "Failed to transfer case ownership");
    } finally {
      setHandoffLoading(false);
    }
  };

  const handleStateTransition = async (newState: InvestigationState) => {
    setStateTransitioning(true);
    setError(null);
    try {
      const updated = await updateInvestigationState(incidentId, newState, "SecAnalyst-1", `Manual transition to ${newState}`);
      setWorkspace(updated);
      if (["OPEN", "ACTIVE", "PAUSED", "READY_FOR_REVIEW", "CLOSED"].includes(newState)) {
        try {
          const c = await updateCaseStatus(incidentId, newState as any, `Sync from workspace: ${newState}`);
          setCaseData(c);
        } catch (_) {}
      }
    } catch (err: any) {
      setError(err.message || `Failed to transition state to ${newState}`);
    } finally {
      setStateTransitioning(false);
    }
  };

  const handleAsk = async (customQ?: string) => {
    const q = customQ || question;
    if (!q.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await askInvestigationQuestion(incidentId, q.trim());
      setResponse(res);
      fetchBundle();
    } catch (err: any) {
      setError(err.message || "Failed to obtain AI analysis");
    } finally {
      setLoading(false);
    }
  };

  const fetchBundle = async () => {
    setBundleLoading(true);
    try {
      const b = await getInvestigationEvidenceBundle(incidentId);
      setBundle(b);
    } catch (err) {
      // Non-fatal
    } finally {
      setBundleLoading(false);
    }
  };

  const handleCreateHypothesis = async () => {
    if (!newHypStatement.trim()) return;
    setCreatingHyp(true);
    setError(null);
    try {
      const tags = newHypTags
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean);
      await createInvestigationHypothesis(incidentId, {
        statement: newHypStatement.trim(),
        supporting_tags: tags,
      });
      setNewHypStatement("");
      setNewHypTags("");
      loadHypotheses();
    } catch (err: any) {
      setError(err.message || "Failed to create hypothesis");
    } finally {
      setCreatingHyp(false);
    }
  };

  const handleUpdateHypStatus = async (hypId: string, status: HypothesisStatus) => {
    try {
      await updateInvestigationHypothesis(incidentId, hypId, { status });
      loadHypotheses();
    } catch (err: any) {
      setError(err.message || `Failed to update status for ${hypId}`);
    }
  };

  const handlePreviewQuery = async (prop: QueryProposal) => {
    setPreviewProposalId(prop.proposal_id);
    setPreviewLoading(true);
    setPreviewResult(null);
    setQueryExecutionResult(null);
    try {
      const res = await previewInvestigationQuery(incidentId, prop);
      setPreviewResult(res);
    } catch (err: any) {
      setError(`Failed to preview query: ${err.message}`);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleExecuteQuery = async (prop: QueryProposal) => {
    setExecutingQuery(true);
    setError(null);
    try {
      const res = await executeApprovedInvestigationQuery(incidentId, prop);
      setQueryExecutionResult(res);
      loadWorkspace();
    } catch (err: any) {
      setError(`Failed to execute approved query: ${err.message}`);
    } finally {
      setExecutingQuery(false);
    }
  };

  const handleLoadSummary = async () => {
    setSummaryLoading(true);
    setError(null);
    try {
      const s = await fetchInvestigationSummary(incidentId);
      setSummaryData(s);
    } catch (err: any) {
      setError(`Failed to load investigation summary: ${err.message}`);
    } finally {
      setSummaryLoading(false);
    }
  };

  const handleGenerateReportDraft = async () => {
    setReportLoading(true);
    setError(null);
    try {
      const r = await generateInvestigationReportDraft(incidentId);
      setReportDraft(r);
    } catch (err: any) {
      setError(`Failed to generate report draft: ${err.message}`);
    } finally {
      setReportLoading(false);
    }
  };

  const handleTraceClaim = async (claimText: string, tags: string[]) => {
    setActiveTraceClaim(claimText);
    setTracingLoading(true);
    try {
      const res = await traceClaimExplainability(incidentId, claimText, tags);
      setActiveTraces(res.traces);
    } catch (err: any) {
      setError(`Failed to trace claim: ${err.message}`);
    } finally {
      setTracingLoading(false);
    }
  };

  const handlePromoteToAnalystNote = async (content: string, type: string) => {
    try {
      await createInvestigationNote(incidentId, {
        author: "SecAnalyst-1",
        content: `[AI-ASSISTED ${type}] ${content}`,
        target_type: "incident",
        target_id: String(incidentId),
      });
      setNoteSavedNotice(`Successfully saved as persistent analyst note`);
      setTimeout(() => setNoteSavedNotice(null), 4000);
    } catch (err: any) {
      setError(`Failed to save note: ${err.message}`);
    }
  };

  const handleCitationClick = (tag: string) => {
    const match = tag.match(/^\[([a-zA-Z0-9_-]+):([^\]\s]+)\]$/);
    if (!match) return;
    const type = match[1].toLowerCase();
    const id = match[2];
    if (type === "event" && onSelectEventId) {
      onSelectEventId(id);
    } else if (type === "alert" && onSelectAlertId) {
      const num = parseInt(id, 10);
      if (!isNaN(num)) onSelectAlertId(num);
    } else if (type === "entity" && onSelectEntityKey) {
      onSelectEntityKey(id);
    }
  };

  const stateColors: Record<string, { bg: string; text: string; border: string }> = {
    OPEN: { bg: "#edf2f7", text: "#4a5568", border: "#cbd5e0" },
    ACTIVE: { bg: "#feebc8", text: "#744210", border: "#fbd38d" },
    PAUSED: { bg: "#edf2f7", text: "#718096", border: "#e2e8f0" },
    READY_FOR_REVIEW: { bg: "#e6fffa", text: "#234e52", border: "#81e6d9" },
    CLOSED: { bg: "#e2e8f0", text: "#2d3748", border: "#a0aec0" },
    ARCHIVED: { bg: "#f1f5f9", text: "#64748b", border: "#cbd5e1" },
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px", padding: "16px 0" }}>
      {/* Persistent Investigation Case Header (M5.5 Continuity) */}
      <div
        style={{
          padding: "12px 16px",
          background: "var(--bg-subtle, #f5f4ef)",
          border: "1px solid var(--border-color, #e2e8f0)",
          borderRadius: "4px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, letterSpacing: "0.5px", color: "var(--text-primary, #1a202c)" }}>
            CASE #{caseData?.case_id ?? incidentId}
          </div>
          <div style={{ fontSize: "11px", fontWeight: 700, padding: "2px 6px", background: "#edf2f7", borderRadius: "3px", color: "#4a5568" }}>
            v{caseData?.version ?? 1}
          </div>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 700,
              textTransform: "uppercase",
              padding: "3px 8px",
              borderRadius: "3px",
              background: stateColors[(caseData?.status as any) || workspace?.state || "OPEN"]?.bg || "#edf2f7",
              color: stateColors[(caseData?.status as any) || workspace?.state || "OPEN"]?.text || "#4a5568",
              border: `1px solid ${stateColors[(caseData?.status as any) || workspace?.state || "OPEN"]?.border || "#cbd5e0"}`,
            }}
          >
            STATUS: {caseData?.status || workspace?.state || "OPEN"}
          </div>
          <div style={{ fontSize: "11px", color: "#4a5568", background: "#f7fafc", padding: "2px 6px", borderRadius: "3px", border: "1px solid #e2e8f0" }}>
            Owner: <strong>{caseData?.owner || "SecAnalyst-1"}</strong>
          </div>
          <button
            className="btn btn-secondary"
            style={{ fontSize: "10px", padding: "2px 6px" }}
            onClick={() => setHandoffModalOpen(!handoffModalOpen)}
          >
            {handoffModalOpen ? "Close Handoff" : "Handoff Case"}
          </button>
          <div style={{ fontSize: "11px", color: "#718096", fontFamily: "var(--font-mono, monospace)" }}>
            Scope: {caseData?.scope?.time_start?.slice(0, 10) || workspace?.scope?.time_start?.slice(0, 10)} to {caseData?.scope?.time_end?.slice(0, 10) || workspace?.scope?.time_end?.slice(0, 10)} • Evidence: {caseData?.evidence_references?.length ?? workspace?.evidence_candidates?.length ?? 0}
          </div>
        </div>

        {/* Governed State Transition Actions */}
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <span style={{ fontSize: "11px", color: "#718096" }}>Transition:</span>
          {(caseData?.status === "OPEN" || (!caseData && workspace?.state === "OPEN")) && (
            <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "2px 8px" }} onClick={() => handleCaseTransition("ACTIVE")} disabled={stateTransitioning}>
              Start Investigation (Active)
            </button>
          )}
          {(caseData?.status === "ACTIVE" || (!caseData && workspace?.state === "ACTIVE")) && (
            <>
              <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "2px 8px" }} onClick={() => handleCaseTransition("PAUSED")} disabled={stateTransitioning}>
                Pause
              </button>
              <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "2px 8px" }} onClick={() => handleCaseTransition("READY_FOR_REVIEW")} disabled={stateTransitioning}>
                Mark Ready for Review
              </button>
            </>
          )}
          {(caseData?.status === "PAUSED" || (!caseData && workspace?.state === "PAUSED")) && (
            <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "2px 8px" }} onClick={() => handleCaseTransition("ACTIVE")} disabled={stateTransitioning}>
              Resume (Active)
            </button>
          )}
          {(caseData?.status === "READY_FOR_REVIEW" || (!caseData && workspace?.state === "READY_FOR_REVIEW")) && (
            <button className="btn btn-primary" style={{ fontSize: "11px", padding: "2px 8px" }} onClick={() => handleCaseTransition("CLOSED")} disabled={stateTransitioning}>
              Approve & Close Case
            </button>
          )}
          {(caseData?.status === "CLOSED" || (!caseData && workspace?.state === "CLOSED")) && (
            <>
              <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "2px 8px" }} onClick={() => handleCaseTransition("ACTIVE")} disabled={stateTransitioning}>
                Reopen Case
              </button>
              <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "2px 8px" }} onClick={() => handleCaseTransition("ARCHIVED")} disabled={stateTransitioning}>
                Archive Case
              </button>
            </>
          )}
          {caseData?.status === "ARCHIVED" && (
            <span style={{ fontSize: "11px", color: "#a0aec0", fontStyle: "italic" }}>Archived (Read-Only)</span>
          )}
        </div>
      </div>

      {/* Case Handoff Inline Form */}
      {handoffModalOpen && (
        <div style={{ padding: "12px 16px", background: "#f8fafc", border: "1px solid #cbd5e1", borderRadius: "4px", display: "flex", flexDirection: "column", gap: "8px" }}>
          <div style={{ fontSize: "12px", fontWeight: 700, color: "#1e293b" }}>ANALYST CASE HANDOFF</div>
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            <input
              type="text"
              className="input-field"
              placeholder="Target Analyst Owner (e.g. SecAnalyst-2)"
              value={handoffOwner}
              onChange={(e) => setHandoffOwner(e.target.value)}
              style={{ fontSize: "11px", padding: "4px 8px", width: "240px" }}
            />
            <input
              type="text"
              className="input-field"
              placeholder="Handoff notes or transfer context"
              value={handoffNotes}
              onChange={(e) => setHandoffNotes(e.target.value)}
              style={{ fontSize: "11px", padding: "4px 8px", flex: 1, minWidth: "220px" }}
            />
            <button
              className="btn btn-primary"
              style={{ fontSize: "11px", padding: "4px 12px" }}
              onClick={handleHandoff}
              disabled={handoffLoading || !handoffOwner.trim()}
            >
              {handoffLoading ? "Transferring..." : "Confirm Handoff"}
            </button>
          </div>
        </div>
      )}

      {/* Sub-Navigation Bar */}
      <div style={{ display: "flex", gap: "4px", borderBottom: "1px solid var(--border-color, #e2e8f0)", paddingBottom: "4px" }}>
        {[
          { id: "ask", label: "Analyst Questions & AI" },
          { id: "assessment", label: "Case Assessment & Closure (M5.11)" },
          { id: "timeline", label: "Temporal Reconstruction & Timeline (M5.10)" },
          { id: "correlation", label: "Evidence Correlation & Findings (M5.9)" },
          { id: "graph", label: "Investigation Graph & Pivots (M5.8)" },
          { id: "hypotheses", label: `Hypothesis Workbench (${hypotheses.length})` },
          { id: "queries", label: "Query Execution & Evidence Candidates" },
          { id: "summary", label: "Structured Summary" },
          { id: "report", label: `Report Versions (${reportVersions.length || 1})` },
          { id: "audit", label: `Audit Trail (${auditLog.length || caseData?.audit_history?.length || 0})` },
        ].map((tab) => (
          <button
            key={tab.id}
            style={{
              padding: "6px 12px",
              fontSize: "12px",
              fontWeight: subTab === tab.id ? 600 : 400,
              background: subTab === tab.id ? "var(--card-bg, #ffffff)" : "transparent",
              color: subTab === tab.id ? "var(--text-primary, #1a202c)" : "#718096",
              border: "1px solid",
              borderColor: subTab === tab.id ? "var(--border-color, #e2e8f0)" : "transparent",
              borderBottom: subTab === tab.id ? "2px solid var(--text-primary, #1a202c)" : "none",
              borderRadius: "4px 4px 0 0",
              cursor: "pointer",
            }}
            onClick={() => {
              setSubTab(tab.id as any);
              if (tab.id === "summary" && !summaryData) handleLoadSummary();
              if (tab.id === "report" && !reportDraft) handleGenerateReportDraft();
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {noteSavedNotice && (
        <div style={{ padding: "8px 12px", background: "#f0fff4", border: "1px solid #9ae6b4", color: "#22543d", borderRadius: "4px", fontSize: "12px" }}>
          {noteSavedNotice}
        </div>
      )}

      {error && (
        <div style={{ padding: "10px 14px", background: "#fff5f5", border: "1px solid #feb2b2", color: "#c53030", borderRadius: "4px", fontSize: "12px" }}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 1: ANALYST QUESTIONS & AI (M5.3 core + M5.4 claim explainability) */}
      {/* ========================================================================= */}
      {subTab === "ask" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Preset Questions */}
          <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
            {[
              { label: "Summarize Incident", q: "Summarize what happened in this incident based on observed evidence." },
              { label: "Reconstruct Timeline", q: "Reconstruct the chronological timeline of observed actions." },
              { label: "Working Hypotheses", q: "What working hypotheses explain this incident, and what evidence supports or contradicts them?" },
              { label: "Audit Visibility Gaps", q: "What telemetry gaps or missing evidence limit our investigation?" },
            ].map((btn, idx) => (
              <button
                key={idx}
                className="btn btn-secondary"
                style={{ fontSize: "11px", padding: "4px 10px" }}
                onClick={() => {
                  setQuestion(btn.q);
                  handleAsk(btn.q);
                }}
                disabled={loading}
              >
                {btn.label}
              </button>
            ))}
          </div>

          {/* Question Input */}
          <div style={{ display: "flex", gap: "8px" }}>
            <input
              type="text"
              className="input-field"
              style={{
                flex: 1,
                padding: "8px 12px",
                fontSize: "13px",
                fontFamily: "inherit",
                border: "1px solid var(--border-color, #e2e8f0)",
                borderRadius: "4px",
              }}
              placeholder="Ask an investigation question against scope..."
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !loading) handleAsk();
              }}
              disabled={loading}
            />
            <button className="btn btn-primary" style={{ padding: "8px 16px", fontSize: "12px" }} onClick={() => handleAsk()} disabled={loading || !question.trim()}>
              {loading ? "Analyzing..." : "Investigate"}
            </button>
          </div>

          {/* Response Container */}
          {response && (
            <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
              {/* Answer Card */}
              <div style={{ padding: "16px", background: "var(--card-bg, #ffffff)", border: "1px solid var(--border-color, #e2e8f0)", borderRadius: "4px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <span style={{ fontSize: "10px", fontWeight: 700, padding: "2px 6px", borderRadius: "3px", background: "#feebc8", color: "#744210" }}>
                      STATUS: {response.epistemic_status}
                    </span>
                    <span style={{ fontSize: "10px", fontWeight: 600, padding: "2px 6px", borderRadius: "3px", background: "#edf2f7", color: "#4a5568" }}>
                      INTENT: {response.intent}
                    </span>
                  </div>
                  <button
                    className="btn btn-secondary"
                    style={{ fontSize: "11px", padding: "2px 8px" }}
                    onClick={() => handlePromoteToAnalystNote(response.answer_markdown, "ANALYSIS DRAFT")}
                  >
                    Save as Analyst Note
                  </button>
                </div>
                <div style={{ fontSize: "13px", lineHeight: "1.6", color: "var(--text-primary, #2d3748)", whiteSpace: "pre-wrap" }}>
                  {response.answer_markdown}
                </div>
              </div>

              {/* Claims & Interactive Explainability Table */}
              {response.claims && response.claims.length > 0 && (
                <div style={{ padding: "16px", background: "var(--card-bg, #ffffff)", border: "1px solid var(--border-color, #e2e8f0)", borderRadius: "4px" }}>
                  <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px", color: "var(--text-primary, #1a202c)" }}>
                    VALIDATED EPISTEMIC CLAIMS & PROVENANCE TRACING
                  </div>
                  <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px" }}>
                    <thead>
                      <tr style={{ borderBottom: "1px solid #e2e8f0", textAlign: "left", color: "#718096" }}>
                        <th style={{ padding: "6px" }}>Epistemic Status</th>
                        <th style={{ padding: "6px" }}>Claim Statement</th>
                        <th style={{ padding: "6px" }}>Evidence Citations</th>
                        <th style={{ padding: "6px" }}>Explainability</th>
                      </tr>
                    </thead>
                    <tbody>
                      {response.claims.map((claim, idx) => (
                        <tr key={idx} style={{ borderBottom: "1px solid #edf2f7" }}>
                          <td style={{ padding: "6px", verticalAlign: "top" }}>
                            <span style={{ fontSize: "10px", fontWeight: 600, padding: "2px 4px", borderRadius: "2px", background: claim.status === "OBSERVED" ? "#e6fffa" : claim.status === "INFERRED" ? "#feebc8" : "#edf2f7", color: claim.status === "OBSERVED" ? "#234e52" : claim.status === "INFERRED" ? "#744210" : "#4a5568" }}>
                              {claim.status}
                            </span>
                          </td>
                          <td style={{ padding: "6px", verticalAlign: "top" }}>{claim.claim_text}</td>
                          <td style={{ padding: "6px", verticalAlign: "top" }}>
                            <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                              {claim.evidence_refs?.map((ref, rIdx) => (
                                <button
                                  key={rIdx}
                                  onClick={() => handleCitationClick(ref.citation_tag)}
                                  style={{ border: "1px solid #cbd5e0", background: "#edf2f7", fontSize: "10px", padding: "1px 4px", borderRadius: "3px", cursor: "pointer", fontFamily: "var(--font-mono, monospace)" }}
                                >
                                  {ref.citation_tag}
                                </button>
                              ))}
                            </div>
                          </td>
                          <td style={{ padding: "6px", verticalAlign: "top" }}>
                            <button
                              className="btn btn-secondary"
                              style={{ fontSize: "10px", padding: "2px 6px" }}
                              onClick={() => handleTraceClaim(claim.claim_text, claim.evidence_refs?.map((r) => r.citation_tag) || [])}
                            >
                              Inspect Provenance
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Explainability Provenance Drawer / Modal */}
              {activeTraceClaim && (
                <div style={{ padding: "14px", background: "#f7fafc", border: "1px solid #cbd5e0", borderRadius: "4px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px" }}>
                    <div style={{ fontSize: "12px", fontWeight: 700, color: "#2d3748" }}>
                      AUTHORITATIVE EVIDENCE PROVENANCE TRACE
                    </div>
                    <button className="btn btn-secondary" style={{ fontSize: "10px", padding: "1px 6px" }} onClick={() => setActiveTraceClaim(null)}>
                      Close
                    </button>
                  </div>
                  <div style={{ fontSize: "12px", color: "#4a5568", marginBottom: "10px", fontStyle: "italic" }}>
                    Claim: "{activeTraceClaim}"
                  </div>
                  {tracingLoading ? (
                    <div style={{ fontSize: "12px", color: "#718096" }}>Tracing citation provenance in authoritative database...</div>
                  ) : activeTraces.length === 0 ? (
                    <div style={{ fontSize: "12px", color: "#718096" }}>No citation tags attached to this claim.</div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                      {activeTraces.map((trace, tIdx) => (
                        <div key={tIdx} style={{ padding: "8px 10px", background: "#ffffff", border: "1px solid #e2e8f0", borderRadius: "3px", fontSize: "11px" }}>
                          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "4px" }}>
                            <strong style={{ fontFamily: "var(--font-mono, monospace)", color: "#2b6cb0" }}>{trace.citation_tag}</strong>
                            <span style={{ color: "#718096" }}>Table: {trace.source_table} • Record ID: {trace.source_id}</span>
                          </div>
                          <div style={{ color: "#2d3748", marginBottom: "4px" }}>{trace.summary}</div>
                          {trace.timestamp && <div style={{ color: "#718096", fontSize: "10px" }}>Authoritative Timestamp: {trace.timestamp}</div>}
                          {trace.raw_evidence && (
                            <details style={{ marginTop: "4px" }}>
                              <summary style={{ cursor: "pointer", color: "#4a5568", fontSize: "10px" }}>Raw Database Record</summary>
                              <pre style={{ margin: "4px 0 0 0", padding: "6px", background: "#edf2f7", fontSize: "10px", borderRadius: "2px", overflowX: "auto" }}>
                                {JSON.stringify(trace.raw_evidence, null, 2)}
                              </pre>
                            </details>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 2: HYPOTHESIS WORKBENCH */}
      {/* ========================================================================= */}
      {subTab === "hypotheses" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Create Hypothesis Card */}
          <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid var(--border-color, #e2e8f0)", borderRadius: "4px" }}>
            <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px" }}>CREATE ANALYST HYPOTHESIS</div>
            <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
              <input
                type="text"
                className="input-field"
                placeholder="State your analytical hypothesis (e.g. Attacker obtained initial access via credential stuffing)..."
                value={newHypStatement}
                onChange={(e) => setNewHypStatement(e.target.value)}
                style={{ padding: "6px 10px", fontSize: "12px", border: "1px solid #cbd5e0", borderRadius: "3px" }}
              />
              <input
                type="text"
                className="input-field"
                placeholder="Supporting citation tags (comma-separated, e.g. [event:ev-fail], [entity:ip:10.0.0.1])..."
                value={newHypTags}
                onChange={(e) => setNewHypTags(e.target.value)}
                style={{ padding: "6px 10px", fontSize: "12px", border: "1px solid #cbd5e0", borderRadius: "3px" }}
              />
              <div style={{ display: "flex", justifyContent: "flex-end" }}>
                <button
                  className="btn btn-primary"
                  style={{ fontSize: "11px", padding: "4px 12px" }}
                  onClick={handleCreateHypothesis}
                  disabled={creatingHyp || !newHypStatement.trim()}
                >
                  {creatingHyp ? "Adding..." : "Register Hypothesis"}
                </button>
              </div>
            </div>
          </div>

          {/* Hypotheses List */}
          <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
            {hypotheses.length === 0 ? (
              <div style={{ padding: "20px", textAlign: "center", color: "#718096", fontSize: "12px" }}>
                No analyst hypotheses currently registered for this investigation.
              </div>
            ) : (
              hypotheses.map((hyp) => (
                <div key={hyp.hypothesis_id} style={{ padding: "12px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                      <span style={{ fontSize: "10px", fontWeight: 700, padding: "2px 6px", borderRadius: "3px", background: hyp.status === "SUPPORTED" ? "#e6fffa" : hyp.status === "REJECTED" ? "#fff5f5" : "#edf2f7", color: hyp.status === "SUPPORTED" ? "#234e52" : hyp.status === "REJECTED" ? "#c53030" : "#4a5568" }}>
                        STATUS: {hyp.status}
                      </span>
                      <strong style={{ fontSize: "12px", color: "var(--text-primary, #1a202c)" }}>{hyp.statement}</strong>
                    </div>
                    <div style={{ display: "flex", gap: "4px" }}>
                      {(["OPEN", "SUPPORTED", "WEAKENED", "UNRESOLVED", "REJECTED"] as HypothesisStatus[]).map((st) => (
                        <button
                          key={st}
                          style={{
                            fontSize: "9px",
                            padding: "2px 5px",
                            borderRadius: "2px",
                            border: "1px solid #cbd5e0",
                            background: hyp.status === st ? "#2d3748" : "#edf2f7",
                            color: hyp.status === st ? "#ffffff" : "#4a5568",
                            cursor: "pointer",
                          }}
                          onClick={() => handleUpdateHypStatus(hyp.hypothesis_id, st)}
                        >
                          {st}
                        </button>
                      ))}
                    </div>
                  </div>
                  {hyp.supporting_evidence_tags.length > 0 && (
                    <div style={{ fontSize: "11px", color: "#718096", display: "flex", gap: "4px", alignItems: "center", marginTop: "4px" }}>
                      <span>Supporting Evidence:</span>
                      {hyp.supporting_evidence_tags.map((tag, tIdx) => (
                        <span key={tIdx} style={{ fontFamily: "var(--font-mono, monospace)", background: "#edf2f7", padding: "1px 4px", borderRadius: "2px", color: "#2b6cb0" }}>
                          {tag}
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

      {/* ========================================================================= */}
      {/* TAB 3: QUERY EXECUTION & EVIDENCE CANDIDATES */}
      {/* ========================================================================= */}
      {subTab === "queries" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Query Proposals List */}
          <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid var(--border-color, #e2e8f0)", borderRadius: "4px" }}>
            <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px" }}>AI THREAT HUNTING QUERY PROPOSALS</div>
            {response?.suggested_query_proposals && response.suggested_query_proposals.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                {response.suggested_query_proposals.map((prop, idx) => (
                  <div key={idx} style={{ padding: "10px", background: "#f7fafc", border: "1px solid #e2e8f0", borderRadius: "3px" }}>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <div>
                        <strong style={{ fontSize: "12px", color: "#2d3748" }}>{prop.title || prop.intent}</strong>
                        <div style={{ fontSize: "11px", color: "#718096" }}>{prop.rationale || "Suggested follow-up threat hunting query"}</div>
                      </div>
                      <div style={{ display: "flex", gap: "6px" }}>
                        <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "3px 8px" }} onClick={() => handlePreviewQuery(prop)} disabled={previewLoading}>
                          Preview Matches
                        </button>
                        <button className="btn btn-primary" style={{ fontSize: "11px", padding: "3px 8px" }} onClick={() => handleExecuteQuery(prop)} disabled={executingQuery}>
                          Approve & Collect Candidates
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: "12px", color: "#718096" }}>
                Ask an investigation question in the Assistant tab to generate structured query proposals.
              </div>
            )}
          </div>

          {/* Preview / Execution Results */}
          {(previewResult || queryExecutionResult) && (
            <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid var(--border-color, #e2e8f0)", borderRadius: "4px" }}>
              <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px" }}>
                {queryExecutionResult ? "APPROVED QUERY EXECUTION RESULTS (EVIDENCE CANDIDATES)" : "READ-ONLY QUERY PREVIEW"}
              </div>
              <div style={{ fontSize: "11px", color: "#718096", marginBottom: "8px" }}>
                Matched {previewResult?.matched_count || queryExecutionResult?.matched_events_count || 0} events in canonical database.
              </div>
              <div style={{ maxHeight: "200px", overflowY: "auto", border: "1px solid #edf2f7", borderRadius: "3px" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px" }}>
                  <thead>
                    <tr style={{ background: "#edf2f7", textAlign: "left", color: "#4a5568" }}>
                      <th style={{ padding: "4px" }}>Event ID</th>
                      <th style={{ padding: "4px" }}>Timestamp</th>
                      <th style={{ padding: "4px" }}>Host</th>
                      <th style={{ padding: "4px" }}>Summary</th>
                    </tr>
                  </thead>
                  <tbody>
                    {((previewResult?.events || queryExecutionResult?.matched_events) || []).map((ev: any, idx: number) => (
                      <tr key={idx} style={{ borderBottom: "1px solid #f7fafc" }}>
                        <td style={{ padding: "4px", fontFamily: "var(--font-mono, monospace)" }}>{ev.id}</td>
                        <td style={{ padding: "4px" }}>{ev.timestamp}</td>
                        <td style={{ padding: "4px" }}>{ev.host}</td>
                        <td style={{ padding: "4px" }}>{ev.summary}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Workspace Evidence Candidates */}
          <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid var(--border-color, #e2e8f0)", borderRadius: "4px" }}>
            <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px" }}>
              WORKSPACE EVIDENCE CANDIDATES ({workspace?.evidence_candidates.length || 0})
            </div>
            {workspace?.evidence_candidates && workspace.evidence_candidates.length > 0 ? (
              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                {workspace.evidence_candidates.map((cand, cIdx) => (
                  <div key={cIdx} style={{ padding: "6px 10px", background: "#f7fafc", border: "1px solid #edf2f7", borderRadius: "3px", fontSize: "11px", display: "flex", justifyContent: "space-between" }}>
                    <div>
                      <strong style={{ fontFamily: "var(--font-mono, monospace)", color: "#2b6cb0" }}>{cand.citation_tag}</strong>
                      <span style={{ marginLeft: "8px", color: "#2d3748" }}>{cand.summary}</span>
                    </div>
                    <span style={{ color: "#718096" }}>Role: {cand.role}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ fontSize: "12px", color: "#718096" }}>No query evidence candidates collected yet.</div>
            )}
          </div>
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 4: STRUCTURED INVESTIGATION SUMMARY */}
      {/* ========================================================================= */}
      {subTab === "summary" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ fontSize: "12px", fontWeight: 700 }}>DETERMINISTIC INVESTIGATION SUMMARY</div>
            <button className="btn btn-secondary" style={{ fontSize: "11px", padding: "4px 10px" }} onClick={handleLoadSummary} disabled={summaryLoading}>
              {summaryLoading ? "Refreshing..." : "Refresh Summary"}
            </button>
          </div>
          {summaryData ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "6px" }}>Key Observations</div>
                <ul style={{ margin: "0 0 0 16px", padding: 0, fontSize: "12px", lineHeight: "1.6" }}>
                  {summaryData.key_observations.map((obs, idx) => (
                    <li key={idx}>{obs}</li>
                  ))}
                </ul>
              </div>

              <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "6px" }}>Identified Visibility Gaps</div>
                <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                  {summaryData.evidence_gaps.map((gap: any, idx: number) => (
                    <div key={idx} style={{ fontSize: "11px", padding: "4px 8px", background: "#f7fafc", borderRadius: "2px" }}>
                      <strong>{gap.source_type} ({gap.gap_type}):</strong> {gap.impact}
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "6px" }}>Open Questions for Hunting</div>
                <ul style={{ margin: "0 0 0 16px", padding: 0, fontSize: "12px", lineHeight: "1.6" }}>
                  {summaryData.open_questions.map((q, idx) => (
                    <li key={idx}>{q}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "#718096" }}>Click Refresh Summary to assemble the structured investigation overview.</div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 5: EXPLAINABLE REPORT DRAFT & CONTINUITY VERSIONS */}
      {/* ========================================================================= */}
      {subTab === "report" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "8px" }}>
            <div style={{ fontSize: "12px", fontWeight: 700 }}>CITATION-GROUNDED REPORT VERSIONS</div>
            <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
              <button
                className="btn btn-secondary"
                style={{ fontSize: "11px", padding: "4px 10px" }}
                onClick={async () => {
                  setReportLoading(true);
                  try {
                    const r = await generateCaseReportDraft(incidentId, `Investigation Dossier - Case #${incidentId}`);
                    const vers = await fetchCaseReports(incidentId);
                    setReportVersions(vers);
                    setSelectedReportVersion(r);
                    loadCase();
                  } catch (err: any) {
                    setError(`Failed to draft report: ${err.message}`);
                  } finally {
                    setReportLoading(false);
                  }
                }}
                disabled={reportLoading}
              >
                {reportLoading ? "Drafting..." : "Draft New Version"}
              </button>
              {selectedReportVersion && selectedReportVersion.version > 1 && (
                <button
                  className="btn btn-secondary"
                  style={{ fontSize: "11px", padding: "4px 10px" }}
                  onClick={async () => {
                    setComparingVersions(true);
                    try {
                      const diff = await compareCaseReportVersions(incidentId, selectedReportVersion.version - 1, selectedReportVersion.version);
                      setVersionDiff(diff);
                    } catch (err: any) {
                      setError(`Failed to compare report versions: ${err.message}`);
                    } finally {
                      setComparingVersions(false);
                    }
                  }}
                  disabled={comparingVersions}
                >
                  {comparingVersions ? "Comparing..." : `Compare with v${selectedReportVersion.version - 1}`}
                </button>
              )}
              {selectedReportVersion && (
                <button
                  className="btn btn-primary"
                  style={{ fontSize: "11px", padding: "4px 10px" }}
                  onClick={() => handlePromoteToAnalystNote(selectedReportVersion.executive_summary, `REPORT v${selectedReportVersion.version}`)}
                >
                  Save as Note
                </button>
              )}
            </div>
          </div>

          {/* Version Pills */}
          {reportVersions.length > 0 && (
            <div style={{ display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" }}>
              <span style={{ fontSize: "11px", color: "#718096" }}>Available Versions:</span>
              {reportVersions.map((v) => (
                <button
                  key={v.version}
                  style={{
                    fontSize: "11px",
                    padding: "3px 8px",
                    borderRadius: "3px",
                    cursor: "pointer",
                    background: selectedReportVersion?.version === v.version ? "var(--text-primary, #1a202c)" : "#edf2f7",
                    color: selectedReportVersion?.version === v.version ? "#ffffff" : "#4a5568",
                    border: "1px solid #cbd5e0",
                  }}
                  onClick={() => {
                    setSelectedReportVersion(v);
                    setVersionDiff(null);
                  }}
                >
                  v{v.version} ({v.origin === "ANALYST_AUTHORED" ? "Analyst" : "AI"})
                </button>
              ))}
            </div>
          )}

          {/* Version Comparison Diff Panel */}
          {versionDiff && (
            <div style={{ padding: "14px", background: "#f8fafc", border: "1px solid #cbd5e1", borderRadius: "4px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "8px" }}>
                <strong style={{ fontSize: "12px", color: "#1e293b" }}>
                  VERSION COMPARISON: v{versionDiff.version_a} vs v{versionDiff.version_b}
                </strong>
                <button className="btn btn-secondary" style={{ fontSize: "10px", padding: "2px 6px" }} onClick={() => setVersionDiff(null)}>
                  Close Diff
                </button>
              </div>
              <div style={{ fontSize: "11px", display: "flex", flexDirection: "column", gap: "6px" }}>
                <div>
                  <span style={{ color: "#047857", fontWeight: 600 }}>Facts Added:</span> {versionDiff.facts_added.length > 0 ? versionDiff.facts_added.join(", ") : "None"}
                </div>
                <div>
                  <span style={{ color: "#b91c1c", fontWeight: 600 }}>Facts Removed:</span> {versionDiff.facts_removed.length > 0 ? versionDiff.facts_removed.join(", ") : "None"}
                </div>
                <div>
                  <span style={{ fontWeight: 600 }}>Summary Differences:</span>
                  <div style={{ background: "#ffffff", padding: "6px 8px", borderRadius: "3px", border: "1px solid #e2e8f0", marginTop: "4px", maxHeight: "120px", overflowY: "auto", fontFamily: "var(--font-mono, monospace)", fontSize: "11px" }}>
                    {versionDiff.summary_diff.map((line: string, lIdx: number) => (
                      <div key={lIdx} style={{ color: line.startsWith("+") ? "#047857" : line.startsWith("-") ? "#b91c1c" : "#475569" }}>
                        {line}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Selected Report Version Content */}
          {selectedReportVersion ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div style={{ padding: "16px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "8px" }}>
                  <div>
                    <div style={{ fontSize: "14px", fontWeight: 700 }}>{selectedReportVersion.title} (v{selectedReportVersion.version})</div>
                    <div style={{ fontSize: "11px", color: "#718096" }}>Created: {selectedReportVersion.created_at} by {selectedReportVersion.created_by}</div>
                  </div>
                  <div style={{ display: "flex", gap: "6px", alignItems: "center" }}>
                    <span style={{ fontSize: "10px", padding: "2px 6px", background: selectedReportVersion.origin === "ANALYST_AUTHORED" ? "#dcfce7" : "#e0e7ff", color: selectedReportVersion.origin === "ANALYST_AUTHORED" ? "#166534" : "#3730a3", borderRadius: "3px", fontWeight: 600 }}>
                      ORIGIN: {selectedReportVersion.origin}
                    </span>
                    {selectedReportVersion.model_name && (
                      <span style={{ fontSize: "10px", padding: "2px 6px", background: "#f1f5f9", color: "#475569", borderRadius: "3px", fontFamily: "var(--font-mono, monospace)" }}>
                        {selectedReportVersion.model_name}
                      </span>
                    )}
                  </div>
                </div>
                <div style={{ fontSize: "13px", lineHeight: "1.6", color: "#2d3748" }}>{selectedReportVersion.executive_summary}</div>
              </div>

              {/* Observed Facts */}
              <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "6px", color: "#234e52" }}>OBSERVED FORENSIC FACTS</div>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {selectedReportVersion.facts.map((fact: any, idx: number) => (
                    <div key={idx} style={{ fontSize: "12px", padding: "6px 8px", background: "#e6fffa", borderRadius: "3px", display: "flex", justifyContent: "space-between" }}>
                      <span>{fact.statement}</span>
                      <strong style={{ fontFamily: "var(--font-mono, monospace)", fontSize: "11px" }}>{fact.evidence_tag}</strong>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analytical Inferences */}
              <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "6px", color: "#744210" }}>ANALYTICAL INFERENCES</div>
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {selectedReportVersion.inferences.map((inf: any, idx: number) => (
                    <div key={idx} style={{ fontSize: "12px", padding: "6px 8px", background: "#feebc8", borderRadius: "3px" }}>
                      <div>{inf.statement}</div>
                      <div style={{ fontSize: "10px", color: "#744210", marginTop: "2px" }}>Rationale: {inf.rationale}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analyst Recommendations */}
              <div style={{ padding: "14px", background: "var(--card-bg, #ffffff)", border: "1px solid #e2e8f0", borderRadius: "4px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "6px" }}>ANALYST RECOMMENDATIONS</div>
                <ul style={{ margin: "0 0 0 16px", padding: 0, fontSize: "12px", lineHeight: "1.6" }}>
                  {selectedReportVersion.recommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div style={{ fontSize: "12px", color: "#718096" }}>Click Draft New Version to generate a citation-grounded report.</div>
          )}
        </div>
      )}

      {/* ========================================================================= */}
      {/* TAB 6: IMMUTABLE AUDIT TRAIL (M5.5 Governance) */}
      {/* ========================================================================= */}
      {subTab === "audit" && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div style={{ fontSize: "12px", fontWeight: 700 }}>IMMUTABLE CASE AUDIT TRAIL</div>
            <button
              className="btn btn-secondary"
              style={{ fontSize: "11px", padding: "4px 10px" }}
              onClick={async () => {
                setAuditLoading(true);
                try {
                  const log = await fetchCaseAuditLog(incidentId);
                  setAuditLog(log);
                } catch (err: any) {
                  setError(`Failed to fetch audit log: ${err.message}`);
                } finally {
                  setAuditLoading(false);
                }
              }}
              disabled={auditLoading}
            >
              {auditLoading ? "Refreshing..." : "Refresh Audit Log"}
            </button>
          </div>

          <div style={{ background: "var(--card-bg, #ffffff)", border: "1px solid var(--border-color, #e2e8f0)", borderRadius: "4px", overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "11px", textAlign: "left" }}>
              <thead>
                <tr style={{ background: "var(--bg-subtle, #f8fafc)", borderBottom: "1px solid var(--border-color, #e2e8f0)" }}>
                  <th style={{ padding: "8px 12px" }}>Timestamp (UTC)</th>
                  <th style={{ padding: "8px 12px" }}>Actor</th>
                  <th style={{ padding: "8px 12px" }}>Action</th>
                  <th style={{ padding: "8px 12px" }}>Previous</th>
                  <th style={{ padding: "8px 12px" }}>New Value</th>
                  <th style={{ padding: "8px 12px" }}>Reason / Notes</th>
                </tr>
              </thead>
              <tbody>
                {auditLog.length > 0 ? (
                  auditLog.map((entry, idx) => (
                    <tr key={idx} style={{ borderBottom: "1px solid #edf2f7" }}>
                      <td style={{ padding: "8px 12px", fontFamily: "var(--font-mono, monospace)", color: "#64748b" }}>
                        {entry.timestamp?.slice(0, 19).replace("T", " ")}
                      </td>
                      <td style={{ padding: "8px 12px", fontWeight: 600 }}>{entry.actor}</td>
                      <td style={{ padding: "8px 12px" }}>
                        <span style={{ padding: "2px 6px", background: "#f1f5f9", borderRadius: "3px", fontFamily: "var(--font-mono, monospace)" }}>
                          {entry.action}
                        </span>
                      </td>
                      <td style={{ padding: "8px 12px", color: "#64748b" }}>{entry.previous_value || "—"}</td>
                      <td style={{ padding: "8px 12px", color: "#0f172a", fontWeight: 500 }}>{entry.new_value || "—"}</td>
                      <td style={{ padding: "8px 12px", color: "#475569" }}>{entry.reason || "—"}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} style={{ padding: "16px", textAlign: "center", color: "#94a3b8" }}>
                      No audit log records found for this case.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* 7. Investigation Graph & Pivots (M5.8) */}
      {subTab === "graph" && (
        <InvestigationGraphExplorer
          caseId={caseData?.case_id || incidentId}
          incidentId={incidentId}
          onSelectEventId={onSelectEventId}
          onSelectAlertId={onSelectAlertId}
          onSelectEntityKey={onSelectEntityKey}
        />
      )}

      {/* 8. Evidence Correlation & Findings (M5.9) */}
      {subTab === "correlation" && (
        <InvestigationCorrelationExplorer
          caseId={caseData?.case_id || incidentId}
          incidentId={incidentId}
          onSelectEventId={onSelectEventId}
          onSelectAlertId={onSelectAlertId}
          onSelectEntityKey={onSelectEntityKey}
        />
      )}

      {/* 9. Temporal Investigation Reconstruction (M5.10) */}
      {subTab === "timeline" && (
        <InvestigationTemporalExplorer
          caseId={caseData?.case_id || incidentId}
          incidentId={incidentId}
          onSelectEventId={onSelectEventId}
          onSelectAlertId={onSelectAlertId}
          onSelectEntityKey={onSelectEntityKey}
        />
      )}

      {/* 10. Case Assessment & Investigation Closure (M5.11) */}
      {subTab === "assessment" && (
        <InvestigationAssessmentExplorer
          caseId={caseData?.case_id || incidentId}
          incidentId={incidentId}
          onSelectEventId={onSelectEventId}
          onSelectAlertId={onSelectAlertId}
          onSelectEntityKey={onSelectEntityKey}
        />
      )}
    </div>
  );
}
