import React, { useEffect, useState, useMemo } from "react";
import {
  CaseAssessment,
  StructuredFinding,
  CompetingHypothesisAssessment,
  InvestigationQuestion,
  PrioritizedEvidenceGap,
  ClosureReadinessAssessment,
  InvestigationBriefing,
  CaseHandoffPackage,
  AssessmentExplanationResponse,
  FindingReviewState,
  EpistemicStatus,
} from "../types/investigation";
import {
  getCaseAssessment,
  getCaseFindings,
  reviewCaseFinding,
  getCaseHypotheses,
  getCaseQuestions,
  createCaseQuestion,
  updateCaseQuestionStatus,
  getCaseGaps,
  getClosureReadiness,
  recordAnalystAssessment,
  getInvestigationBriefing,
  getCaseHandoff,
  explainCaseAssessment,
} from "../lib/api";
import {
  RefreshIcon,
  SearchIcon,
  CheckIcon,
  AlertIcon,
  TimelineIcon,
  ActivityIcon,
} from "../components/Icons";

interface InvestigationAssessmentExplorerProps {
  caseId: number;
  incidentId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function InvestigationAssessmentExplorer({
  caseId,
  incidentId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}: InvestigationAssessmentExplorerProps) {
  // Navigation tabs
  const [activeTab, setActiveTab] = useState<
    "overview" | "findings" | "hypotheses" | "questions" | "gaps" | "conclusion" | "briefing"
  >("overview");

  // State
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [assessment, setAssessment] = useState<CaseAssessment | null>(null);
  const [briefing, setBriefing] = useState<InvestigationBriefing | null>(null);
  const [handoff, setHandoff] = useState<CaseHandoffPackage | null>(null);

  // Form states
  const [analystNote, setAnalystNote] = useState<string>("");
  const [newQuestion, setNewQuestion] = useState<string>("");
  const [newQuestionCategory, setNewQuestionCategory] = useState<string>("AUTHENTICATION");
  const [newQuestionQuery, setNewQuestionQuery] = useState<string>("");
  const [explanation, setExplanation] = useState<AssessmentExplanationResponse | null>(null);
  const [explaining, setExplaining] = useState<boolean>(false);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Load assessment data
  const loadAssessment = async (refresh: boolean = false) => {
    setLoading(true);
    setError(null);
    try {
      const data = await getCaseAssessment(caseId, refresh);
      setAssessment(data);
      setAnalystNote(data.analyst_assessment || "");
    } catch (err: any) {
      setError(err?.message || "Failed to load case assessment");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (caseId) {
      loadAssessment(false);
    }
  }, [caseId]);

  // Load briefing on tab activation
  useEffect(() => {
    if (activeTab === "briefing" && caseId && !briefing) {
      getInvestigationBriefing(caseId)
        .then(setBriefing)
        .catch((e) => console.error("Could not load briefing:", e));
    }
  }, [activeTab, caseId]);

  // Handlers
  const handleReviewFinding = async (findingId: string, reviewState: FindingReviewState) => {
    try {
      await reviewCaseFinding(caseId, findingId, reviewState, "Analyst review via Assessment Explorer");
      setSuccessMsg(`Finding ${findingId} marked as ${reviewState}`);
      await loadAssessment(true);
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setError(err?.message || "Failed to update finding review");
    }
  };

  const handleCreateQuestion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newQuestion.trim()) return;
    try {
      await createCaseQuestion(
        caseId,
        newQuestion.trim(),
        newQuestionCategory,
        [],
        [],
        newQuestionQuery.trim() || undefined
      );
      setNewQuestion("");
      setNewQuestionQuery("");
      setSuccessMsg("Investigation question added");
      await loadAssessment(true);
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setError(err?.message || "Failed to add investigation question");
    }
  };

  const handleUpdateQuestionStatus = async (questionId: string, status: string) => {
    try {
      await updateCaseQuestionStatus(caseId, questionId, status);
      setSuccessMsg(`Question marked as ${status}`);
      await loadAssessment(true);
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setError(err?.message || "Failed to update question status");
    }
  };

  const handleSaveAnalystAssessment = async () => {
    try {
      await recordAnalystAssessment(caseId, analystNote);
      setSuccessMsg("Analyst assessment saved to case record");
      await loadAssessment(false);
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setError(err?.message || "Failed to save analyst assessment");
    }
  };

  const handleExplain = async (targetId?: string) => {
    setExplaining(true);
    try {
      const exp = await explainCaseAssessment(caseId, targetId);
      setExplanation(exp);
    } catch (err: any) {
      setError(err?.message || "Failed to generate explanation");
    } finally {
      setExplaining(false);
    }
  };

  const handleGenerateHandoff = async () => {
    try {
      const hnd = await getCaseHandoff(caseId);
      setHandoff(hnd);
      setSuccessMsg("Analyst handoff package generated");
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err: any) {
      setError(err?.message || "Failed to generate handoff package");
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#1A1A18] text-[#D4D2CD] font-sans text-xs">
      {/* Top Banner / Case Assessment Header */}
      <div className="flex items-center justify-between px-4 py-2.5 bg-[#22221F] border-b border-[#2E2E2A]">
        <div className="flex items-center gap-3">
          <span className="font-mono text-sm font-semibold text-[#EDEBE6]">
            Case #{caseId} Assessment Intelligence
          </span>
          {assessment && (
            <span
              className={`px-2 py-0.5 rounded font-mono text-[10px] font-medium uppercase border ${
                assessment.closure_readiness.status === "READY"
                  ? "bg-[#1E3A2A] text-[#5ED492] border-[#2A523A]"
                  : assessment.closure_readiness.status === "READY_WITH_LIMITATIONS"
                  ? "bg-[#3D331A] text-[#F5C242] border-[#5A4B24]"
                  : "bg-[#3A1E1E] text-[#FF7A70] border-[#5A2A2A]"
              }`}
            >
              Readiness: {assessment.closure_readiness.status.replace(/_/g, " ")}
            </span>
          )}
          {assessment && (
            <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-[#2A2A26] text-[#A8A69E] border border-[#3A3A34]">
              Sufficiency: {assessment.evidence_sufficiency.status}
            </span>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => handleExplain()}
            disabled={explaining}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#2A2A26] hover:bg-[#34342E] text-[#D4D2CD] border border-[#3A3A34] transition-colors"
          >
            <ActivityIcon className="w-3.5 h-3.5 text-[#5ED492]" />
            <span>{explaining ? "Explaining..." : "AI Advisory Review"}</span>
          </button>
          <button
            onClick={() => loadAssessment(true)}
            disabled={loading}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#2A2A26] hover:bg-[#34342E] text-[#D4D2CD] border border-[#3A3A34] transition-colors"
          >
            <RefreshIcon className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Synthesize</span>
          </button>
        </div>
      </div>

      {/* Alerts / Error Messages */}
      {error && (
        <div className="flex items-center gap-2 px-4 py-2 bg-[#3A1E1E] text-[#FF7A70] border-b border-[#5A2A2A]">
          <AlertIcon className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {successMsg && (
        <div className="flex items-center gap-2 px-4 py-2 bg-[#1E3A2A] text-[#5ED492] border-b border-[#2A523A]">
          <CheckIcon className="w-4 h-4 flex-shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Advisory explanation modal / banner */}
      {explanation && (
        <div className="p-3 bg-[#242420] border-b border-[#2E2E2A] text-xs">
          <div className="flex items-center justify-between mb-1.5">
            <span className="font-mono text-[11px] font-semibold text-[#5ED492]">
              LOCAL AI ADVISORY EXPLANATION (NON-AUTHORITATIVE)
            </span>
            <button
              onClick={() => setExplanation(null)}
              className="text-[#8C8A82] hover:text-[#D4D2CD]"
            >
              ✕
            </button>
          </div>
          <pre className="font-mono text-[11px] text-[#A8A69E] whitespace-pre-wrap bg-[#1A1A18] p-2.5 rounded border border-[#2E2E2A]">
            {explanation.explanation_text}
          </pre>
          <div className="mt-1 text-[10px] text-[#6E6D66]">
            Generated at {explanation.generated_at} by {explanation.generated_by}. Grounded in evidence citations.
          </div>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex items-center px-4 bg-[#1E1E1C] border-b border-[#2E2E2A] overflow-x-auto">
        {(
          [
            ["overview", "Assessment Overview"],
            ["findings", `Findings (${assessment?.key_findings.length ?? 0})`],
            ["hypotheses", `Hypotheses (${assessment?.hypotheses.length ?? 0})`],
            ["questions", `Questions (${assessment?.questions.length ?? 0})`],
            ["gaps", `Evidence Gaps (${assessment?.evidence_gaps.length ?? 0})`],
            ["conclusion", "Conclusion & Disposition"],
            ["briefing", "Briefing & Handoff"],
          ] as const
        ).map(([tabKey, label]) => (
          <button
            key={tabKey}
            onClick={() => setActiveTab(tabKey)}
            className={`px-3 py-2 border-b-2 font-medium transition-colors whitespace-nowrap ${
              activeTab === tabKey
                ? "border-[#5ED492] text-[#EDEBE6]"
                : "border-transparent text-[#8C8A82] hover:text-[#D4D2CD]"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Main Tab Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {loading && !assessment ? (
          <div className="flex items-center justify-center h-48 text-[#8C8A82]">
            <RefreshIcon className="w-5 h-5 animate-spin mr-2" />
            Synthesizing case assessment...
          </div>
        ) : !assessment ? (
          <div className="text-center py-12 text-[#8C8A82]">
            No assessment available. Click Synthesize to analyze case evidence.
          </div>
        ) : (
          <>
            {/* SUB-VIEW 1: OVERVIEW */}
            {activeTab === "overview" && (
              <div className="space-y-4">
                {/* Readiness & Sufficiency Cards */}
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 bg-[#22221F] rounded border border-[#2E2E2A]">
                    <div className="text-[#8C8A82] uppercase text-[10px] font-mono tracking-wider mb-1">
                      Closure Readiness State
                    </div>
                    <div className="text-base font-semibold text-[#EDEBE6] mb-1 font-mono">
                      {assessment.closure_readiness.status}
                    </div>
                    <p className="text-[#A8A69E] text-[11px] leading-relaxed">
                      {assessment.closure_readiness.summary}
                    </p>
                    {assessment.closure_readiness.blocking_factors.length > 0 && (
                      <div className="mt-2.5 pt-2 border-t border-[#2E2E2A]">
                        <span className="font-mono text-[10px] text-[#FF7A70] uppercase font-semibold">
                          Blocking Factors:
                        </span>
                        <ul className="list-disc list-inside mt-1 space-y-0.5 text-[#FF7A70] text-[11px]">
                          {assessment.closure_readiness.blocking_factors.map((b, i) => (
                            <li key={i}>{b}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>

                  <div className="p-3 bg-[#22221F] rounded border border-[#2E2E2A]">
                    <div className="text-[#8C8A82] uppercase text-[10px] font-mono tracking-wider mb-1">
                      Evidence Sufficiency Evaluation
                    </div>
                    <div className="text-base font-semibold text-[#EDEBE6] mb-1 font-mono">
                      {assessment.evidence_sufficiency.status}
                    </div>
                    <p className="text-[#A8A69E] text-[11px] leading-relaxed">
                      {assessment.evidence_sufficiency.rationale}
                    </p>
                    {assessment.evidence_sufficiency.missing_evidence.length > 0 && (
                      <div className="mt-2.5 pt-2 border-t border-[#2E2E2A]">
                        <span className="font-mono text-[10px] text-[#F5C242] uppercase font-semibold">
                          Missing Telemetry / Remedies:
                        </span>
                        <ul className="list-disc list-inside mt-1 space-y-0.5 text-[#A8A69E] text-[11px]">
                          {assessment.evidence_sufficiency.missing_evidence.map((m, i) => (
                            <li key={i}>{m}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                </div>

                {/* Epistemic Summary Census */}
                <div className="p-3 bg-[#22221F] rounded border border-[#2E2E2A]">
                  <div className="text-[#8C8A82] uppercase text-[10px] font-mono tracking-wider mb-2">
                    Epistemic Demarcation Census
                  </div>
                  <div className="grid grid-cols-4 gap-2 text-center">
                    <div className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A]">
                      <div className="text-lg font-mono font-bold text-[#EDEBE6]">
                        {assessment.epistemic_summary.total_findings ?? 0}
                      </div>
                      <div className="text-[10px] text-[#8C8A82]">Total Findings</div>
                    </div>
                    <div className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A]">
                      <div className="text-lg font-mono font-bold text-[#5ED492]">
                        {assessment.epistemic_summary.observed ?? 0}
                      </div>
                      <div className="text-[10px] text-[#5ED492]">OBSERVED (Authoritative)</div>
                    </div>
                    <div className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A]">
                      <div className="text-lg font-mono font-bold text-[#F5C242]">
                        {assessment.epistemic_summary.inferred ?? 0}
                      </div>
                      <div className="text-[10px] text-[#F5C242]">INFERRED (Analytical)</div>
                    </div>
                    <div className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A]">
                      <div className="text-lg font-mono font-bold text-[#8C8A82]">
                        {assessment.epistemic_summary.unknown ?? 0}
                      </div>
                      <div className="text-[10px] text-[#8C8A82]">UNKNOWN (Indeterminate)</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* SUB-VIEW 2: FINDINGS */}
            {activeTab === "findings" && (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-xs text-[#8C8A82] px-1">
                  <span>Structured Case Findings ({assessment.key_findings.length})</span>
                  <span className="font-mono text-[10px]">
                    Epistemic status is independent of Analyst Review state
                  </span>
                </div>
                {assessment.key_findings.map((f) => (
                  <div
                    key={f.finding_id}
                    className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-2"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <div className="font-medium text-[#EDEBE6] text-xs">{f.title}</div>
                        <div className="text-[#A8A69E] text-[11px] mt-0.5">{f.description}</div>
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <span
                          className={`px-1.5 py-0.5 rounded font-mono text-[9px] uppercase border ${
                            f.epistemic_status === "OBSERVED"
                              ? "bg-[#1E3A2A] text-[#5ED492] border-[#2A523A]"
                              : f.epistemic_status === "INFERRED"
                              ? "bg-[#3D331A] text-[#F5C242] border-[#5A4B24]"
                              : "bg-[#2A2A26] text-[#8C8A82] border-[#3A3A34]"
                          }`}
                        >
                          {f.epistemic_status}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded font-mono text-[9px] uppercase border ${
                            f.review_state === "ACCEPTED"
                              ? "bg-[#1E3A2A] text-[#5ED492] border-[#2A523A]"
                              : f.review_state === "REJECTED"
                              ? "bg-[#3A1E1E] text-[#FF7A70] border-[#5A2A2A]"
                              : f.review_state === "DISPUTED"
                              ? "bg-[#3D331A] text-[#F5C242] border-[#5A4B24]"
                              : "bg-[#2A2A26] text-[#A8A69E] border-[#3A3A34]"
                          }`}
                        >
                          {f.review_state}
                        </span>
                      </div>
                    </div>

                    {/* Citations & Evidence References */}
                    {f.evidence_references.length > 0 && (
                      <div className="flex items-center gap-1 text-[10px] font-mono text-[#8C8A82]">
                        <span>Citations:</span>
                        {f.evidence_references.map((c, i) => (
                          <span
                            key={i}
                            className="px-1 py-0.5 bg-[#1A1A18] rounded text-[#5ED492] border border-[#2E2E2A]"
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Review Actions */}
                    <div className="flex items-center justify-between pt-2 border-t border-[#2E2E2A] text-[10px]">
                      <span className="text-[#6E6D66] font-mono">ID: {f.finding_id}</span>
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => handleReviewFinding(f.finding_id, "ACCEPTED")}
                          className="px-2 py-0.5 bg-[#1E3A2A] hover:bg-[#2A523A] text-[#5ED492] rounded transition-colors"
                        >
                          Accept
                        </button>
                        <button
                          onClick={() => handleReviewFinding(f.finding_id, "DISPUTED")}
                          className="px-2 py-0.5 bg-[#3D331A] hover:bg-[#5A4B24] text-[#F5C242] rounded transition-colors"
                        >
                          Dispute
                        </button>
                        <button
                          onClick={() => handleReviewFinding(f.finding_id, "REJECTED")}
                          className="px-2 py-0.5 bg-[#3A1E1E] hover:bg-[#5A2A2A] text-[#FF7A70] rounded transition-colors"
                        >
                          Reject
                        </button>
                        <button
                          onClick={() => handleExplain(f.finding_id)}
                          className="px-2 py-0.5 bg-[#2A2A26] hover:bg-[#34342E] text-[#D4D2CD] rounded transition-colors"
                        >
                          AI Explain
                        </button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* SUB-VIEW 3: HYPOTHESES */}
            {activeTab === "hypotheses" && (
              <div className="space-y-3">
                <div className="text-xs text-[#8C8A82] px-1">
                  Competing Hypotheses Evaluation ({assessment.hypotheses.length})
                </div>
                {assessment.hypotheses.map((h) => (
                  <div
                    key={h.hypothesis_id}
                    className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-2"
                  >
                    <div className="flex items-start justify-between">
                      <div className="font-medium text-[#EDEBE6] text-xs">{h.statement}</div>
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono text-[9px] uppercase border ${
                          h.determination === "SUPPORTING"
                            ? "bg-[#1E3A2A] text-[#5ED492] border-[#2A523A]"
                            : h.determination === "CONTRADICTING"
                            ? "bg-[#3A1E1E] text-[#FF7A70] border-[#5A2A2A]"
                            : "bg-[#2A2A26] text-[#A8A69E] border-[#3A3A34]"
                        }`}
                      >
                        {h.determination}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-2 text-[11px] pt-1">
                      <div className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A]">
                        <span className="font-mono text-[9px] text-[#5ED492] uppercase font-semibold">
                          Supporting Evidence ({h.supporting_evidence.length}):
                        </span>
                        {h.supporting_evidence.length > 0 ? (
                          <ul className="list-disc list-inside mt-1 space-y-0.5 text-[#A8A69E]">
                            {h.supporting_evidence.map((s, i) => (
                              <li key={i}>{s}</li>
                            ))}
                          </ul>
                        ) : (
                          <div className="text-[#6E6D66] mt-0.5">None cited</div>
                        )}
                      </div>

                      <div className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A]">
                        <span className="font-mono text-[9px] text-[#FF7A70] uppercase font-semibold">
                          Contradicting Evidence ({h.contradicting_evidence.length}):
                        </span>
                        {h.contradicting_evidence.length > 0 ? (
                          <ul className="list-disc list-inside mt-1 space-y-0.5 text-[#A8A69E]">
                            {h.contradicting_evidence.map((c, i) => (
                              <li key={i}>{c}</li>
                            ))}
                          </ul>
                        ) : (
                          <div className="text-[#6E6D66] mt-0.5">None cited</div>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* SUB-VIEW 4: QUESTIONS */}
            {activeTab === "questions" && (
              <div className="space-y-3">
                {/* Add question form */}
                <form
                  onSubmit={handleCreateQuestion}
                  className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-2"
                >
                  <div className="font-mono text-[10px] text-[#8C8A82] uppercase font-semibold">
                    Add Structured Investigation Question
                  </div>
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={newQuestion}
                      onChange={(e) => setNewQuestion(e.target.value)}
                      placeholder="e.g. Was process execution local or invoked via SSH?"
                      className="flex-1 px-2.5 py-1.5 bg-[#1A1A18] border border-[#2E2E2A] rounded text-xs text-[#EDEBE6] focus:outline-none focus:border-[#5ED492]"
                    />
                    <select
                      value={newQuestionCategory}
                      onChange={(e) => setNewQuestionCategory(e.target.value)}
                      className="px-2 py-1.5 bg-[#1A1A18] border border-[#2E2E2A] rounded text-xs text-[#EDEBE6]"
                    >
                      <option value="AUTHENTICATION">AUTHENTICATION</option>
                      <option value="EXECUTION">EXECUTION</option>
                      <option value="LATERAL_MOVEMENT">LATERAL_MOVEMENT</option>
                      <option value="PERSISTENCE">PERSISTENCE</option>
                      <option value="DATA_EXFILTRATION">DATA_EXFILTRATION</option>
                      <option value="TEMPORAL_GAP">TEMPORAL_GAP</option>
                      <option value="IDENTITY_CONTINUITY">IDENTITY_CONTINUITY</option>
                      <option value="HOST_ATTRIBUTION">HOST_ATTRIBUTION</option>
                      <option value="AUTHORIZATION">AUTHORIZATION</option>
                    </select>
                    <button
                      type="submit"
                      className="px-3 py-1.5 bg-[#5ED492] hover:bg-[#4EBD80] text-[#1A1A18] font-medium rounded transition-colors"
                    >
                      Add Question
                    </button>
                  </div>
                  <input
                    type="text"
                    value={newQuestionQuery}
                    onChange={(e) => setNewQuestionQuery(e.target.value)}
                    placeholder="Optional recommended governed query (SELECT ... FROM events WHERE ...)"
                    className="w-full px-2.5 py-1 bg-[#1A1A18] border border-[#2E2E2A] rounded text-[11px] font-mono text-[#A8A69E]"
                  />
                </form>

                {/* List questions */}
                {assessment.questions.map((q) => (
                  <div
                    key={q.question_id}
                    className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-1.5"
                  >
                    <div className="flex items-start justify-between">
                      <div>
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-[#1A1A18] text-[#8C8A82] border border-[#2E2E2A] mr-2">
                          {q.category}
                        </span>
                        <span className="font-medium text-[#EDEBE6] text-xs">{q.question}</span>
                      </div>
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono text-[9px] uppercase border ${
                          q.status === "ANSWERED"
                            ? "bg-[#1E3A2A] text-[#5ED492] border-[#2A523A]"
                            : q.status === "OPEN"
                            ? "bg-[#3D331A] text-[#F5C242] border-[#5A4B24]"
                            : "bg-[#2A2A26] text-[#8C8A82] border-[#3A3A34]"
                        }`}
                      >
                        {q.status}
                      </span>
                    </div>

                    {q.recommended_query && (
                      <div className="p-1.5 bg-[#1A1A18] rounded font-mono text-[10px] text-[#A8A69E] border border-[#2E2E2A]">
                        Recommended Query: {q.recommended_query}
                      </div>
                    )}

                    <div className="flex items-center justify-between pt-1 text-[10px]">
                      <span className="text-[#6E6D66] font-mono">ID: {q.question_id}</span>
                      <div className="flex items-center gap-1.5">
                        {q.status !== "ANSWERED" && (
                          <button
                            onClick={() => handleUpdateQuestionStatus(q.question_id, "ANSWERED")}
                            className="px-2 py-0.5 bg-[#1E3A2A] text-[#5ED492] rounded hover:bg-[#2A523A]"
                          >
                            Mark Answered
                          </button>
                        )}
                        {q.status !== "UNRESOLVED" && (
                          <button
                            onClick={() => handleUpdateQuestionStatus(q.question_id, "UNRESOLVED")}
                            className="px-2 py-0.5 bg-[#2A2A26] text-[#A8A69E] rounded hover:bg-[#34342E]"
                          >
                            Mark Unresolved
                          </button>
                        )}
                        {q.status !== "NOT_APPLICABLE" && (
                          <button
                            onClick={() => handleUpdateQuestionStatus(q.question_id, "NOT_APPLICABLE")}
                            className="px-2 py-0.5 bg-[#2A2A26] text-[#8C8A82] rounded hover:bg-[#34342E]"
                          >
                            Mark N/A
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* SUB-VIEW 5: EVIDENCE GAPS */}
            {activeTab === "gaps" && (
              <div className="space-y-3">
                <div className="text-xs text-[#8C8A82] px-1">
                  Prioritized Evidence Gaps & Governed Remedies ({assessment.evidence_gaps.length})
                </div>
                {assessment.evidence_gaps.map((g) => (
                  <div
                    key={g.gap_id}
                    className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-1.5"
                  >
                    <div className="flex items-start justify-between">
                      <div className="font-medium text-[#EDEBE6] text-xs">{g.title}</div>
                      <span
                        className={`px-1.5 py-0.5 rounded font-mono text-[9px] uppercase border ${
                          g.priority === "CRITICAL"
                            ? "bg-[#3A1E1E] text-[#FF7A70] border-[#5A2A2A]"
                            : g.priority === "HIGH"
                            ? "bg-[#3D331A] text-[#F5C242] border-[#5A4B24]"
                            : "bg-[#2A2A26] text-[#A8A69E] border-[#3A3A34]"
                        }`}
                      >
                        Priority: {g.priority}
                      </span>
                    </div>
                    <p className="text-[#A8A69E] text-[11px]">{g.explanation}</p>
                    <div className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A] text-[11px]">
                      <span className="font-mono text-[9px] text-[#5ED492] uppercase font-semibold">
                        Remedy / Hunt Query:
                      </span>
                      <div className="font-mono text-[10px] text-[#EDEBE6] mt-0.5">{g.remedy}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* SUB-VIEW 6: CONCLUSION */}
            {activeTab === "conclusion" && (
              <div className="space-y-4">
                <div className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] text-[#8C8A82] uppercase font-semibold">
                      Evidence-Backed Case Conclusion
                    </span>
                    <span className="px-1.5 py-0.5 rounded font-mono text-[9px] uppercase bg-[#1A1A18] text-[#5ED492] border border-[#2E2E2A]">
                      Epistemic: {assessment.conclusion.epistemic_status}
                    </span>
                  </div>
                  <p className="text-sm font-medium text-[#EDEBE6] leading-relaxed">
                    {assessment.conclusion.statement}
                  </p>
                  {assessment.conclusion.supporting_evidence.length > 0 && (
                    <div className="pt-2 border-t border-[#2E2E2A] text-[11px]">
                      <span className="font-mono text-[9px] text-[#5ED492] uppercase font-semibold">
                        Supporting Evidence Citations:
                      </span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {assessment.conclusion.supporting_evidence.map((c, i) => (
                          <span
                            key={i}
                            className="px-1.5 py-0.5 rounded bg-[#1A1A18] text-[#5ED492] font-mono text-[10px] border border-[#2E2E2A]"
                          >
                            {c}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Analyst assessment authoring box */}
                <div className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-[10px] text-[#8C8A82] uppercase font-semibold">
                      Analyst-Authored Case Assessment & Rationale
                    </span>
                    <span className="font-mono text-[9px] text-[#A8A69E]">Origin: ANALYST_AUTHORED</span>
                  </div>
                  <textarea
                    rows={4}
                    value={analystNote}
                    onChange={(e) => setAnalystNote(e.target.value)}
                    placeholder="Enter formal analyst assessment, investigative findings, or closure justification..."
                    className="w-full p-2.5 bg-[#1A1A18] border border-[#2E2E2A] rounded text-xs text-[#EDEBE6] font-mono focus:outline-none focus:border-[#5ED492]"
                  />
                  <div className="flex justify-end">
                    <button
                      onClick={handleSaveAnalystAssessment}
                      className="px-3 py-1.5 bg-[#5ED492] hover:bg-[#4EBD80] text-[#1A1A18] font-medium rounded transition-colors text-xs"
                    >
                      Save Analyst Assessment
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* SUB-VIEW 7: BRIEFING & HANDOFF */}
            {activeTab === "briefing" && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[#8C8A82]">
                    Structured 15-Section Investigation Briefing & Provenance
                  </span>
                  <button
                    onClick={handleGenerateHandoff}
                    className="px-2.5 py-1 rounded bg-[#2A2A26] hover:bg-[#34342E] text-[#D4D2CD] border border-[#3A3A34] text-xs transition-colors"
                  >
                    Generate Handoff Package
                  </button>
                </div>

                {briefing && (
                  <div className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-3">
                    <div className="font-mono text-[11px] text-[#5ED492] font-semibold border-b border-[#2E2E2A] pb-1.5">
                      BRIEFING #{briefing.briefing_id} — READINESS: {briefing.closure_readiness}
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      {Object.entries(briefing.sections).map(([title, content]) => (
                        <div key={title} className="p-2 bg-[#1A1A18] rounded border border-[#2E2E2A]">
                          <div className="font-mono text-[10px] text-[#A8A69E] uppercase font-semibold mb-1">
                            {title}
                          </div>
                          <div className="text-[11px] text-[#D4D2CD] leading-relaxed">{content}</div>
                        </div>
                      ))}
                    </div>
                    <div className="font-mono text-[9px] text-[#6E6D66] pt-1">
                      Provenance Hash: {briefing.provenance_hash} | Generated at {briefing.generated_at}
                    </div>
                  </div>
                )}

                {handoff && (
                  <div className="p-3 bg-[#22221F] rounded border border-[#2E2E2A] space-y-2">
                    <div className="font-mono text-[11px] text-[#F5C242] font-semibold">
                      ANALYST HANDOFF PACKAGE — {handoff.handoff_id}
                    </div>
                    <div className="text-xs text-[#D4D2CD]">{handoff.case_summary}</div>
                    <div className="text-[11px] text-[#A8A69E]">
                      Operator: <span className="font-mono text-[#EDEBE6]">{handoff.operator}</span> |
                      State: <span className="font-mono text-[#EDEBE6]">{handoff.current_state}</span>
                    </div>
                    <div className="pt-2 border-t border-[#2E2E2A]">
                      <span className="font-mono text-[10px] text-[#5ED492] uppercase font-semibold">
                        Required Next Actions:
                      </span>
                      <ul className="list-disc list-inside mt-1 space-y-0.5 text-[#A8A69E] text-[11px]">
                        {handoff.required_next_actions.map((act, idx) => (
                          <li key={idx}>{act}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
