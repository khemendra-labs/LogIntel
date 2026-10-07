import React, { useEffect, useState } from "react";
import {
  createCaseReportM76,
  listCaseReportsM76,
  getCurrentCaseReportM76,
  getCaseReportVersionM76,
  updateCaseReportDraftM76,
  submitCaseReportReviewM76,
  finalizeCaseReportM76,
  compareCaseReportsM76,
  exportCaseReportM76,
  requestAIReportDraftM76,
  createEvidencePackageM76,
  prepareCaseHandoffM76,
  acknowledgeCaseHandoffM76,
  returnCaseHandoffM76,
  getCurrentCaseHandoffM76,
} from "../lib/api";
import {
  StructuredReport,
  ReportVersionSummary,
  ReportComparisonResult,
  EvidencePackage,
  CaseHandoffPacket,
  ReportExportResponse,
  ReportLifecycleStatus,
} from "../types/investigation";

interface InvestigationReportWorkbenchProps {
  caseId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onPivotTimeline?: (timestamp: string) => void;
}

export function InvestigationReportWorkbench({
  caseId,
  onSelectEventId,
  onSelectAlertId,
  onPivotTimeline,
}: InvestigationReportWorkbenchProps) {
  const [activeTab, setActiveTab] = useState<
    "report" | "provenance" | "versions" | "package" | "handoff"
  >("report");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // --- Report State ---
  const [report, setReport] = useState<StructuredReport | null>(null);
  const [versions, setVersions] = useState<ReportVersionSummary[]>([]);
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null);

  // --- Draft Edit Form State ---
  const [editTitle, setEditTitle] = useState("");
  const [editExecutiveSummary, setEditExecutiveSummary] = useState("");
  const [editInterpretation, setEditInterpretation] = useState("");
  const [editConclusion, setEditConclusion] = useState("");
  const [editHandoffInstructions, setEditHandoffInstructions] = useState("");
  const [editNextActions, setEditNextActions] = useState("");
  const [editLimitations, setEditLimitations] = useState("");

  // --- Review & Finalize Form State ---
  const [reviewerName, setReviewerName] = useState("SecLead-1");
  const [reviewNotes, setReviewNotes] = useState("");
  const [finalizationNotes, setFinalizationNotes] = useState("");

  // --- AI Drafting Assistant ---
  const [aiSection, setAiSection] = useState("executive_summary");
  const [aiGuidance, setAiGuidance] = useState("");
  const [aiDraftResult, setAiDraftResult] = useState<string | null>(null);
  const [aiLoading, setAiLoading] = useState(false);

  // --- Version Comparison State ---
  const [cmpOlder, setCmpOlder] = useState<number>(1);
  const [cmpNewer, setCmpNewer] = useState<number>(1);
  const [comparisonResult, setComparisonResult] = useState<ReportComparisonResult | null>(null);

  // --- Package & Export State ---
  const [evidencePackage, setEvidencePackage] = useState<EvidencePackage | null>(null);
  const [exportFormat, setExportFormat] = useState<"json" | "csv" | "markdown">("json");
  const [exportResult, setExportResult] = useState<ReportExportResponse | null>(null);

  // --- Handoff State ---
  const [currentHandoff, setCurrentHandoff] = useState<CaseHandoffPacket | null>(null);
  const [handoffTarget, setHandoffTarget] = useState("SecAnalyst-2");
  const [handoffNotes, setHandoffNotes] = useState("");
  const [returnReason, setReturnReason] = useState("");
  const [ackNotes, setAckNotes] = useState("");

  // --- Load Initial Data ---
  useEffect(() => {
    loadReportData();
  }, [caseId]);

  async function loadReportData(ver?: number) {
    setLoading(true);
    setError(null);
    try {
      // 1. Fetch versions list
      const vList = await listCaseReportsM76(caseId);
      setVersions(vList.versions || []);

      if (vList.versions && vList.versions.length > 0) {
        const targetVer = ver !== undefined ? ver : vList.versions[0].version;
        setSelectedVersion(targetVer);
        const rep = await getCaseReportVersionM76(caseId, targetVer);
        setReport(rep);
        syncFormState(rep);

        if (vList.versions.length >= 2) {
          setCmpOlder(vList.versions[vList.versions.length - 1].version);
          setCmpNewer(vList.versions[0].version);
        } else {
          setCmpOlder(targetVer);
          setCmpNewer(targetVer);
        }
      } else {
        // Automatically initialize a draft report if none exists
        const newRep = await createCaseReportM76(caseId, {
          title: `Investigation Report — Case #${caseId}`,
          objective: "Establish forensic timeline and root cause analysis",
        });
        setReport(newRep);
        setSelectedVersion(newRep.version);
        syncFormState(newRep);
        const updatedList = await listCaseReportsM76(caseId);
        setVersions(updatedList.versions || []);
      }

      // 2. Load active handoff
      try {
        const hnd = await getCurrentCaseHandoffM76(caseId);
        setCurrentHandoff(hnd);
      } catch {
        setCurrentHandoff(null);
      }
    } catch (err: any) {
      setError(err.message || "Failed to load investigation report data.");
    } finally {
      setLoading(false);
    }
  }

  function syncFormState(rep: StructuredReport) {
    setEditTitle(rep.case_identification.title || "");
    setEditExecutiveSummary(rep.executive_summary.summary_text || "");
    setEditInterpretation(rep.analyst_interpretation.interpretation_notes || "");
    setEditConclusion(rep.conclusion.current_conclusion || "");
    setEditHandoffInstructions(rep.handoff_notes.handoff_instructions || "");
    setEditNextActions((rep.handoff_notes.recommended_next_actions || []).join("\n"));
    setEditLimitations((rep.limitations.limitations || []).join("\n"));
  }

  // --- Handlers ---

  async function handleSaveDraft() {
    if (!report) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const nextActionsArr = editNextActions.split("\n").map((s) => s.trim()).filter(Boolean);
      const limitationsArr = editLimitations.split("\n").map((s) => s.trim()).filter(Boolean);
      const updated = await updateCaseReportDraftM76(caseId, report.report_id, {
        title: editTitle,
        executive_summary: editExecutiveSummary,
        analyst_interpretation: editInterpretation,
        conclusion: editConclusion,
        handoff_instructions: editHandoffInstructions,
        recommended_next_actions: nextActionsArr,
        limitations: limitationsArr,
      });
      setReport(updated);
      setSelectedVersion(updated.version);
      setSuccessMsg(`Report revision v${updated.version} saved successfully.`);
      const vList = await listCaseReportsM76(caseId);
      setVersions(vList.versions || []);
    } catch (err: any) {
      setError(err.message || "Failed to save report draft.");
    } finally {
      setLoading(false);
    }
  }

  async function handleSubmitReview() {
    if (!report) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const updated = await submitCaseReportReviewM76(caseId, report.report_id, {
        review_notes: reviewNotes,
      });
      setReport(updated);
      setSelectedVersion(updated.version);
      setSuccessMsg(`Report submitted for review as v${updated.version} (REVIEW_READY).`);
      const vList = await listCaseReportsM76(caseId);
      setVersions(vList.versions || []);
    } catch (err: any) {
      setError(err.message || "Failed to submit report for review.");
    } finally {
      setLoading(false);
    }
  }

  async function handleFinalizeReport() {
    if (!report) return;
    if (!reviewerName.trim()) {
      setError("Reviewer identity is required to finalize report.");
      return;
    }
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const updated = await finalizeCaseReportM76(caseId, report.report_id, {
        reviewed_by: reviewerName.trim(),
        finalization_notes: finalizationNotes,
      });
      setReport(updated);
      setSelectedVersion(updated.version);
      setSuccessMsg(`Report version v${updated.version} FINALIZED. Content is now frozen.`);
      const vList = await listCaseReportsM76(caseId);
      setVersions(vList.versions || []);
    } catch (err: any) {
      setError(err.message || "Failed to finalize report.");
    } finally {
      setLoading(false);
    }
  }

  async function handleRequestAIDraft() {
    setAiLoading(true);
    setError(null);
    try {
      const res = await requestAIReportDraftM76(caseId, {
        section_to_draft: aiSection,
        custom_guidance: aiGuidance,
      });
      setAiDraftResult(res.draft_text);
    } catch (err: any) {
      setError(err.message || "AI drafting failed.");
    } finally {
      setAiLoading(false);
    }
  }

  function handleApplyAIDraft() {
    if (!aiDraftResult) return;
    if (aiSection === "executive_summary") {
      setEditExecutiveSummary(aiDraftResult);
    } else if (aiSection === "analyst_interpretation") {
      setEditInterpretation(aiDraftResult);
    } else if (aiSection === "conclusion") {
      setEditConclusion(aiDraftResult);
    } else if (aiSection === "handoff_notes") {
      setEditHandoffInstructions(aiDraftResult);
    }
    setAiDraftResult(null);
    setSuccessMsg(`Applied AI draft to ${aiSection}.`);
  }

  async function handleCompareVersions() {
    setLoading(true);
    setError(null);
    try {
      const cmp = await compareCaseReportsM76(caseId, cmpOlder, cmpNewer);
      setComparisonResult(cmp);
    } catch (err: any) {
      setError(err.message || "Comparison failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleGeneratePackage() {
    if (!report) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const pkg = await createEvidencePackageM76(caseId, {
        report_version: report.version,
        package_notes: "Analyst generated evidence package",
      });
      setEvidencePackage(pkg);
      setSuccessMsg(`Evidence package ${pkg.manifest.package_id} generated successfully.`);
    } catch (err: any) {
      setError(err.message || "Package generation failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleExport() {
    if (!report) return;
    setLoading(true);
    setError(null);
    try {
      const exp = await exportCaseReportM76(caseId, report.version, exportFormat);
      setExportResult(exp);
      setSuccessMsg(`Exported report in ${exportFormat.toUpperCase()} format.`);
    } catch (err: any) {
      setError(err.message || "Export failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handlePrepareHandoff() {
    if (!report) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const hnd = await prepareCaseHandoffM76(caseId, {
        target_operator: handoffTarget,
        report_version: report.version,
        operational_notes: handoffNotes,
      });
      setCurrentHandoff(hnd);
      setSuccessMsg(`Case handoff packet ${hnd.handoff_id} prepared for ${handoffTarget}.`);
    } catch (err: any) {
      setError(err.message || "Prepare handoff failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleAcknowledgeHandoff() {
    if (!currentHandoff) return;
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const updated = await acknowledgeCaseHandoffM76(caseId, currentHandoff.handoff_id, {
        acknowledgement_notes: ackNotes,
      });
      setCurrentHandoff(updated);
      setSuccessMsg("Case custody acknowledged.");
    } catch (err: any) {
      setError(err.message || "Acknowledgement failed.");
    } finally {
      setLoading(false);
    }
  }

  async function handleReturnHandoff() {
    if (!currentHandoff) return;
    if (!returnReason.trim()) {
      setError("Return reason is required.");
      return;
    }
    setLoading(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const updated = await returnCaseHandoffM76(caseId, currentHandoff.handoff_id, {
        return_reason: returnReason.trim(),
      });
      setCurrentHandoff(updated);
      setSuccessMsg("Case returned for followup.");
    } catch (err: any) {
      setError(err.message || "Return failed.");
    } finally {
      setLoading(false);
    }
  }

  // --- Sub-View: 20-Section Document Explorer & Editor ---
  function renderReportView() {
    if (!report) {
      return (
        <div className="p-8 text-center text-stone-500 font-mono text-sm">
          No investigation report available. Initializing draft...
        </div>
      );
    }

    const isFinal = report.lifecycle_status === "FINALIZED";

    return (
      <div className="grid grid-cols-12 gap-6">
        {/* Left Navigator (20 Sections) */}
        <div className="col-span-3 border-r border-stone-200 pr-4 space-y-2 text-xs font-mono">
          <div className="font-semibold text-stone-700 uppercase tracking-wider mb-2">
            Report Sections (20)
          </div>
          <nav className="space-y-1">
            {[
              "1. Case Identification",
              "2. Investigation Scope",
              "3. Executive Summary",
              "4. Investigation Objective",
              "5. Evidence Sources",
              "6. Evidence Collections",
              "7. Unified Timeline",
              "8. Key Findings",
              "9. Hypotheses",
              "10. Threat Hunts",
              "11. Evidence Correlation",
              "12. Case Assessment",
              "13. Evidence Gaps",
              "14. Outstanding Questions",
              "15. Analyst Interpretation",
              "16. Conclusion",
              "17. Limitations",
              "18. Handoff Notes",
              "19. Provenance Manifest",
              "20. Report Metadata",
            ].map((sec, idx) => (
              <a
                key={idx}
                href={`#sec-${idx + 1}`}
                className="block p-1.5 rounded hover:bg-stone-100 text-stone-600 hover:text-stone-900 truncate"
              >
                {sec}
              </a>
            ))}
          </nav>

          {/* AI Drafting Assistant Trigger */}
          <div className="mt-6 pt-4 border-t border-stone-200">
            <div className="font-semibold text-stone-700 uppercase tracking-wider mb-2">
              Advisory AI Draft
            </div>
            <select
              value={aiSection}
              onChange={(e) => setAiSection(e.target.value)}
              className="w-full text-xs bg-white border border-stone-300 rounded p-1 mb-2 font-mono"
              disabled={isFinal}
            >
              <option value="executive_summary">Executive Summary</option>
              <option value="analyst_interpretation">Analyst Interpretation</option>
              <option value="conclusion">Conclusion</option>
              <option value="handoff_notes">Handoff Notes</option>
            </select>
            <textarea
              value={aiGuidance}
              onChange={(e) => setAiGuidance(e.target.value)}
              placeholder="Optional analyst guidance..."
              className="w-full text-xs bg-white border border-stone-300 rounded p-1.5 mb-2 h-16 font-sans resize-none"
              disabled={isFinal}
            />
            <button
              onClick={handleRequestAIDraft}
              disabled={aiLoading || isFinal}
              className="w-full py-1 text-xs bg-stone-800 text-stone-100 rounded hover:bg-stone-700 disabled:opacity-50 font-medium"
            >
              {aiLoading ? "Drafting..." : "Generate Advisory Draft"}
            </button>
            {aiDraftResult && (
              <div className="mt-3 p-2 bg-stone-50 border border-stone-200 rounded text-xs">
                <div className="font-semibold text-stone-700 mb-1">Generated Draft:</div>
                <div className="text-stone-600 mb-2 whitespace-pre-wrap">{aiDraftResult}</div>
                <button
                  onClick={handleApplyAIDraft}
                  className="w-full py-1 text-xs bg-emerald-700 text-white rounded hover:bg-emerald-600 font-medium"
                >
                  Apply to Draft
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Center: Structured Document View & Editable Fields */}
        <div className="col-span-9 space-y-6 max-h-[75vh] overflow-y-auto pr-2">
          {/* Header Card */}
          <div className="bg-stone-50 border border-stone-200 rounded p-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-mono font-bold text-stone-500 uppercase tracking-wider">
                  CASE #{report.case_id} — INVESTIGATION REPORT
                </span>
                <h2 className="text-xl font-bold text-stone-900 mt-0.5">
                  {report.case_identification.title}
                </h2>
              </div>
              <div className="flex items-center space-x-3 text-right">
                <div>
                  <span
                    className={`inline-block px-2.5 py-0.5 text-xs font-mono font-bold rounded ${
                      report.lifecycle_status === "FINALIZED"
                        ? "bg-emerald-100 text-emerald-800 border border-emerald-300"
                        : report.lifecycle_status === "REVIEW_READY"
                        ? "bg-amber-100 text-amber-800 border border-amber-300"
                        : "bg-stone-200 text-stone-800 border border-stone-300"
                    }`}
                  >
                    {report.lifecycle_status}
                  </span>
                  <div className="text-xs text-stone-500 font-mono mt-1">
                    v{report.version} • {report.created_by}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-3 pt-3 border-t border-stone-200 flex items-center justify-between text-xs text-stone-500 font-mono">
              <div>Fingerprint: <span className="text-stone-700">{report.metadata.blake2b_fingerprint.slice(0, 16)}...</span></div>
              <div>Provenance Sources: <span className="font-bold text-stone-800">{report.provenance_manifest.total_references}</span></div>
              <div>Updated: {report.updated_at.slice(0, 19)}</div>
            </div>
          </div>

          {/* 1. Case Identification */}
          <section id="sec-1" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              1. Case Identification
            </h3>
            <div className="grid grid-cols-4 gap-4 bg-white border border-stone-200 rounded p-3 text-xs font-mono">
              <div><span className="text-stone-500">Case ID:</span> #{report.case_identification.case_id}</div>
              <div><span className="text-stone-500">Incident:</span> #{report.case_identification.incident_id}</div>
              <div><span className="text-stone-500">Owner:</span> {report.case_identification.owner}</div>
              <div><span className="text-stone-500">Status:</span> {report.case_identification.status}</div>
            </div>
          </section>

          {/* 2. Investigation Scope */}
          <section id="sec-2" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              2. Investigation Scope
            </h3>
            <div className="bg-white border border-stone-200 rounded p-3 text-xs space-y-1">
              <div><strong className="text-stone-700">Scoped Hosts:</strong> {report.investigation_scope.hosts.join(", ") || "None specified"}</div>
              <div><strong className="text-stone-700">Scoped Users:</strong> {report.investigation_scope.users.join(", ") || "None specified"}</div>
              <div><strong className="text-stone-700">Boundary Notes:</strong> {report.investigation_scope.boundary_notes || "N/A"}</div>
            </div>
          </section>

          {/* 3. Executive Summary */}
          <section id="sec-3" className="border-b border-stone-200 pb-4">
            <div className="flex items-center justify-between mb-2">
              <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider">
                3. Executive Summary
              </h3>
              <span className="text-xs font-mono text-stone-500">
                Origin: {report.executive_summary.content_origin}
              </span>
            </div>
            {isFinal ? (
              <div className="p-3 bg-stone-50 border border-stone-200 rounded text-sm text-stone-800 whitespace-pre-wrap">
                {report.executive_summary.summary_text}
              </div>
            ) : (
              <textarea
                value={editExecutiveSummary}
                onChange={(e) => setEditExecutiveSummary(e.target.value)}
                rows={4}
                className="w-full text-sm p-3 bg-white border border-stone-300 rounded font-sans focus:outline-none focus:ring-1 focus:ring-stone-500"
              />
            )}
          </section>

          {/* 4. Investigation Objective */}
          <section id="sec-4" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              4. Investigation Objective
            </h3>
            <div className="bg-white border border-stone-200 rounded p-3 text-xs space-y-1">
              <div><strong className="text-stone-700">Objective:</strong> {report.investigation_objective.primary_objective}</div>
            </div>
          </section>

          {/* 5. Evidence Sources */}
          <section id="sec-5" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              5. Evidence Sources
            </h3>
            <div className="bg-white border border-stone-200 rounded p-3 text-xs font-mono flex items-center justify-between">
              <div>Sources: {report.evidence_sources.sources_inspected.join(", ")}</div>
              <div>Total Telemetry Considered: {report.evidence_sources.total_telemetry_events_considered}</div>
            </div>
          </section>

          {/* 6. Evidence Collections */}
          <section id="sec-6" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              6. Evidence Collections ({report.evidence_collections.collections.length})
            </h3>
            {report.evidence_collections.collections.length === 0 ? (
              <div className="text-xs text-stone-500 italic">No collections attached.</div>
            ) : (
              <div className="space-y-2">
                {report.evidence_collections.collections.map((c, i) => (
                  <div key={i} className="p-2.5 bg-white border border-stone-200 rounded text-xs font-mono">
                    <div className="font-bold text-stone-800">{c.name || c.collection_id}</div>
                    <div className="text-stone-500">{c.description || "No description"}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* 7. Unified Timeline */}
          <section id="sec-7" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              7. Unified Timeline ({report.unified_timeline_summary.milestones.length} Events)
            </h3>
            <div className="max-h-48 overflow-y-auto space-y-1.5 font-mono text-xs">
              {report.unified_timeline_summary.milestones.map((m, idx) => (
                <div key={idx} className="p-2 bg-white border border-stone-200 rounded flex justify-between items-center">
                  <div>
                    <span className="font-bold text-stone-800">[{m.source_type}]</span> {m.citation_tag}
                    {m.annotation && <span className="text-stone-600 block text-xs">{m.annotation}</span>}
                  </div>
                  <span className="text-stone-500">{m.timestamp ? m.timestamp.slice(0, 19) : ""}</span>
                </div>
              ))}
            </div>
          </section>

          {/* 8. Key Findings */}
          <section id="sec-8" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              8. Key Findings ({report.key_findings.findings.length})
            </h3>
            {report.key_findings.findings.length === 0 ? (
              <div className="text-xs text-stone-500 italic">No findings recorded.</div>
            ) : (
              <div className="space-y-2">
                {report.key_findings.findings.map((f, i) => (
                  <div key={i} className="p-3 bg-white border border-stone-200 rounded text-xs">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-stone-900">{f.title || f.finding_id}</span>
                      <span className="px-2 py-0.5 bg-stone-100 border border-stone-300 font-mono text-stone-700 rounded">
                        {f.epistemic_status || "UNKNOWN"}
                      </span>
                    </div>
                    <div className="text-stone-700">{f.description || f.statement}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* 9. Hypotheses */}
          <section id="sec-9" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              9. Hypotheses ({report.hypotheses.hypotheses.length})
            </h3>
            {report.hypotheses.hypotheses.length === 0 ? (
              <div className="text-xs text-stone-500 italic">No hypotheses recorded.</div>
            ) : (
              <div className="space-y-2">
                {report.hypotheses.hypotheses.map((h, i) => (
                  <div key={i} className="p-2.5 bg-white border border-stone-200 rounded text-xs">
                    <div className="font-bold text-stone-800">{h.statement || h.hypothesis_id}</div>
                    <div className="text-stone-500 text-xs mt-1">Status: {h.status || "OPEN"}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* 10. Threat Hunts */}
          <section id="sec-10" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              10. Threat Hunting Activity ({report.threat_hunting_activity.hunts_executed.length})
            </h3>
            {report.threat_hunting_activity.hunts_executed.length === 0 ? (
              <div className="text-xs text-stone-500 italic">No governed hunts executed.</div>
            ) : (
              <div className="space-y-2">
                {report.threat_hunting_activity.hunts_executed.map((ht, i) => (
                  <div key={i} className="p-2.5 bg-white border border-stone-200 rounded text-xs font-mono">
                    <div className="font-bold text-stone-800">Hunt #{ht.hunt_id}: {ht.intent}</div>
                    <div className="text-stone-600">Results: {ht.result_count} • Executed by: {ht.executed_by}</div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* 11. Evidence Correlation */}
          <section id="sec-11" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              11. Evidence Correlation
            </h3>
            <div className="text-xs text-stone-500 italic">
              {report.evidence_correlation.correlated_clusters.length} clusters correlated.
            </div>
          </section>

          {/* 12. Case Assessment */}
          <section id="sec-12" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              12. Case Assessment
            </h3>
            <div className="bg-white border border-stone-200 rounded p-3 text-xs space-y-1 font-mono">
              <div>Assessment State: {report.case_assessment.assessment_state || "DRAFT"}</div>
              <div>Closure Readiness: {report.case_assessment.closure_readiness || "UNKNOWN"}</div>
              {report.case_assessment.analyst_assessment_text && (
                <div className="font-sans text-stone-700 mt-2">{report.case_assessment.analyst_assessment_text}</div>
              )}
            </div>
          </section>

          {/* 13. Evidence Gaps */}
          <section id="sec-13" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              13. Evidence Gaps & Epistemic Boundaries
            </h3>
            <div className="p-2.5 bg-amber-50 border border-amber-200 rounded text-xs text-amber-900 mb-2 font-medium">
              Forensic Invariant: Absence of telemetry is not evidence of absence.
            </div>
            <div className="space-y-2">
              {report.evidence_gaps.gaps.map((g, i) => (
                <div key={i} className="p-2 bg-white border border-stone-200 rounded text-xs">
                  <span className="font-mono font-bold text-stone-700">[{g.category}]</span>: {g.description}
                </div>
              ))}
            </div>
          </section>

          {/* 14. Outstanding Questions */}
          <section id="sec-14" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              14. Outstanding Questions
            </h3>
            {report.outstanding_questions.questions.length === 0 ? (
              <div className="text-xs text-stone-500 italic">All investigative questions addressed.</div>
            ) : (
              <div className="space-y-1">
                {report.outstanding_questions.questions.map((q, i) => (
                  <div key={i} className="text-xs text-stone-700">• {q.question || JSON.stringify(q)}</div>
                ))}
              </div>
            )}
          </section>

          {/* 15. Analyst Interpretation */}
          <section id="sec-15" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              15. Analyst Interpretation
            </h3>
            {isFinal ? (
              <div className="p-3 bg-stone-50 border border-stone-200 rounded text-sm text-stone-800 whitespace-pre-wrap">
                {report.analyst_interpretation.interpretation_notes}
              </div>
            ) : (
              <textarea
                value={editInterpretation}
                onChange={(e) => setEditInterpretation(e.target.value)}
                rows={3}
                className="w-full text-sm p-3 bg-white border border-stone-300 rounded font-sans focus:outline-none focus:ring-1 focus:ring-stone-500"
              />
            )}
          </section>

          {/* 16. Conclusion */}
          <section id="sec-16" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              16. Conclusion
            </h3>
            {isFinal ? (
              <div className="p-3 bg-stone-50 border border-stone-200 rounded text-sm text-stone-800 whitespace-pre-wrap">
                {report.conclusion.current_conclusion}
              </div>
            ) : (
              <textarea
                value={editConclusion}
                onChange={(e) => setEditConclusion(e.target.value)}
                rows={3}
                className="w-full text-sm p-3 bg-white border border-stone-300 rounded font-sans focus:outline-none focus:ring-1 focus:ring-stone-500"
              />
            )}
          </section>

          {/* 17. Limitations */}
          <section id="sec-17" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              17. Limitations
            </h3>
            {isFinal ? (
              <ul className="list-disc pl-5 text-xs text-stone-700 space-y-1">
                {report.limitations.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            ) : (
              <textarea
                value={editLimitations}
                onChange={(e) => setEditLimitations(e.target.value)}
                rows={3}
                className="w-full text-xs p-2 bg-white border border-stone-300 rounded font-mono"
                placeholder="One limitation per line..."
              />
            )}
          </section>

          {/* 18. Handoff Notes */}
          <section id="sec-18" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              18. Handoff Notes & Recommended Actions
            </h3>
            {isFinal ? (
              <div className="space-y-2 text-xs text-stone-800">
                <div>{report.handoff_notes.handoff_instructions}</div>
                <div className="font-bold">Recommended Actions:</div>
                <ul className="list-disc pl-5 space-y-0.5">
                  {report.handoff_notes.recommended_next_actions.map((a, i) => (
                    <li key={i}>{a}</li>
                  ))}
                </ul>
              </div>
            ) : (
              <div className="space-y-2">
                <textarea
                  value={editHandoffInstructions}
                  onChange={(e) => setEditHandoffInstructions(e.target.value)}
                  rows={2}
                  className="w-full text-xs p-2 bg-white border border-stone-300 rounded font-sans"
                  placeholder="Handoff instructions..."
                />
                <textarea
                  value={editNextActions}
                  onChange={(e) => setEditNextActions(e.target.value)}
                  rows={2}
                  className="w-full text-xs p-2 bg-white border border-stone-300 rounded font-mono"
                  placeholder="One recommended action per line..."
                />
              </div>
            )}
          </section>

          {/* 19. Provenance Manifest Summary */}
          <section id="sec-19" className="border-b border-stone-200 pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              19. Provenance Manifest Summary
            </h3>
            <div className="p-3 bg-white border border-stone-200 rounded text-xs font-mono">
              <div>Total References: {report.provenance_manifest.total_references}</div>
              <div>Digest: {report.provenance_manifest.manifest_blake2b_digest}</div>
            </div>
          </section>

          {/* 20. Metadata */}
          <section id="sec-20" className="pb-4">
            <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2">
              20. Report Metadata
            </h3>
            <div className="grid grid-cols-3 gap-3 bg-stone-50 border border-stone-200 rounded p-3 text-xs font-mono">
              <div>Version: v{report.metadata.version}</div>
              <div>Lifecycle: {report.metadata.lifecycle_status}</div>
              <div>Created: {report.metadata.created_at.slice(0, 19)}</div>
              {report.metadata.reviewed_by && (
                <div>Reviewed By: {report.metadata.reviewed_by}</div>
              )}
              {report.metadata.reviewed_at && (
                <div>Reviewed At: {report.metadata.reviewed_at.slice(0, 19)}</div>
              )}
            </div>
          </section>

          {/* Lifecycle Action Bar */}
          {!isFinal && (
            <div className="pt-4 border-t border-stone-200 flex items-center justify-between bg-stone-50 p-4 rounded">
              <button
                onClick={handleSaveDraft}
                disabled={loading}
                className="px-4 py-2 bg-stone-800 text-stone-100 rounded text-xs font-bold hover:bg-stone-700 disabled:opacity-50"
              >
                Save Draft Revision (v{report.version + 1})
              </button>

              <div className="flex items-center space-x-3">
                <button
                  onClick={handleSubmitReview}
                  disabled={loading}
                  className="px-4 py-2 bg-amber-600 text-white rounded text-xs font-bold hover:bg-amber-500 disabled:opacity-50"
                >
                  Submit for Review
                </button>

                <div className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={reviewerName}
                    onChange={(e) => setReviewerName(e.target.value)}
                    placeholder="Reviewer ID"
                    className="text-xs p-2 bg-white border border-stone-300 rounded font-mono w-32"
                  />
                  <button
                    onClick={handleFinalizeReport}
                    disabled={loading || !reviewerName.trim()}
                    className="px-4 py-2 bg-emerald-700 text-white rounded text-xs font-bold hover:bg-emerald-600 disabled:opacity-50"
                  >
                    Finalize Report
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // --- Sub-View: Provenance Manifest Table ---
  function renderProvenanceView() {
    if (!report) return null;
    const { provenance_manifest } = report;

    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between p-4 bg-stone-50 border border-stone-200 rounded text-xs font-mono">
          <div>
            <div className="font-bold text-stone-900">CRYPTOGRAPHIC PROVENANCE MANIFEST</div>
            <div className="text-stone-500">Report v{provenance_manifest.report_version} • Generated: {provenance_manifest.generated_at}</div>
          </div>
          <div className="text-right">
            <div className="font-bold text-stone-900">{provenance_manifest.total_references} Total Citations</div>
            <div className="text-stone-500 text-[10px]">Digest: {provenance_manifest.manifest_blake2b_digest}</div>
          </div>
        </div>

        <div className="border border-stone-200 rounded overflow-hidden">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-stone-100 text-stone-700 border-b border-stone-200">
                <th className="p-2.5 font-bold">Source Type</th>
                <th className="p-2.5 font-bold">Source ID</th>
                <th className="p-2.5 font-bold">Citation Tag</th>
                <th className="p-2.5 font-bold">Epistemic Status</th>
                <th className="p-2.5 font-bold">Cryptographic Source Hash</th>
                <th className="p-2.5 font-bold">Selection Reason</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-stone-200 bg-white">
              {provenance_manifest.entries.map((entry, idx) => (
                <tr key={idx} className="hover:bg-stone-50">
                  <td className="p-2.5 font-bold text-stone-800">{entry.source_type}</td>
                  <td className="p-2.5 text-stone-700">{entry.source_id}</td>
                  <td className="p-2.5 text-stone-600">{entry.citation_tag}</td>
                  <td className="p-2.5">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        entry.epistemic_status === "OBSERVED"
                          ? "bg-emerald-100 text-emerald-800"
                          : entry.epistemic_status === "INFERRED"
                          ? "bg-amber-100 text-amber-800"
                          : "bg-stone-100 text-stone-600"
                      }`}
                    >
                      {entry.epistemic_status}
                    </span>
                  </td>
                  <td className="p-2.5 text-stone-500 text-[11px] truncate max-w-xs">{entry.cryptographic_source_hash}</td>
                  <td className="p-2.5 text-stone-600 font-sans">{entry.selection_reason || "Selected for report"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // --- Sub-View: Version History & Semantic Comparison ---
  function renderVersionsView() {
    return (
      <div className="space-y-6">
        {/* Version Listing Table */}
        <div>
          <h3 className="text-sm font-bold text-stone-800 uppercase tracking-wider mb-2 font-mono">
            Historical Versions ({versions.length})
          </h3>
          <div className="border border-stone-200 rounded overflow-hidden">
            <table className="w-full text-left text-xs font-mono border-collapse">
              <thead>
                <tr className="bg-stone-100 text-stone-700 border-b border-stone-200">
                  <th className="p-2.5 font-bold">Ver</th>
                  <th className="p-2.5 font-bold">Title</th>
                  <th className="p-2.5 font-bold">Status</th>
                  <th className="p-2.5 font-bold">Created By</th>
                  <th className="p-2.5 font-bold">Created At</th>
                  <th className="p-2.5 font-bold">Reviewer</th>
                  <th className="p-2.5 font-bold">Fingerprint</th>
                  <th className="p-2.5 font-bold">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-stone-200 bg-white">
                {versions.map((v) => (
                  <tr
                    key={v.version}
                    className={`hover:bg-stone-50 ${v.version === selectedVersion ? "bg-stone-50 font-bold" : ""}`}
                  >
                    <td className="p-2.5 font-bold">v{v.version}</td>
                    <td className="p-2.5 text-stone-800">{v.title}</td>
                    <td className="p-2.5">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          v.lifecycle_status === "FINALIZED"
                            ? "bg-emerald-100 text-emerald-800"
                            : v.lifecycle_status === "REVIEW_READY"
                            ? "bg-amber-100 text-amber-800"
                            : "bg-stone-100 text-stone-700"
                        }`}
                      >
                        {v.lifecycle_status}
                      </span>
                    </td>
                    <td className="p-2.5 text-stone-600">{v.created_by}</td>
                    <td className="p-2.5 text-stone-500">{v.created_at.slice(0, 19)}</td>
                    <td className="p-2.5 text-stone-600">{v.reviewed_by || "—"}</td>
                    <td className="p-2.5 text-stone-400 text-[10px]">{v.blake2b_fingerprint.slice(0, 12)}...</td>
                    <td className="p-2.5">
                      <button
                        onClick={() => loadReportData(v.version)}
                        className="text-stone-800 hover:underline font-bold"
                      >
                        Load
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Semantic Comparison Selector */}
        <div className="bg-stone-50 border border-stone-200 rounded p-4 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <div className="font-bold text-stone-900 text-sm">SEMANTIC VERSION COMPARISON</div>
              <div className="text-xs text-stone-500 font-mono">
                Compare structured section diffs between two report revisions
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <div className="flex items-center space-x-1 text-xs font-mono">
                <span>Base (Older):</span>
                <select
                  value={cmpOlder}
                  onChange={(e) => setCmpOlder(Number(e.target.value))}
                  className="bg-white border border-stone-300 rounded p-1"
                >
                  {versions.map((v) => (
                    <option key={v.version} value={v.version}>v{v.version}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-center space-x-1 text-xs font-mono">
                <span>Target (Newer):</span>
                <select
                  value={cmpNewer}
                  onChange={(e) => setCmpNewer(Number(e.target.value))}
                  className="bg-white border border-stone-300 rounded p-1"
                >
                  {versions.map((v) => (
                    <option key={v.version} value={v.version}>v{v.version}</option>
                  ))}
                </select>
              </div>
              <button
                onClick={handleCompareVersions}
                disabled={loading}
                className="px-3 py-1.5 bg-stone-800 text-stone-100 rounded text-xs font-bold hover:bg-stone-700"
              >
                Run Comparison
              </button>
            </div>
          </div>

          {comparisonResult && (
            <div className="space-y-3 pt-3 border-t border-stone-200">
              <div className="flex items-center justify-between text-xs font-mono">
                <div>
                  Differences Count: <strong className="text-stone-900">{comparisonResult.differences_count}</strong>
                </div>
                <div>Compared At: {comparisonResult.compared_at.slice(0, 19)}</div>
              </div>

              <div className="border border-stone-200 rounded overflow-hidden">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="bg-stone-100 text-stone-700 border-b border-stone-200">
                      <th className="p-2 font-bold">Section</th>
                      <th className="p-2 font-bold">Status</th>
                      <th className="p-2 font-bold">Details</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-stone-200 bg-white">
                    {comparisonResult.section_diffs.map((diff, i) => (
                      <tr key={i} className="hover:bg-stone-50">
                        <td className="p-2 font-bold text-stone-800">{diff.section_name}</td>
                        <td className="p-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              diff.status === "IDENTICAL"
                                ? "bg-stone-100 text-stone-600"
                                : "bg-amber-100 text-amber-800"
                            }`}
                          >
                            {diff.status}
                          </span>
                        </td>
                        <td className="p-2 text-stone-500 text-[11px]">
                          {diff.status === "IDENTICAL" ? "No changes" : "Content modified between versions"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    );
  }

  // --- Sub-View: Evidence Package & Export ---
  function renderPackageView() {
    return (
      <div className="grid grid-cols-2 gap-6">
        {/* Left: Package Generator */}
        <div className="bg-stone-50 border border-stone-200 rounded p-4 space-y-4">
          <div>
            <h3 className="text-sm font-bold text-stone-900 uppercase tracking-wider font-mono">
              Deterministic Evidence Package
            </h3>
            <p className="text-xs text-stone-500 font-sans mt-0.5">
              Generates a self-contained manifest packaging referenced case findings, collections, hypotheses, and telemetry digests.
            </p>
          </div>

          <button
            onClick={handleGeneratePackage}
            disabled={loading || !report}
            className="w-full py-2 bg-stone-800 text-stone-100 rounded text-xs font-bold hover:bg-stone-700 disabled:opacity-50"
          >
            Generate Package for v{report?.version || 1}
          </button>

          {evidencePackage && (
            <div className="bg-white border border-stone-200 rounded p-3 text-xs font-mono space-y-2">
              <div className="font-bold text-stone-900">MANIFEST: {evidencePackage.manifest.package_id}</div>
              <div>Schema Version: {evidencePackage.manifest.schema_version}</div>
              <div>Status: {evidencePackage.manifest.status}</div>
              <div>Included Artifacts: {evidencePackage.manifest.included_artifacts.join(", ")}</div>
              <div>Source References: {evidencePackage.manifest.source_reference_count}</div>
              <div className="text-[10px] break-all text-stone-500">
                Digest: {evidencePackage.manifest.package_blake2b_digest}
              </div>
            </div>
          )}
        </div>

        {/* Right: Deterministic Export Controls */}
        <div className="bg-stone-50 border border-stone-200 rounded p-4 space-y-4">
          <div>
            <h3 className="text-sm font-bold text-stone-900 uppercase tracking-wider font-mono">
              Deterministic Export
            </h3>
            <p className="text-xs text-stone-500 font-sans mt-0.5">
              Export investigation report in JSON, CSV (formula injection defanged), or Markdown.
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <select
              value={exportFormat}
              onChange={(e) => setExportFormat(e.target.value as any)}
              className="bg-white border border-stone-300 rounded text-xs font-mono p-1.5 flex-1"
            >
              <option value="json">JSON (Canonical Indented)</option>
              <option value="csv">CSV (Formula-Safe)</option>
              <option value="markdown">Markdown (Forensic Doc)</option>
            </select>
            <button
              onClick={handleExport}
              disabled={loading || !report}
              className="px-4 py-1.5 bg-stone-800 text-stone-100 rounded text-xs font-bold hover:bg-stone-700"
            >
              Export
            </button>
          </div>

          {exportResult && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-stone-500">
                <span>Format: {exportResult.format.toUpperCase()}</span>
                <span>Fingerprint: {exportResult.fingerprint.slice(0, 16)}...</span>
              </div>
              <textarea
                readOnly
                value={exportResult.content}
                rows={10}
                className="w-full text-xs font-mono p-2 bg-white border border-stone-300 rounded"
              />
            </div>
          )}
        </div>
      </div>
    );
  }

  // --- Sub-View: Case Handoff Workflow ---
  function renderHandoffView() {
    return (
      <div className="space-y-6">
        <div className="bg-stone-50 border border-stone-200 rounded p-4">
          <h3 className="text-sm font-bold text-stone-900 uppercase tracking-wider font-mono mb-1">
            Operational Case Handoff Workflow
          </h3>
          <p className="text-xs text-stone-500 font-sans">
            Transfers custody of case materials to another analyst without automatically closing or altering case conclusions.
          </p>

          <div className="mt-4 grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono font-bold text-stone-700 mb-1">
                Target Operator ID:
              </label>
              <input
                type="text"
                value={handoffTarget}
                onChange={(e) => setHandoffTarget(e.target.value)}
                className="w-full text-xs p-2 bg-white border border-stone-300 rounded font-mono"
              />
            </div>
            <div>
              <label className="block text-xs font-mono font-bold text-stone-700 mb-1">
                Operational Notes:
              </label>
              <input
                type="text"
                value={handoffNotes}
                onChange={(e) => setHandoffNotes(e.target.value)}
                placeholder="Shift handoff instructions..."
                className="w-full text-xs p-2 bg-white border border-stone-300 rounded font-sans"
              />
            </div>
          </div>

          <div className="mt-4">
            <button
              onClick={handlePrepareHandoff}
              disabled={loading || !report}
              className="px-4 py-2 bg-stone-800 text-stone-100 rounded text-xs font-bold hover:bg-stone-700"
            >
              Prepare Handoff Packet
            </button>
          </div>
        </div>

        {/* Current Active Handoff Packet */}
        {currentHandoff && (
          <div className="border border-stone-200 rounded p-4 bg-white space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-stone-500">PACKET: {currentHandoff.handoff_id}</span>
                <div className="font-bold text-sm text-stone-900 mt-0.5">
                  Custody Transfer: {currentHandoff.prepared_by} → {currentHandoff.handed_off_to || "Unassigned"}
                </div>
              </div>
              <span
                className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                  currentHandoff.status === "ACKNOWLEDGED"
                    ? "bg-emerald-100 text-emerald-800"
                    : currentHandoff.status === "RETURNED_FOR_FOLLOWUP"
                    ? "bg-rose-100 text-rose-800"
                    : "bg-amber-100 text-amber-800"
                }`}
              >
                {currentHandoff.status}
              </span>
            </div>

            <div className="grid grid-cols-4 gap-2 text-xs font-mono bg-stone-50 p-2.5 rounded border border-stone-200">
              <div>Observed Facts: {currentHandoff.observed_facts_count}</div>
              <div>Active Hypotheses: {currentHandoff.active_hypotheses_count}</div>
              <div>Evidence Gaps: {currentHandoff.evidence_gaps_count}</div>
              <div>Report Ver: v{currentHandoff.report_version}</div>
            </div>

            {currentHandoff.operational_notes && (
              <div className="text-xs text-stone-700">
                <strong>Notes:</strong> {currentHandoff.operational_notes}
              </div>
            )}

            {currentHandoff.return_reason && (
              <div className="text-xs text-rose-700 bg-rose-50 p-2 rounded border border-rose-200">
                <strong>Return Reason:</strong> {currentHandoff.return_reason}
              </div>
            )}

            {/* Recipient Action Controls */}
            <div className="pt-3 border-t border-stone-200 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  value={ackNotes}
                  onChange={(e) => setAckNotes(e.target.value)}
                  placeholder="Custody acknowledgement note..."
                  className="text-xs p-1.5 border border-stone-300 rounded font-sans w-64"
                />
                <button
                  onClick={handleAcknowledgeHandoff}
                  disabled={loading}
                  className="px-3 py-1.5 bg-emerald-700 text-white rounded text-xs font-bold hover:bg-emerald-600"
                >
                  Acknowledge & Accept
                </button>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="text"
                  value={returnReason}
                  onChange={(e) => setReturnReason(e.target.value)}
                  placeholder="Required return reason..."
                  className="text-xs p-1.5 border border-stone-300 rounded font-sans w-56"
                />
                <button
                  onClick={handleReturnHandoff}
                  disabled={loading || !returnReason.trim()}
                  className="px-3 py-1.5 bg-rose-700 text-white rounded text-xs font-bold hover:bg-rose-600 disabled:opacity-50"
                >
                  Return for Followup
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-[#fcfbf9] text-stone-900 font-sans">
      {/* Top Navigation Bar */}
      <div className="flex items-center justify-between px-6 py-3 border-b border-stone-200 bg-white">
        <div className="flex items-center space-x-4">
          <h1 className="text-sm font-bold uppercase tracking-wider text-stone-800 font-mono">
            M7.6 Investigation Report Workbench
          </h1>
          <div className="flex items-center space-x-1 border border-stone-200 rounded p-0.5 bg-stone-50 text-xs font-mono">
            {[
              { id: "report", label: "Report Document" },
              { id: "provenance", label: "Provenance Manifest" },
              { id: "versions", label: "Version History" },
              { id: "package", label: "Evidence Package" },
              { id: "handoff", label: "Case Handoff" },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`px-3 py-1 rounded font-medium transition-colors ${
                  activeTab === tab.id
                    ? "bg-stone-800 text-stone-100"
                    : "text-stone-600 hover:text-stone-900"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex items-center space-x-3 text-xs font-mono">
          {report && (
            <span className="text-stone-500">
              Loaded: <strong>v{report.version}</strong> ({report.lifecycle_status})
            </span>
          )}
          <button
            onClick={() => loadReportData()}
            disabled={loading}
            className="p-1 hover:text-stone-600"
            title="Refresh"
          >
            ↻
          </button>
        </div>
      </div>

      {/* Messages */}
      {error && (
        <div className="mx-6 mt-3 p-3 bg-rose-50 border border-rose-200 text-rose-800 text-xs rounded flex justify-between items-center">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="font-bold">×</button>
        </div>
      )}
      {successMsg && (
        <div className="mx-6 mt-3 p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 text-xs rounded flex justify-between items-center">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="font-bold">×</button>
        </div>
      )}

      {/* Main Workspace Body */}
      <div className="flex-1 p-6 overflow-y-auto">
        {activeTab === "report" && renderReportView()}
        {activeTab === "provenance" && renderProvenanceView()}
        {activeTab === "versions" && renderVersionsView()}
        {activeTab === "package" && renderPackageView()}
        {activeTab === "handoff" && renderHandoffView()}
      </div>
    </div>
  );
}
