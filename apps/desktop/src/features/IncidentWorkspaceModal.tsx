import React, { useEffect, useState } from "react";
import {
  AttackPathIcon,
  CloseIcon,
  ExportIcon,
  GraphIcon,
  MitreIcon,
  NoteIcon,
  SearchIcon,
  TimelineIcon,
  TrashIcon,
} from "../components/Icons";
import { InvestigationIntelligencePanel } from "./InvestigationIntelligencePanel";
import {
  AlertStatusBadge,
  ConfidenceBadge,
  EntityTypeBadge,
  IncidentStatusBadge,
  SeverityBadge,
} from "../components/StatusBadge";
import {
  createIncidentNote,
  deleteIncidentNote,
  exportInvestigation,
  fetchIncidentAttackPath,
  fetchIncidentDetail,
  fetchIncidentMitre,
  fetchIncidentNotes,
  fetchInvestigationNotes,
  fetchInvestigationNotesAudit,
  updateIncidentStatus,
} from "../lib/api";
import {
  ALLOWED_INCIDENT_STATUS_TRANSITIONS,
  IncidentDetailResponse,
  IncidentStatus,
} from "../types/incidents";
import {
  AttackPathReconstruction,
  InvestigationNote,
  InvestigationNoteAudit,
  MitreMapping,
} from "../types/investigation";
import { AttackGraphVisualizer } from "./AttackGraphVisualizer";
import { InvestigationTimeline } from "./InvestigationTimeline";
import { InvestigationUnifiedTimeline } from "./InvestigationUnifiedTimeline";
import { InvestigationEvidenceWorkbench } from "./InvestigationEvidenceWorkbench";
import { InvestigationFindingsWorkbench } from "./InvestigationFindingsWorkbench";
import { InvestigationThreatHuntWorkbench } from "./InvestigationThreatHuntWorkbench";
import { InvestigationReportWorkbench } from "./InvestigationReportWorkbench";

interface IncidentWorkspaceModalProps {
  incidentId: number;
  onClose: () => void;
  onStatusUpdated?: () => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEventId?: (eventId: string) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function IncidentWorkspaceModal({
  incidentId,
  onClose,
  onStatusUpdated,
  onSelectAlertId,
  onSelectEventId,
  onSelectEntityKey,
}: IncidentWorkspaceModalProps) {
  const [detail, setDetail] = useState<IncidentDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Tabs
  const [activeTab, setActiveTab] = useState<
    "graph" | "path" | "timeline" | "alerts" | "entities" | "mitre" | "notes" | "evidence" | "findings" | "hunting" | "report" | "ai"
  >("graph");

  // Attack Path state
  const [attackPath, setAttackPath] = useState<AttackPathReconstruction | null>(null);
  const [pathLoading, setPathLoading] = useState<boolean>(false);

  // MITRE state
  const [mitreMappings, setMitreMappings] = useState<MitreMapping[]>([]);
  const [mitreLoading, setMitreLoading] = useState<boolean>(false);

  // Notes state
  const [notes, setNotes] = useState<InvestigationNote[]>([]);
  const [notesLoading, setNotesLoading] = useState<boolean>(false);
  const [includeDeletedNotes, setIncludeDeletedNotes] = useState<boolean>(false);
  const [notesAuditTrail, setNotesAuditTrail] = useState<InvestigationNoteAudit[]>([]);
  const [showAuditLedger, setShowAuditLedger] = useState<boolean>(false);
  const [newNoteAuthor, setNewNoteAuthor] = useState<string>("SecAnalyst-1");
  const [newNoteContent, setNewNoteContent] = useState<string>("");
  const [newNoteTargetType, setNewNoteTargetType] = useState<string>("INCIDENT");
  const [newNoteTargetId, setNewNoteTargetId] = useState<string>("");
  const [addingNote, setAddingNote] = useState<boolean>(false);

  // Status transition state
  const [selectedStatus, setSelectedStatus] = useState<IncidentStatus | "">("");
  const [resolutionNote, setResolutionNote] = useState<string>("");
  const [updating, setUpdating] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<{ text: string; isError: boolean } | null>(null);

  // Export state
  const [exporting, setExporting] = useState<boolean>(false);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  // M7.2 Timeline mode
  const [timelineMode, setTimelineMode] = useState<"unified" | "classic">("unified");

  const loadDossier = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchIncidentDetail(incidentId);
      setDetail(data);
      setSelectedStatus("");
    } catch (err: any) {
      setError(err.message || "Failed to load incident workspace dossier");
    } finally {
      setLoading(false);
    }
  };

  const loadAttackPath = async () => {
    setPathLoading(true);
    try {
      const pathData = await fetchIncidentAttackPath(incidentId);
      setAttackPath(pathData);
    } catch (err: any) {
      console.error("Failed to load attack path:", err);
    } finally {
      setPathLoading(false);
    }
  };

  const loadMitre = async () => {
    setMitreLoading(true);
    try {
      const mappings = await fetchIncidentMitre(incidentId);
      setMitreMappings(mappings);
    } catch (err: any) {
      console.error("Failed to load MITRE ATT&CK mapping:", err);
    } finally {
      setMitreLoading(false);
    }
  };

  const loadNotes = async (withDeleted = includeDeletedNotes) => {
    setNotesLoading(true);
    try {
      const noteList = await fetchInvestigationNotes(incidentId, withDeleted);
      setNotes(noteList.items);
      const auditRes = await fetchInvestigationNotesAudit(incidentId);
      setNotesAuditTrail(auditRes.items);
    } catch (err: any) {
      console.error("Failed to load analyst notes:", err);
    } finally {
      setNotesLoading(false);
    }
  };

  useEffect(() => {
    loadDossier();
    loadAttackPath();
    loadMitre();
    loadNotes(includeDeletedNotes);
  }, [incidentId, includeDeletedNotes]);

  const handleUpdateStatus = async () => {
    if (!selectedStatus) return;
    setUpdating(true);
    setStatusMessage(null);
    try {
      await updateIncidentStatus(incidentId, selectedStatus as IncidentStatus, resolutionNote || undefined);
      setStatusMessage({ text: `Incident status updated to ${selectedStatus}`, isError: false });
      setResolutionNote("");
      await loadDossier();
      if (onStatusUpdated) onStatusUpdated();
    } catch (err: any) {
      setStatusMessage({ text: err.message || "Failed to update incident status", isError: true });
    } finally {
      setUpdating(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteContent.trim() || !newNoteAuthor.trim()) return;
    setAddingNote(true);
    try {
      await createIncidentNote(incidentId, {
        author: newNoteAuthor.trim(),
        content: newNoteContent.trim(),
        target_type: newNoteTargetType || undefined,
        target_id: newNoteTargetId.trim() || undefined,
      });
      setNewNoteContent("");
      setNewNoteTargetId("");
      await loadNotes();
    } catch (err: any) {
      alert(`Failed to add note: ${err.message}`);
    } finally {
      setAddingNote(false);
    }
  };

  const handleDeleteNote = async (noteId: number) => {
    if (!confirm("Are you sure you want to delete this analyst annotation?")) return;
    try {
      await deleteIncidentNote(noteId);
      await loadNotes();
    } catch (err: any) {
      alert(`Failed to delete note: ${err.message}`);
    }
  };

  const handleExport = async (format: "json" | "markdown" | "csv") => {
    setExporting(true);
    setExportNotice(null);
    try {
      const exp = await exportInvestigation(incidentId, format);
      const mime =
        format === "json"
          ? "application/json"
          : format === "csv"
          ? "text/csv"
          : "text/markdown";
      const blob = new Blob([exp.content], { type: mime });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = exp.filename;
      link.click();
      URL.revokeObjectURL(url);
      setExportNotice(`Exported evidence dossier (${exp.filename})`);
      setTimeout(() => setExportNotice(null), 4000);
    } catch (err: any) {
      setExportNotice(`Export failed: ${err.message}`);
    } finally {
      setExporting(false);
    }
  };

  const incident = detail?.incident;
  const allowedTransitions = incident ? ALLOWED_INCIDENT_STATUS_TRANSITIONS[incident.status] || [] : [];

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-dialog"
        style={{ width: "1040px", maxWidth: "96vw", height: "90vh", display: "flex", flexDirection: "column" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "10px", flexWrap: "wrap" }}>
            <span style={{ fontSize: "14px", fontWeight: 700, fontFamily: "var(--font-mono)" }}>
              {incident?.incident_key || `Incident #${incidentId}`}
            </span>
            {incident && <SeverityBadge severity={incident.severity} />}
            {incident && <IncidentStatusBadge status={incident.status} />}
            <span style={{ fontSize: "13px", fontWeight: 600, color: "var(--text-primary)" }}>
              {incident?.title}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            {/* Export Toolbar */}
            <div style={{ display: "flex", alignItems: "center", gap: "4px", marginRight: "10px" }}>
              <span style={{ fontSize: "10px", color: "var(--text-muted)", textTransform: "uppercase" }}>Export:</span>
              <button
                className="btn btn-secondary"
                style={{ padding: "2px 6px", fontSize: "10px" }}
                disabled={exporting}
                onClick={() => handleExport("markdown")}
                title="Export Evidence Dossier as Markdown"
              >
                <ExportIcon /> MD
              </button>
              <button
                className="btn btn-secondary"
                style={{ padding: "2px 6px", fontSize: "10px" }}
                disabled={exporting}
                onClick={() => handleExport("json")}
                title="Export Complete Investigation as JSON"
              >
                JSON
              </button>
              <button
                className="btn btn-secondary"
                style={{ padding: "2px 6px", fontSize: "10px" }}
                disabled={exporting}
                onClick={() => handleExport("csv")}
                title="Export Forensic Event Timeline as CSV"
              >
                CSV
              </button>
            </div>

            <button className="btn btn-secondary" style={{ padding: "4px" }} onClick={onClose}>
              <CloseIcon />
            </button>
          </div>
        </div>

        {/* Notice Bar */}
        {exportNotice && (
          <div
            style={{
              padding: "6px 14px",
              background: "var(--bg-surface-subtle)",
              borderBottom: "1px solid var(--border-subtle)",
              fontSize: "11px",
              color: "var(--text-secondary)",
            }}
          >
            {exportNotice}
          </div>
        )}

        {/* Body */}
        <div className="modal-body" style={{ display: "flex", flexDirection: "column", gap: "12px", flex: 1, overflowY: "hidden" }}>
          {loading && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
              Loading incident investigation dossier...
            </div>
          )}

          {error && (
            <div className="panel" style={{ padding: "12px", border: "1px solid var(--badge-alert-border)", background: "var(--badge-alert-bg)" }}>
              <span style={{ color: "var(--badge-alert-text)", fontWeight: 600 }}>{error}</span>
            </div>
          )}

          {incident && !loading && (
            <>
              {/* Incident Metrics Bar */}
              <div
                className="panel"
                style={{
                  padding: "8px 14px",
                  background: "var(--bg-surface-subtle)",
                  border: "1px solid var(--border-subtle)",
                  display: "flex",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: "10px",
                }}
              >
                <div>
                  <span className="property-label">Primary Host:</span>
                  <strong style={{ fontSize: "12px", marginLeft: "4px" }}>{incident.primary_host}</strong>
                </div>
                <div>
                  <span className="property-label">Primary User:</span>
                  <strong style={{ fontSize: "12px", marginLeft: "4px" }}>{incident.primary_user || "N/A"}</strong>
                </div>
                <div>
                  <span className="property-label">Alerts:</span>
                  <span className="badge badge-alert" style={{ marginLeft: "4px", fontSize: "11px" }}>
                    {incident.alert_count}
                  </span>
                </div>
                <div>
                  <span className="property-label">Evidence Events:</span>
                  <span className="badge badge-neutral" style={{ marginLeft: "4px", fontSize: "11px" }}>
                    {incident.event_count}
                  </span>
                </div>
                <div>
                  <span className="property-label">First Seen:</span>
                  <span style={{ fontSize: "11px", fontFamily: "var(--font-mono)", marginLeft: "4px" }}>
                    {new Date(incident.first_seen).toISOString().slice(0, 19).replace("T", " ")}
                  </span>
                </div>
                <div>
                  <span className="property-label">Last Seen:</span>
                  <span style={{ fontSize: "11px", fontFamily: "var(--font-mono)", marginLeft: "4px" }}>
                    {new Date(incident.last_seen).toISOString().slice(0, 19).replace("T", " ")}
                  </span>
                </div>
              </div>

              {/* Status Transition Control Bar */}
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "space-between",
                  flexWrap: "wrap",
                  gap: "10px",
                  padding: "6px 12px",
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "2px",
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>
                    Lifecycle Transition:
                  </span>
                  <select
                    value={selectedStatus}
                    onChange={(e) => setSelectedStatus(e.target.value as IncidentStatus)}
                    style={{
                      padding: "4px 8px",
                      fontSize: "11px",
                      border: "1px solid var(--border-strong)",
                      borderRadius: "2px",
                      background: "var(--bg-surface)",
                    }}
                  >
                    <option value="">Select Target Status...</option>
                    {allowedTransitions.map((st) => (
                      <option key={st} value={st}>
                        &rarr; {st.replace("_", " ")}
                      </option>
                    ))}
                  </select>

                  <input
                    type="text"
                    placeholder="Audit note / resolution details..."
                    value={resolutionNote}
                    onChange={(e) => setResolutionNote(e.target.value)}
                    style={{
                      padding: "4px 8px",
                      fontSize: "11px",
                      width: "280px",
                      border: "1px solid var(--border-strong)",
                      borderRadius: "2px",
                    }}
                  />

                  <button
                    className="btn btn-primary"
                    disabled={!selectedStatus || updating}
                    onClick={handleUpdateStatus}
                    style={{ padding: "4px 10px", fontSize: "11px" }}
                  >
                    {updating ? "Updating..." : "Transition Status"}
                  </button>
                </div>

                {statusMessage && (
                  <span
                    style={{
                      fontSize: "11px",
                      fontWeight: 600,
                      color: statusMessage.isError ? "var(--badge-alert-text)" : "var(--badge-success-text)",
                    }}
                  >
                    {statusMessage.text}
                  </span>
                )}
              </div>

              {/* Workspace Navigation Tabs */}
              <div style={{ display: "flex", borderBottom: "1px solid var(--border-subtle)", gap: "2px", overflowX: "auto" }}>
                <button
                  className={`btn btn-secondary ${activeTab === "graph" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "graph" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "graph" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("graph")}
                >
                  <GraphIcon /> Attack Graph ({detail?.graph?.nodes?.length || 0})
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "path" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "path" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "path" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("path")}
                >
                  <AttackPathIcon /> Attack Path ({attackPath?.steps?.length || 0} steps)
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "timeline" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "timeline" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "timeline" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("timeline")}
                >
                  <TimelineIcon /> Timeline ({detail?.timeline?.length || 0})
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "alerts" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "alerts" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "alerts" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("alerts")}
                >
                  Alerts ({detail?.alerts?.length || 0})
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "entities" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "entities" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "entities" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("entities")}
                >
                  Entities & Edges ({detail?.graph?.edges?.length || 0})
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "mitre" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "mitre" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "mitre" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("mitre")}
                >
                  <MitreIcon /> MITRE ATT&CK ({mitreMappings.length})
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "notes" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "notes" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "notes" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("notes")}
                >
                  <NoteIcon /> Notes & Annotations ({notes.length})
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "evidence" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "evidence" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "evidence" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("evidence")}
                >
                  Evidence Workbench (M7.3)
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "findings" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "findings" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "findings" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("findings")}
                >
                  Findings & Hypotheses (M7.4)
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "hunting" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "hunting" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "hunting" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("hunting")}
                >
                  Threat Hunting (M7.5)
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "report" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "report" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "report" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("report")}
                >
                  Investigation Report (M7.6)
                </button>

                <button
                  className={`btn btn-secondary ${activeTab === "ai" ? "active" : ""}`}
                  style={{
                    padding: "6px 12px",
                    fontSize: "11px",
                    borderBottom: activeTab === "ai" ? "2px solid var(--border-dark)" : "none",
                    fontWeight: activeTab === "ai" ? 600 : 400,
                  }}
                  onClick={() => setActiveTab("ai")}
                >
                  <SearchIcon /> AI Intelligence
                </button>
              </div>

              {/* Tab Contents Pane */}
              <div style={{ flex: 1, overflowY: "auto", minHeight: "380px" }}>
                {/* 1. Attack Graph Tab */}
                {activeTab === "graph" && detail?.graph && (
                  <AttackGraphVisualizer
                    graph={detail.graph}
                    onSelectEventId={onSelectEventId}
                  />
                )}

                {/* 2. Attack Path Tab */}
                {activeTab === "path" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                    <div
                      style={{
                        padding: "8px 12px",
                        background: "var(--bg-surface-subtle)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                        fontSize: "11px",
                        color: "var(--text-secondary)",
                      }}
                    >
                      Topological attack-path reconstruction traces causal and temporal progression across
                      attributed entities. Steps are classified strictly as <strong>OBSERVED</strong> (substantiated
                      by canonical events) or <strong>INFERRED</strong> (structural link in the graph).
                    </div>

                    {pathLoading && (
                      <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                        Reconstructing attack path progression...
                      </div>
                    )}

                    {!pathLoading && (!attackPath || attackPath.steps.length === 0) && (
                      <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
                        No multi-hop attack steps reconstructed for this incident graph.
                      </div>
                    )}

                    {!pathLoading && attackPath && attackPath.steps.length > 0 && (
                      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                        {attackPath.steps.map((step) => {
                          const borderCol =
                            step.nature === "OBSERVED"
                              ? "3px solid #0284c7"
                              : step.nature === "INFERRED"
                              ? "3px dashed #d97706"
                              : "3px dotted #64748b";
                          const badgeClass =
                            step.nature === "OBSERVED"
                              ? "badge-notice"
                              : step.nature === "INFERRED"
                              ? "badge-warning"
                              : "badge-neutral";
                          return (
                            <div
                              key={step.step_number}
                              className="panel"
                              style={{
                                padding: "10px 14px",
                                borderLeft: borderCol,
                              }}
                            >
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700 }}>
                                    Step {step.step_number}
                                  </span>
                                  <span className={`badge ${badgeClass}`} style={{ fontSize: "10px" }}>
                                    {step.nature}
                                  </span>
                                  <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-primary)" }}>
                                    {step.relationship_type.replace(/_/g, " ")}
                                  </span>
                                </div>
                                <ConfidenceBadge confidence={step.confidence} />
                              </div>

                              <div style={{ display: "flex", alignItems: "center", gap: "10px", margin: "6px 0", flexWrap: "wrap" }}>
                                {/* Source Node */}
                                {(() => {
                                  const srcKey = typeof step.source_node === "string" ? step.source_node : step.source_node.id;
                                  const srcLabel = typeof step.source_node === "string" ? step.source_node : step.source_node.label;
                                  const srcType = typeof step.source_node === "string" ? "entity" : step.source_node.entity_type;
                                  return (
                                    <div
                                      style={{
                                        padding: "4px 8px",
                                        border: "1px solid var(--border-subtle)",
                                        borderRadius: "2px",
                                        background: "var(--bg-surface)",
                                        display: "inline-flex",
                                        alignItems: "center",
                                        gap: "6px",
                                      }}
                                    >
                                      <EntityTypeBadge entityType={srcType} />
                                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 600 }}>
                                        {srcLabel}
                                      </span>
                                      {onSelectEntityKey && (
                                        <button
                                          className="btn btn-secondary"
                                          style={{ padding: "1px 4px", fontSize: "9px" }}
                                          onClick={() => onSelectEntityKey(srcKey)}
                                        >
                                          Pivot
                                        </button>
                                      )}
                                    </div>
                                  );
                                })()}

                                <span style={{ color: "var(--text-muted)", fontSize: "14px" }}>&rarr;</span>

                                {/* Target Node */}
                                {(() => {
                                  const dstKey = typeof step.target_node === "string" ? step.target_node : step.target_node.id;
                                  const dstLabel = typeof step.target_node === "string" ? step.target_node : step.target_node.label;
                                  const dstType = typeof step.target_node === "string" ? "entity" : step.target_node.entity_type;
                                  return (
                                    <div
                                      style={{
                                        padding: "4px 8px",
                                        border: "1px solid var(--border-subtle)",
                                        borderRadius: "2px",
                                        background: "var(--bg-surface)",
                                        display: "inline-flex",
                                        alignItems: "center",
                                        gap: "6px",
                                      }}
                                    >
                                      <EntityTypeBadge entityType={dstType} />
                                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 600 }}>
                                        {dstLabel}
                                      </span>
                                      {onSelectEntityKey && (
                                        <button
                                          className="btn btn-secondary"
                                          style={{ padding: "1px 4px", fontSize: "9px" }}
                                          onClick={() => onSelectEntityKey(dstKey)}
                                        >
                                          Pivot
                                        </button>
                                      )}
                                    </div>
                                  );
                                })()}
                              </div>

                              {/* Inference details */}
                              {step.inference_reason && (
                                <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "4px", fontStyle: "italic" }}>
                                  <strong>Inference Rationale:</strong> {step.inference_reason} ({step.derivation_source})
                                </div>
                              )}

                            {/* Evidence events supporting step */}
                            {((step.evidence_event_ids || step.supporting_event_ids || []).length > 0) && (
                              <div style={{ display: "flex", alignItems: "center", gap: "6px", marginTop: "6px" }}>
                                <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>Evidence:</span>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                                  {(step.evidence_event_ids || step.supporting_event_ids || []).map((evId: string) => (
                                    <button
                                      key={evId}
                                      className="btn btn-secondary"
                                      style={{ padding: "1px 6px", fontSize: "10px", fontFamily: "var(--font-mono)" }}
                                      onClick={() => onSelectEventId && onSelectEventId(evId)}
                                    >
                                      evt:{evId.slice(0, 8)}...
                                    </button>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                      </div>
                    )}
                  </div>
                )}

                {/* 3. Timeline Tab */}
                {activeTab === "timeline" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    <div style={{ display: "flex", justifyContent: "flex-end", gap: "6px" }}>
                      <button
                        className={timelineMode === "unified" ? "btn btn-primary" : "btn btn-secondary"}
                        style={{ fontSize: "11px", padding: "3px 8px" }}
                        onClick={() => setTimelineMode("unified")}
                      >
                        Unified Timeline & Replay (M7.2)
                      </button>
                      <button
                        className={timelineMode === "classic" ? "btn btn-primary" : "btn btn-secondary"}
                        style={{ fontSize: "11px", padding: "3px 8px" }}
                        onClick={() => setTimelineMode("classic")}
                      >
                        Classic Incident Timeline
                      </button>
                    </div>

                    {timelineMode === "unified" ? (
                      <InvestigationUnifiedTimeline
                        caseId={incidentId}
                        onSelectEntityKey={onSelectEntityKey}
                        onSelectAlertId={onSelectAlertId}
                        onSelectEventId={onSelectEventId}
                      />
                    ) : (
                      detail?.timeline && (
                        <InvestigationTimeline
                          timeline={detail.timeline}
                          onSelectAlertId={onSelectAlertId}
                          onSelectEventId={onSelectEventId}
                        />
                      )
                    )}
                  </div>
                )}

                {/* 4. Correlated Alerts Tab */}
                {activeTab === "alerts" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    <table className="data-table" style={{ width: "100%" }}>
                      <thead>
                        <tr>
                          <th>ID</th>
                          <th>Rule</th>
                          <th>Title</th>
                          <th>Severity</th>
                          <th>Status</th>
                          <th>Host</th>
                          <th>First Seen</th>
                          <th>Occurrences</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detail?.alerts.map((al) => (
                          <tr key={al.id}>
                            <td style={{ fontFamily: "var(--font-mono)" }}>#{al.id}</td>
                            <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>{al.rule_id}</td>
                            <td><strong>{al.title}</strong></td>
                            <td><SeverityBadge severity={al.severity} /></td>
                            <td><AlertStatusBadge status={al.status} /></td>
                            <td>{al.host}</td>
                            <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                              {new Date(al.first_seen).toISOString().slice(0, 19).replace("T", " ")}
                            </td>
                            <td>{al.occurrence_count}</td>
                            <td>
                              {onSelectAlertId && (
                                <button
                                  className="btn btn-secondary"
                                  style={{ padding: "2px 6px", fontSize: "10px" }}
                                  onClick={() => onSelectAlertId(al.id)}
                                >
                                  View Alert
                                </button>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {/* 5. Entities & Edges Tab (with Interactive Pivot) */}
                {activeTab === "entities" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                    <div>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>
                        Correlated Entity Nodes ({detail?.graph.nodes.length || 0})
                      </h4>
                      <table className="data-table" style={{ width: "100%" }}>
                        <thead>
                          <tr>
                            <th>Key</th>
                            <th>Type</th>
                            <th>Label</th>
                            <th>Metadata</th>
                            <th>Forensic Pivot</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detail?.graph.nodes.map((n) => (
                            <tr key={n.id}>
                              <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>{n.id}</td>
                              <td><EntityTypeBadge entityType={n.entity_type} /></td>
                              <td><strong>{n.label}</strong></td>
                              <td style={{ fontFamily: "var(--font-mono)", fontSize: "10px" }}>
                                {JSON.stringify(n.metadata)}
                              </td>
                              <td>
                                {onSelectEntityKey && (
                                  <button
                                    className="btn btn-secondary"
                                    style={{ padding: "2px 6px", fontSize: "10px" }}
                                    onClick={() => onSelectEntityKey(n.id)}
                                  >
                                    Pivot &rarr;
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <div>
                      <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>
                        Attributed Relationships / Edges ({detail?.graph.edges.length || 0})
                      </h4>
                      <table className="data-table" style={{ width: "100%" }}>
                        <thead>
                          <tr>
                            <th>Source</th>
                            <th>Target</th>
                            <th>Relationship</th>
                            <th>Confidence</th>
                            <th>Evidence Events</th>
                          </tr>
                        </thead>
                        <tbody>
                          {detail?.graph.edges.map((e) => (
                            <tr key={e.id}>
                              <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                                {e.source}
                                {onSelectEntityKey && (
                                  <button
                                    className="btn btn-secondary"
                                    style={{ padding: "1px 4px", fontSize: "9px", marginLeft: "4px" }}
                                    onClick={() => onSelectEntityKey(e.source)}
                                  >
                                    Pivot
                                  </button>
                                )}
                              </td>
                              <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                                {e.target}
                                {onSelectEntityKey && (
                                  <button
                                    className="btn btn-secondary"
                                    style={{ padding: "1px 4px", fontSize: "9px", marginLeft: "4px" }}
                                    onClick={() => onSelectEntityKey(e.target)}
                                  >
                                    Pivot
                                  </button>
                                )}
                              </td>
                              <td>
                                <span className="badge badge-notice" style={{ fontSize: "10px" }}>
                                  {e.relationship_type}
                                </span>
                              </td>
                              <td><ConfidenceBadge confidence={e.confidence} /></td>
                              <td>
                                <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                                  {e.evidence_event_ids &&
                                    e.evidence_event_ids.map((evId) => (
                                      <button
                                        key={evId}
                                        className="btn btn-secondary"
                                        style={{ padding: "1px 5px", fontSize: "10px", fontFamily: "var(--font-mono)" }}
                                        onClick={() => onSelectEventId && onSelectEventId(evId)}
                                      >
                                        {evId.slice(0, 8)}...
                                      </button>
                                    ))}
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {/* 6. MITRE ATT&CK Matrix Tab */}
                {activeTab === "mitre" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                    <div
                      style={{
                        padding: "8px 12px",
                        background: "var(--bg-surface-subtle)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                        fontSize: "11px",
                        color: "var(--text-secondary)",
                      }}
                    >
                      MITRE ATT&CK mappings are strictly evidence-backed and derived directly from active detection
                      and correlation rules triggered within this incident.
                    </div>

                    {mitreLoading && (
                      <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                        Loading MITRE ATT&CK mappings...
                      </div>
                    )}

                    {!mitreLoading && mitreMappings.length === 0 && (
                      <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
                        No MITRE ATT&CK techniques mapped to this incident's current evidence rules.
                      </div>
                    )}

                    {!mitreLoading && mitreMappings.length > 0 && (
                      <table className="data-table" style={{ width: "100%" }}>
                        <thead>
                          <tr>
                            <th>Technique ID</th>
                            <th>Technique Name</th>
                            <th>Tactic</th>
                            <th>Triggered Rule</th>
                            <th>Supporting Alerts</th>
                            <th>Evidence Events</th>
                          </tr>
                        </thead>
                        <tbody>
                          {mitreMappings.map((m) => (
                            <tr key={m.technique_id}>
                              <td style={{ fontFamily: "var(--font-mono)", fontSize: "12px", fontWeight: 700 }}>
                                <span className="badge badge-alert" style={{ fontSize: "10px" }}>
                                  {m.technique_id}
                                </span>
                              </td>
                              <td><strong>{m.technique_name}</strong></td>
                              <td>
                                <span className="badge badge-neutral" style={{ fontSize: "10px" }}>
                                  {m.tactic}
                                </span>
                              </td>
                              <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>{m.rule_id}</td>
                              <td>
                                <div style={{ display: "flex", gap: "4px" }}>
                                  {m.supporting_alert_ids.map((alId) => (
                                    <button
                                      key={alId}
                                      className="btn btn-secondary"
                                      style={{ padding: "1px 5px", fontSize: "10px" }}
                                      onClick={() => onSelectAlertId && onSelectAlertId(alId)}
                                    >
                                      #{alId}
                                    </button>
                                  ))}
                                </div>
                              </td>
                              <td>
                                <span className="badge badge-neutral" style={{ fontSize: "10px" }}>
                                  {m.evidence_event_count ?? m.supporting_event_ids?.length ?? 0} events
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                )}

                {/* 7. Analyst Notes & Annotations Tab */}
                {activeTab === "notes" && (
                  <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
                    {/* Add Note Form */}
                    <form
                      onSubmit={handleAddNote}
                      className="panel"
                      style={{ padding: "12px 14px", display: "flex", flexDirection: "column", gap: "10px" }}
                    >
                      <span style={{ fontSize: "12px", fontWeight: 600 }}>Create Analyst Annotation / Note</span>
                      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "10px" }}>
                        <div>
                          <label className="property-label">Analyst Author</label>
                          <input
                            type="text"
                            className="input-control"
                            value={newNoteAuthor}
                            onChange={(e) => setNewNoteAuthor(e.target.value)}
                            required
                            style={{ width: "100%", marginTop: "3px" }}
                          />
                        </div>
                        <div>
                          <label className="property-label">Target Association</label>
                          <select
                            className="input-control"
                            value={newNoteTargetType}
                            onChange={(e) => setNewNoteTargetType(e.target.value)}
                            style={{ width: "100%", marginTop: "3px" }}
                          >
                            <option value="INCIDENT">INCIDENT (General)</option>
                            <option value="EVENT">EVENT (Specific Event)</option>
                            <option value="ENTITY">ENTITY (Host / IP / User)</option>
                            <option value="ALERT">ALERT (Specific Alert)</option>
                          </select>
                        </div>
                        <div>
                          <label className="property-label">Target ID / Key (Optional)</label>
                          <input
                            type="text"
                            className="input-control"
                            placeholder="e.g. host:server-01 or event ID"
                            value={newNoteTargetId}
                            onChange={(e) => setNewNoteTargetId(e.target.value)}
                            style={{ width: "100%", marginTop: "3px" }}
                          />
                        </div>
                      </div>

                      <div>
                        <label className="property-label">Annotation Findings / Notes</label>
                        <textarea
                          className="input-control"
                          rows={3}
                          placeholder="Document investigative hypothesis, evidence corroboration, or containment steps..."
                          value={newNoteContent}
                          onChange={(e) => setNewNoteContent(e.target.value)}
                          required
                          style={{ width: "100%", marginTop: "3px" }}
                        />
                      </div>

                      <div style={{ display: "flex", justifyContent: "flex-end" }}>
                        <button
                          type="submit"
                          className="btn btn-primary"
                          disabled={addingNote || !newNoteContent.trim()}
                          style={{ padding: "5px 14px", fontSize: "11px" }}
                        >
                          {addingNote ? "Saving..." : "Add Annotation"}
                        </button>
                      </div>
                    </form>

                    {/* Notes List */}
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "10px" }}>
                        <h4 style={{ fontSize: "12px", margin: 0 }}>
                          Investigative Notes & Annotations ({notes.length})
                        </h4>
                        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
                          <label style={{ display: "flex", alignItems: "center", gap: "5px", fontSize: "11px", color: "var(--text-secondary)", cursor: "pointer" }}>
                            <input
                              type="checkbox"
                              checked={includeDeletedNotes}
                              onChange={(e) => setIncludeDeletedNotes(e.target.checked)}
                            />
                            Show Tombstoned Notes
                          </label>
                          <button
                            type="button"
                            className={`btn ${showAuditLedger ? "btn-primary" : "btn-secondary"}`}
                            style={{ padding: "3px 8px", fontSize: "10px" }}
                            onClick={() => setShowAuditLedger(!showAuditLedger)}
                          >
                            {showAuditLedger ? "Hide Audit Ledger" : "View Audit Ledger"}
                          </button>
                        </div>
                      </div>

                      {showAuditLedger && (
                        <div className="panel" style={{ padding: "10px 14px", marginBottom: "12px", background: "var(--bg-surface-subtle)" }}>
                          <span style={{ fontSize: "11px", fontWeight: 700, display: "block", marginBottom: "6px" }}>
                            Immutable Historical Audit Ledger ({notesAuditTrail.length} events)
                          </span>
                          {notesAuditTrail.length === 0 ? (
                            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>No audit records recorded yet.</span>
                          ) : (
                            <table className="data-table" style={{ width: "100%", fontSize: "10px" }}>
                              <thead>
                                <tr>
                                  <th>Action</th>
                                  <th>Actor</th>
                                  <th>Timestamp</th>
                                  <th>Target</th>
                                  <th>Reason</th>
                                </tr>
                              </thead>
                              <tbody>
                                {notesAuditTrail.map((entry) => (
                                  <tr key={entry.id}>
                                    <td>
                                      <span className={`badge ${entry.action === "CREATED" ? "badge-notice" : "badge-alert"}`} style={{ fontSize: "9px" }}>
                                        {entry.action}
                                      </span>
                                    </td>
                                    <td><strong>{entry.actor}</strong></td>
                                    <td style={{ fontFamily: "var(--font-mono)" }}>{new Date(entry.action_timestamp).toISOString().replace("T", " ")}</td>
                                    <td>{entry.target_type} {entry.target_id ? `(${entry.target_id})` : ""}</td>
                                    <td>{entry.reason || "N/A"}</td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          )}
                        </div>
                      )}

                      {notesLoading && (
                        <div style={{ textAlign: "center", padding: "20px", color: "var(--text-muted)" }}>
                          Loading annotations...
                        </div>
                      )}
                      {!notesLoading && notes.length === 0 && (
                        <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                          No analyst annotations recorded for this investigation yet.
                        </div>
                      )}
                      {!notesLoading && notes.length > 0 && (
                        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                          {notes.map((note) => (
                            <div
                              key={note.id}
                              className="panel"
                              style={{
                                padding: "10px 14px",
                                background: note.is_deleted ? "var(--bg-surface-subtle)" : "var(--bg-surface)",
                                opacity: note.is_deleted ? 0.75 : 1,
                                borderLeft: note.is_deleted ? "3px solid #ef4444" : "1px solid var(--border-subtle)",
                              }}
                            >
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                  <strong>{note.author}</strong>
                                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-muted)" }}>
                                    {new Date(note.created_at).toISOString().replace("T", " ")}
                                  </span>
                                  {note.target_type && (
                                    <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                                      {note.target_type}
                                      {note.target_id ? `: ${note.target_id}` : ""}
                                    </span>
                                  )}
                                  {note.is_deleted && (
                                    <span className="badge badge-alert" style={{ fontSize: "9px" }}>
                                      TOMBSTONED
                                    </span>
                                  )}
                                </div>
                                {!note.is_deleted && (
                                  <button
                                    className="btn btn-secondary"
                                    style={{ padding: "2px 5px", fontSize: "10px", color: "var(--badge-alert-text)" }}
                                    onClick={() => handleDeleteNote(note.id)}
                                    title="Tombstone annotation"
                                  >
                                    <TrashIcon />
                                  </button>
                                )}
                              </div>
                              <p style={{
                                margin: 0,
                                fontSize: "12px",
                                whiteSpace: "pre-wrap",
                                color: note.is_deleted ? "var(--text-muted)" : "var(--text-primary)",
                                textDecoration: note.is_deleted ? "line-through" : "none",
                              }}>
                                {note.content}
                              </p>
                              {note.is_deleted && (
                                <div style={{ marginTop: "6px", fontSize: "10px", color: "var(--text-muted)", fontStyle: "italic" }}>
                                  Tombstoned by {note.deleted_by || "Analyst"} at {note.deleted_at ? new Date(note.deleted_at).toISOString().replace("T", " ") : "N/A"}: {note.deletion_reason || "Removed"}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* 8. AI Investigation Intelligence Tab */}
                {activeTab === "ai" && (
                  <InvestigationIntelligencePanel
                    incidentId={incidentId}
                    onSelectEventId={onSelectEventId}
                    onSelectAlertId={onSelectAlertId}
                    onSelectEntityKey={onSelectEntityKey}
                  />
                )}

                {/* 9. Evidence Workbench & Collections Tab (M7.3) */}
                {activeTab === "evidence" && (
                  <InvestigationEvidenceWorkbench
                    caseId={incidentId}
                    onSelectEventId={onSelectEventId}
                    onSelectAlertId={onSelectAlertId}
                    onSelectEntityKey={onSelectEntityKey}
                  />
                )}

                {/* 10. Findings & Hypothesis Workbench Tab (M7.4) */}
                {activeTab === "findings" && (
                  <InvestigationFindingsWorkbench
                    caseId={incidentId}
                    onSelectEventId={onSelectEventId}
                    onSelectAlertId={onSelectAlertId}
                    onSelectEntityKey={onSelectEntityKey}
                  />
                )}

                {/* 11. Threat Hunting Workbench Tab (M7.5) */}
                {activeTab === "hunting" && (
                  <InvestigationThreatHuntWorkbench
                    caseId={incidentId}
                    onSelectEventId={onSelectEventId}
                    onSelectAlertId={onSelectAlertId}
                    onSelectEntityKey={onSelectEntityKey}
                  />
                )}

                {/* 12. Investigation Report & Handoff Tab (M7.6) */}
                {activeTab === "report" && (
                  <InvestigationReportWorkbench
                    caseId={incidentId}
                    onSelectEventId={onSelectEventId}
                    onSelectAlertId={onSelectAlertId}
                  />
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
