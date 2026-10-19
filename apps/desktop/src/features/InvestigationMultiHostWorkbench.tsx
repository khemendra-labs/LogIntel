import React, { useState, useEffect, useRef } from "react";
import type {
  CaseHostSummary,
  CaseMultiHostDossier,
  HostTimelineResponse,
  HostVisibilityGap,
  HostDiscrepancy,
  InvestigationScope,
  ComparativeTimelineResponse,
  InvestigationTimelineItem,
  MultiHostExportResponse,
} from "../types/investigation";
import {
  fetchCaseMultiHostDossier,
  fetchCaseHostTimeline,
  fetchCaseComparativeTimeline,
  exportCaseMultiHostDossier,
  fetchCase,
  updateCaseScope,
} from "../lib/api";

export function formatSafeTimestamp(ts?: string | null, fallback = "N/A"): string {
  if (!ts) return fallback;
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return fallback;
    return d.toISOString().replace("T", " ");
  } catch {
    return fallback;
  }
}

export function formatSafeTimeOnly(ts?: string | null, fallback = "--:--:--"): string {
  if (!ts) return fallback;
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return fallback;
    return d.toISOString().substring(11, 19);
  } catch {
    return fallback;
  }
}

interface InvestigationMultiHostWorkbenchProps {
  caseId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export const InvestigationMultiHostWorkbench: React.FC<InvestigationMultiHostWorkbenchProps> = ({
  caseId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}) => {
  // Main dossier state
  const [dossier, setDossier] = useState<CaseMultiHostDossier | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Active sub-tab
  const [activeSubTab, setActiveSubTab] = useState<"inventory" | "timeline" | "lateral" | "continuity" | "gaps" | "scope">("inventory");

  // Host search / filter in inventory
  const [searchFilter, setSearchFilter] = useState<string>("");

  // Visual lateral topology state (M7.12.4)
  const [lateralViewMode, setLateralViewMode] = useState<"topology" | "cards">("topology");
  const [selectedTopologyHost, setSelectedTopologyHost] = useState<string | null>(null);
  const [selectedTopologyTraceId, setSelectedTopologyTraceId] = useState<string | null>(null);

  // Timeline view mode & comparative swimlanes state (M7.12.4)
  const [timelineMode, setTimelineMode] = useState<"comparative" | "single">("comparative");
  const [selectedComparativeHosts, setSelectedComparativeHosts] = useState<string[]>([]);
  const [comparativeData, setComparativeData] = useState<ComparativeTimelineResponse | null>(null);
  const [comparativeLoading, setComparativeLoading] = useState<boolean>(false);
  const [comparativeError, setComparativeError] = useState<string | null>(null);
  const [comparativeLimitPerLane, setComparativeLimitPerLane] = useState<number>(30);
  const [selectedEventDetail, setSelectedEventDetail] = useState<InvestigationTimelineItem | null>(null);

  // Single host timeline view state
  const [selectedHostId, setSelectedHostId] = useState<string | null>(null);
  const [timelineData, setTimelineData] = useState<HostTimelineResponse | null>(null);
  const [timelineLoading, setTimelineLoading] = useState<boolean>(false);
  const [timelineError, setTimelineError] = useState<string | null>(null);
  const [timelineOffset, setTimelineOffset] = useState<number>(0);
  const [timelineLimit] = useState<number>(50);
  const [timelineTimeStart, setTimelineTimeStart] = useState<string>("");
  const [timelineTimeEnd, setTimelineTimeEnd] = useState<string>("");

  // Scope editor state
  const [newTargetHostInput, setNewTargetHostInput] = useState<string>("");
  const [scopeSaving, setScopeSaving] = useState<boolean>(false);
  const [scopeMessage, setScopeMessage] = useState<{ text: string; isError: boolean } | null>(null);

  // Export & reporting state (M7.12.5)
  const [exportModalOpen, setExportModalOpen] = useState<boolean>(false);
  const [exportFormat, setExportFormat] = useState<"markdown" | "json">("markdown");
  const [exportLoading, setExportLoading] = useState<boolean>(false);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportData, setExportData] = useState<MultiHostExportResponse | null>(null);
  const [exportCopied, setExportCopied] = useState<boolean>(false);

  // Ref to cancel stale async requests when caseId or selectedHostId changes
  const activeCaseRef = useRef<number>(caseId);
  const activeHostRef = useRef<string | null>(null);

  // Load dossier when caseId changes
  useEffect(() => {
    activeCaseRef.current = caseId;
    activeHostRef.current = null;
    setDossier(null);
    setSelectedHostId(null);
    setTimelineData(null);
    setTimelineLoading(false);
    setTimelineError(null);
    setTimelineOffset(0);
    setTimelineTimeStart("");
    setTimelineTimeEnd("");
    setSearchFilter("");
    setNewTargetHostInput("");
    setScopeMessage(null);
    // Comparative and topology state reset
    setComparativeData(null);
    setComparativeLoading(false);
    setComparativeError(null);
    setSelectedComparativeHosts([]);
    setSelectedEventDetail(null);
    setSelectedTopologyHost(null);
    setSelectedTopologyTraceId(null);
    // Export state reset
    setExportModalOpen(false);
    setExportData(null);
    setExportLoading(false);
    setExportError(null);
    setExportCopied(false);
    loadDossier();
  }, [caseId]);

  const handleOpenExportModal = async (fmt: "markdown" | "json" = "markdown") => {
    setExportFormat(fmt);
    setExportModalOpen(true);
    setExportLoading(true);
    setExportError(null);
    setExportCopied(false);
    try {
      const res = await exportCaseMultiHostDossier(caseId, fmt);
      if (activeCaseRef.current === caseId) {
        setExportData(res);
      }
    } catch (err: any) {
      if (activeCaseRef.current === caseId) {
        setExportError(err.message || "Failed to generate multi-host export report");
      }
    } finally {
      if (activeCaseRef.current === caseId) {
        setExportLoading(false);
      }
    }
  };

  const handleSwitchExportFormat = async (fmt: "markdown" | "json") => {
    if (fmt === exportFormat && exportData) return;
    setExportFormat(fmt);
    setExportLoading(true);
    setExportError(null);
    setExportCopied(false);
    try {
      const res = await exportCaseMultiHostDossier(caseId, fmt);
      if (activeCaseRef.current === caseId) {
        setExportData(res);
      }
    } catch (err: any) {
      if (activeCaseRef.current === caseId) {
        setExportError(err.message || "Failed to generate multi-host export report");
      }
    } finally {
      if (activeCaseRef.current === caseId) {
        setExportLoading(false);
      }
    }
  };

  const handleCopyExportContent = () => {
    if (!exportData?.content) return;
    navigator.clipboard.writeText(exportData.content);
    setExportCopied(true);
    setTimeout(() => setExportCopied(false), 2500);
  };

  const loadDossier = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetchCaseMultiHostDossier(caseId);
      if (activeCaseRef.current === caseId) {
        setDossier(res);
        // Default selected comparative hosts to participating hosts
        if (res.participating_hosts.length > 0) {
          setSelectedComparativeHosts(res.participating_hosts.slice(0, 8).map((h) => h.host_id));
        }
        // If a host was selected, ensure it still exists in the new dossier
        if (selectedHostId) {
          const exists = res.participating_hosts.some(
            (h) => h.host_id.toLowerCase() === selectedHostId.toLowerCase()
          );
          if (!exists) {
            setSelectedHostId(null);
            setTimelineData(null);
          }
        }
      }
    } catch (err: any) {
      if (activeCaseRef.current === caseId) {
        setError(err.message || "Failed to load multi-host investigation dossier");
      }
    } finally {
      if (activeCaseRef.current === caseId) {
        setLoading(false);
      }
    }
  };

  // Load host timeline when selectedHostId, pagination, or time bounds change
  useEffect(() => {
    if (!selectedHostId) return;
    activeHostRef.current = selectedHostId;
    loadHostTimeline(selectedHostId, timelineOffset);
  }, [selectedHostId, timelineOffset]);

  const loadHostTimeline = async (hostId: string, offset: number) => {
    setTimelineLoading(true);
    setTimelineError(null);
    try {
      const res = await fetchCaseHostTimeline(caseId, hostId, {
        limit: timelineLimit,
        offset: offset,
        time_start: timelineTimeStart || undefined,
        time_end: timelineTimeEnd || undefined,
      });
      if (activeCaseRef.current === caseId && activeHostRef.current === hostId) {
        setTimelineData(res);
      }
    } catch (err: any) {
      if (activeCaseRef.current === caseId && activeHostRef.current === hostId) {
        setTimelineError(err.message || `Failed to retrieve timeline for host ${hostId}`);
      }
    } finally {
      if (activeCaseRef.current === caseId && activeHostRef.current === hostId) {
        setTimelineLoading(false);
      }
    }
  };

  // Load comparative timeline when in comparative mode
  useEffect(() => {
    if (activeSubTab === "timeline" && timelineMode === "comparative" && selectedComparativeHosts.length > 0) {
      loadComparativeTimeline(selectedComparativeHosts);
    }
  }, [activeSubTab, timelineMode, selectedComparativeHosts, caseId]);

  const loadComparativeTimeline = async (hostsToQuery: string[]) => {
    if (hostsToQuery.length === 0) {
      setComparativeData(null);
      return;
    }
    setComparativeLoading(true);
    setComparativeError(null);
    try {
      const res = await fetchCaseComparativeTimeline(caseId, {
        hosts: hostsToQuery.join(","),
        time_start: timelineTimeStart || undefined,
        time_end: timelineTimeEnd || undefined,
        limit_per_lane: comparativeLimitPerLane,
      });
      if (activeCaseRef.current === caseId) {
        setComparativeData(res);
      }
    } catch (err: any) {
      if (activeCaseRef.current === caseId) {
        setComparativeError(err.message || "Failed to retrieve comparative timeline swimlanes");
      }
    } finally {
      if (activeCaseRef.current === caseId) {
        setComparativeLoading(false);
      }
    }
  };

  const handleSelectHostForTimeline = (hostId: string) => {
    setSelectedHostId(hostId);
    setTimelineMode("single");
    setTimelineOffset(0);
    setActiveSubTab("timeline");
  };

  // Scope editing actions
  const handleAddTargetHost = async () => {
    const trimmed = newTargetHostInput.trim();
    if (!trimmed) return;

    setScopeSaving(true);
    setScopeMessage(null);
    try {
      const caseDetail = await fetchCase(caseId);
      const currentScope: InvestigationScope = caseDetail.scope || {
        investigation_id: caseId,
        subject_id: `case-${caseId}`,
        subject_type: "case",
        selected_entity_ids: [],
        selected_alert_ids: [],
        selected_detection_ids: [],
        selected_event_ids: [],
        target_hosts: [],
      };

      const existingTargets = currentScope.target_hosts || [];
      if (existingTargets.map((h) => h.toLowerCase()).includes(trimmed.toLowerCase())) {
        setScopeMessage({ text: `Host '${trimmed}' is already in target scope`, isError: true });
        setScopeSaving(false);
        return;
      }

      const updatedTargets = [...existingTargets, trimmed];
      await updateCaseScope(caseId, {
        ...currentScope,
        target_hosts: updatedTargets,
      });

      setNewTargetHostInput("");
      setScopeMessage({ text: `Target host '${trimmed}' added to investigation scope`, isError: false });
      await loadDossier();
    } catch (err: any) {
      setScopeMessage({ text: err.message || "Failed to update investigation scope", isError: true });
    } finally {
      setScopeSaving(false);
    }
  };

  const handleRemoveTargetHost = async (hostToRemove: string) => {
    setScopeSaving(true);
    setScopeMessage(null);
    try {
      const caseDetail = await fetchCase(caseId);
      const currentScope: InvestigationScope = caseDetail.scope;
      if (!currentScope) {
        throw new Error("Case scope not found");
      }

      const existingTargets = currentScope.target_hosts || [];
      const updatedTargets = existingTargets.filter(
        (h) => h.toLowerCase() !== hostToRemove.toLowerCase()
      );

      await updateCaseScope(caseId, {
        ...currentScope,
        target_hosts: updatedTargets,
      });

      setScopeMessage({ text: `Host '${hostToRemove}' removed from scope`, isError: false });
      await loadDossier();
    } catch (err: any) {
      setScopeMessage({ text: err.message || "Failed to update investigation scope", isError: true });
    } finally {
      setScopeSaving(false);
    }
  };

  // Filtered hosts
  const filteredHosts = (dossier?.participating_hosts || []).filter((h) => {
    if (!searchFilter) return true;
    const q = searchFilter.toLowerCase();
    return (
      h.host_id.toLowerCase().includes(q) ||
      h.hostname.toLowerCase().includes(q) ||
      (h.os_name && h.os_name.toLowerCase().includes(q))
    );
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px", height: "100%" }}>
      {/* Top Banner / Metrics Header */}
      <div
        className="panel"
        style={{
          padding: "12px 16px",
          background: "var(--bg-surface)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "2px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "12px",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>
              Multi-Host Investigation Workbench
            </span>
            <span className="badge badge-neutral" style={{ fontSize: "10px", fontFamily: "var(--font-mono)" }}>
              Case #{caseId}
            </span>
            {dossier?.is_scope_unspecified ? (
              <span className="badge badge-notice" style={{ fontSize: "10px" }} title="Scope dynamically derived from evidence">
                Dynamic Scope (All Evidence Hosts)
              </span>
            ) : (
              <span className="badge badge-neutral" style={{ fontSize: "10px" }}>
                Target Scope ({dossier?.scoped_hosts_count || 0} Scoped)
              </span>
            )}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "4px" }}>
            Case-scoped host inventory, cross-host lateral traces, and evidence-grounded timeline slicing.
          </div>
        </div>

        {/* Quick summary stats */}
        {dossier && (
          <div style={{ display: "flex", gap: "14px", alignItems: "center", fontSize: "11px" }}>
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>
                {dossier.total_hosts_count}
              </div>
              <div style={{ color: "var(--text-muted)", fontSize: "10px" }}>Total Hosts</div>
            </div>
            <div style={{ width: "1px", height: "20px", background: "var(--border-subtle)" }} />
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--badge-warn-text)" }}>
                {dossier.cross_host_hops_count}
              </div>
              <div style={{ color: "var(--text-muted)", fontSize: "10px" }}>Lateral Hops</div>
            </div>
            <div style={{ width: "1px", height: "20px", background: "var(--border-subtle)" }} />
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: "14px", fontWeight: 700, color: dossier.overall_visibility_gaps.length > 0 ? "var(--badge-alert-text)" : "var(--text-primary)" }}>
                {dossier.overall_visibility_gaps.length}
              </div>
              <div style={{ color: "var(--text-muted)", fontSize: "10px" }}>Visibility Gaps</div>
            </div>
            <div style={{ width: "1px", height: "20px", background: "var(--border-subtle)" }} />
            <div style={{ textAlign: "center" }}>
              <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--text-primary)" }}>
                {dossier.entity_continuity?.length || 0}
              </div>
              <div style={{ color: "var(--text-muted)", fontSize: "10px" }}>Cross-Host Entities</div>
            </div>
            <div style={{ width: "1px", height: "20px", background: "var(--border-subtle)" }} />
            <div>
              <button
                className="btn btn-primary"
                style={{
                  padding: "4px 10px",
                  fontSize: "11px",
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                }}
                onClick={() => handleOpenExportModal("markdown")}
                title="Export multi-host investigation report and provenance digest"
              >
                <span>Export Dossier</span>
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Navigation Sub-Tabs */}
      <div style={{ display: "flex", gap: "4px", borderBottom: "1px solid var(--border-subtle)" }}>
        <button
          className={`btn btn-secondary ${activeSubTab === "inventory" ? "active" : ""}`}
          style={{
            padding: "6px 14px",
            fontSize: "11px",
            borderBottom: activeSubTab === "inventory" ? "2px solid var(--border-dark)" : "none",
            fontWeight: activeSubTab === "inventory" ? 600 : 400,
          }}
          onClick={() => setActiveSubTab("inventory")}
        >
          Host Inventory ({dossier?.participating_hosts.length || 0})
        </button>

        <button
          className={`btn btn-secondary ${activeSubTab === "lateral" ? "active" : ""}`}
          style={{
            padding: "6px 14px",
            fontSize: "11px",
            borderBottom: activeSubTab === "lateral" ? "2px solid var(--border-dark)" : "none",
            fontWeight: activeSubTab === "lateral" ? 600 : 400,
          }}
          onClick={() => setActiveSubTab("lateral")}
        >
          Lateral Traces ({dossier?.lateral_traces.length || 0})
        </button>

        <button
          className={`btn btn-secondary ${activeSubTab === "continuity" ? "active" : ""}`}
          style={{
            padding: "6px 14px",
            fontSize: "11px",
            borderBottom: activeSubTab === "continuity" ? "2px solid var(--border-dark)" : "none",
            fontWeight: activeSubTab === "continuity" ? 600 : 400,
          }}
          onClick={() => setActiveSubTab("continuity")}
        >
          Cross-Host Entities ({dossier?.entity_continuity?.length || 0})
        </button>

        <button
          className={`btn btn-secondary ${activeSubTab === "timeline" ? "active" : ""}`}
          style={{
            padding: "6px 14px",
            fontSize: "11px",
            borderBottom: activeSubTab === "timeline" ? "2px solid var(--border-dark)" : "none",
            fontWeight: activeSubTab === "timeline" ? 600 : 400,
          }}
          onClick={() => setActiveSubTab("timeline")}
        >
          Comparative Timelines & Swimlanes {timelineMode === "single" && selectedHostId ? `(${selectedHostId})` : ""}
        </button>

        <button
          className={`btn btn-secondary ${activeSubTab === "gaps" ? "active" : ""}`}
          style={{
            padding: "6px 14px",
            fontSize: "11px",
            borderBottom: activeSubTab === "gaps" ? "2px solid var(--border-dark)" : "none",
            fontWeight: activeSubTab === "gaps" ? 600 : 400,
          }}
          onClick={() => setActiveSubTab("gaps")}
        >
          Visibility Gaps ({dossier?.overall_visibility_gaps.length || 0})
        </button>

        <button
          className={`btn btn-secondary ${activeSubTab === "scope" ? "active" : ""}`}
          style={{
            padding: "6px 14px",
            fontSize: "11px",
            borderBottom: activeSubTab === "scope" ? "2px solid var(--border-dark)" : "none",
            fontWeight: activeSubTab === "scope" ? 600 : 400,
          }}
          onClick={() => setActiveSubTab("scope")}
        >
          Scope Editor ({dossier?.scope_target_hosts.length || 0})
        </button>
      </div>

      {/* Loading & Global Error States */}
      {loading && (
        <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
          Assembling case-scoped multi-host dossier and reconciling evidence...
        </div>
      )}

      {error && !loading && (
        <div
          className="panel"
          style={{
            padding: "16px",
            background: "var(--badge-alert-bg)",
            border: "1px solid var(--badge-alert-border)",
            color: "var(--badge-alert-text)",
            fontSize: "12px",
          }}
        >
          <strong>Error loading Multi-Host Dossier:</strong> {error}
        </div>
      )}

      {/* Content Panes */}
      {!loading && !error && dossier && (
        <div style={{ flex: 1, overflowY: "auto" }}>
          {/* =========================================================================
              TAB 1: HOST INVENTORY
          ========================================================================= */}
          {activeSubTab === "inventory" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {/* Filter controls */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "10px" }}>
                <input
                  type="text"
                  placeholder="Filter by host identifier, hostname, or OS..."
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  style={{
                    padding: "6px 10px",
                    fontSize: "11px",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "2px",
                    width: "320px",
                    background: "var(--bg-surface)",
                  }}
                />
                <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                  Showing {filteredHosts.length} of {dossier.participating_hosts.length} participating hosts
                </span>
              </div>

              {/* Empty inventory state */}
              {dossier.participating_hosts.length === 0 && (
                <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)", border: "1px dashed var(--border-subtle)" }}>
                  No participating hosts discovered for Case #{caseId}. Add evidence references or configure target hosts in the Scope Editor.
                </div>
              )}

              {/* Host Cards */}
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {filteredHosts.map((host: CaseHostSummary) => {
                  const isUnknown = host.epistemic_status === "UNKNOWN";
                  const hasGaps = host.telemetry_gaps.length > 0;
                  const hasDiscrepancy = host.discrepancies.length > 0;

                  return (
                    <div
                      key={host.host_id}
                      className="panel"
                      style={{
                        padding: "12px 16px",
                        background: "var(--bg-surface)",
                        borderLeft: isUnknown
                          ? "3px solid #f59e0b"
                          : hasGaps
                          ? "3px solid #0284c7"
                          : "3px solid #10b981",
                        borderTop: "1px solid var(--border-subtle)",
                        borderRight: "1px solid var(--border-subtle)",
                        borderBottom: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "8px" }}>
                        <div>
                          <div style={{ display: "flex", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
                            <span style={{ fontFamily: "var(--font-mono)", fontSize: "13px", fontWeight: 700, color: "var(--text-primary)" }}>
                              {host.hostname || host.host_id}
                            </span>
                            {host.hostname !== host.host_id && (
                              <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-muted)" }}>
                                (ID: {host.host_id})
                              </span>
                            )}
                            <span className={`badge ${isUnknown ? "badge-warning" : "badge-neutral"}`} style={{ fontSize: "9px" }}>
                              {host.epistemic_status}
                            </span>
                            {host.is_in_target_scope && (
                              <span className="badge badge-notice" style={{ fontSize: "9px" }}>
                                SCOPED TARGET
                              </span>
                            )}
                            {hasGaps && (
                              <span className="badge badge-warning" style={{ fontSize: "9px" }}>
                                {host.telemetry_gaps.length} GAP(S)
                              </span>
                            )}
                            {hasDiscrepancy && (
                              <span className="badge badge-alert" style={{ fontSize: "9px" }}>
                                IDENTITY CONFLICT
                              </span>
                            )}
                          </div>

                          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "4px", display: "flex", gap: "16px", flexWrap: "wrap" }}>
                            <span>
                              OS: <strong>{host.os_name ? `${host.os_name} ${host.os_version || ""}`.trim() : "Uncataloged / Unknown"}</strong>
                            </span>
                            <span>
                              First Seen: <strong>{formatSafeTimestamp(host.first_seen)}</strong>
                            </span>
                            <span>
                              Last Seen: <strong>{formatSafeTimestamp(host.last_seen)}</strong>
                            </span>
                          </div>
                        </div>

                        {/* Action buttons */}
                        <div style={{ display: "flex", gap: "6px" }}>
                          <button
                            className="btn btn-secondary"
                            style={{ padding: "4px 8px", fontSize: "11px" }}
                            onClick={() => handleSelectHostForTimeline(host.host_id)}
                          >
                            View Host Timeline
                          </button>
                          {host.host_graph_available && onSelectEntityKey && (
                            <button
                              className="btn btn-secondary"
                              style={{ padding: "4px 8px", fontSize: "11px" }}
                              onClick={() => onSelectEntityKey(`host:${host.host_id}`)}
                              title="Inspect host telemetry attack graph"
                            >
                              Host Graph
                            </button>
                          )}
                          {onSelectEntityKey && (
                            <button
                              className="btn btn-secondary"
                              style={{ padding: "4px 8px", fontSize: "11px" }}
                              onClick={() => onSelectEntityKey(`host:${host.host_id}`)}
                              title="Pivot to entity in investigation graph"
                            >
                              Pivot Graph
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Evidence & Hop Counts */}
                      <div
                        style={{
                          display: "flex",
                          gap: "16px",
                          marginTop: "10px",
                          paddingTop: "8px",
                          borderTop: "1px solid var(--border-subtle)",
                          fontSize: "11px",
                          color: "var(--text-secondary)",
                          flexWrap: "wrap",
                        }}
                      >
                        <div>
                          Events: <strong>{host.event_count}</strong>
                        </div>
                        <div>
                          Alerts: <strong>{host.alert_count}</strong>
                        </div>
                        <div>
                          Inbound Lateral Hops: <strong>{host.inbound_lateral_hops}</strong>
                        </div>
                        <div>
                          Outbound Lateral Hops: <strong>{host.outbound_lateral_hops}</strong>
                        </div>
                        {host.evidence_references.length > 0 && (
                          <div style={{ display: "flex", gap: "4px", alignItems: "center" }}>
                            <span>Citations:</span>
                            {host.evidence_references.map((tag) => (
                              <span
                                key={tag}
                                className="badge badge-neutral"
                                style={{ fontSize: "9px", fontFamily: "var(--font-mono)", cursor: "pointer" }}
                                onClick={() => {
                                  if (tag.startsWith("[event:") && onSelectEventId) {
                                    onSelectEventId(tag.replace("[event:", "").replace("]", ""));
                                  } else if (tag.startsWith("[alert:") && onSelectAlertId) {
                                    onSelectAlertId(parseInt(tag.replace("[alert:", "").replace("]", ""), 10));
                                  }
                                }}
                              >
                                {tag}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Per-host Gaps Banner */}
                      {host.telemetry_gaps.length > 0 && (
                        <div style={{ marginTop: "8px", padding: "6px 10px", background: "var(--bg-surface-subtle)", border: "1px dashed #f59e0b", borderRadius: "2px", fontSize: "10px" }}>
                          {host.telemetry_gaps.map((g: HostVisibilityGap, idx: number) => (
                            <div key={idx} style={{ color: "var(--badge-warn-text)", margin: "2px 0" }}>
                              <strong>[{g.gap_type}]:</strong> {g.description} {g.remedy_suggestion ? `(${g.remedy_suggestion})` : ""}
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Identity discrepancies */}
                      {host.discrepancies.length > 0 && (
                        <div style={{ marginTop: "6px", padding: "6px 10px", background: "#fee2e2", border: "1px solid #fca5a5", borderRadius: "2px", fontSize: "10px", color: "var(--badge-alert-text)" }}>
                          {host.discrepancies.map((d: HostDiscrepancy, idx: number) => (
                            <div key={idx}>
                              <strong>Conflict on {d.field}:</strong> {d.description}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* =========================================================================
              TAB 2: LATERAL MOVEMENT TRACES & TOPOLOGY (M7.12.4)
          ========================================================================= */}
          {activeSubTab === "lateral" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: "8px",
                  padding: "8px 12px",
                  background: "var(--bg-surface-subtle)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "2px",
                }}
              >
                <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                  Reconstructed cross-host progressions preserving original source and target identities, hop counts, and timestamps.
                </div>
                <div style={{ display: "flex", gap: "4px" }}>
                  <button
                    className={`btn btn-secondary ${lateralViewMode === "topology" ? "active" : ""}`}
                    style={{
                      padding: "4px 10px",
                      fontSize: "10px",
                      fontWeight: lateralViewMode === "topology" ? 600 : 400,
                    }}
                    onClick={() => setLateralViewMode("topology")}
                  >
                    Visual Topology Graph
                  </button>
                  <button
                    className={`btn btn-secondary ${lateralViewMode === "cards" ? "active" : ""}`}
                    style={{
                      padding: "4px 10px",
                      fontSize: "10px",
                      fontWeight: lateralViewMode === "cards" ? 600 : 400,
                    }}
                    onClick={() => setLateralViewMode("cards")}
                  >
                    Trace Details List ({dossier.lateral_traces.length})
                  </button>
                </div>
              </div>

              {dossier.lateral_traces.length === 0 ? (
                <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)", border: "1px dashed var(--border-subtle)" }}>
                  No cross-host lateral movement traces reconstructed from current evidence.
                </div>
              ) : lateralViewMode === "topology" ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  {/* SVG Node-Link Diagram Canvas */}
                  {(() => {
                    // Extract all unique host IDs from lateral traces
                    const traceHostIds = Array.from(
                      new Set(dossier.lateral_traces.flatMap((t) => [t.source_host, t.target_host]))
                    );

                    // Compute in/out degrees to partition into source, intermediary, and target columns
                    const inDegrees: Record<string, number> = {};
                    const outDegrees: Record<string, number> = {};
                    traceHostIds.forEach((h) => {
                      inDegrees[h] = 0;
                      outDegrees[h] = 0;
                    });
                    dossier.lateral_traces.forEach((t) => {
                      if (outDegrees[t.source_host] !== undefined) outDegrees[t.source_host]++;
                      if (inDegrees[t.target_host] !== undefined) inDegrees[t.target_host]++;
                    });

                    // Determine column assignments
                    const sources = traceHostIds.filter((h) => outDegrees[h] > 0 && inDegrees[h] === 0);
                    const intermediates = traceHostIds.filter((h) => outDegrees[h] > 0 && inDegrees[h] > 0);
                    const targets = traceHostIds.filter((h) => outDegrees[h] === 0 && inDegrees[h] > 0);
                    const others = traceHostIds.filter((h) => !sources.includes(h) && !intermediates.includes(h) && !targets.includes(h));

                    // Layout coordinates map
                    const positions: Record<string, { x: number; y: number }> = {};
                    const colX = [140, 410, 680];
                    if (intermediates.length === 0 && others.length === 0) {
                      colX[0] = 180;
                      colX[2] = 640;
                    }

                    const assignCol = (hosts: string[], colIndex: number) => {
                      const total = hosts.length;
                      hosts.forEach((h, idx) => {
                        const y = total === 1 ? 190 : 80 + (idx / (total - 1)) * 220;
                        positions[h] = { x: colX[colIndex], y };
                      });
                    };

                    assignCol(sources, 0);
                    assignCol(intermediates.concat(others), 1);
                    assignCol(targets, 2);

                    const selectedHostData = selectedTopologyHost
                      ? dossier.participating_hosts.find((h) => h.host_id === selectedTopologyHost)
                      : null;
                    const selectedTraceData = selectedTopologyTraceId
                      ? dossier.lateral_traces.find((t) => t.trace_id === selectedTopologyTraceId)
                      : null;

                    return (
                      <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                        <div
                          className="panel"
                          style={{
                            padding: "16px",
                            background: "var(--bg-surface)",
                            border: "1px solid var(--border-subtle)",
                            borderRadius: "4px",
                            overflowX: "auto",
                          }}
                        >
                          <svg
                            viewBox="0 0 820 380"
                            style={{
                              width: "100%",
                              minWidth: "750px",
                              height: "380px",
                              display: "block",
                            }}
                          >
                            <defs>
                              <marker
                                id="topo-arrow"
                                viewBox="0 0 10 10"
                                refX="10"
                                refY="5"
                                markerWidth="6"
                                markerHeight="6"
                                orient="auto-start-reverse"
                              >
                                <path d="M 0 0 L 10 5 L 0 10 z" fill="#6366f1" />
                              </marker>
                              <marker
                                id="topo-arrow-selected"
                                viewBox="0 0 10 10"
                                refX="10"
                                refY="5"
                                markerWidth="7"
                                markerHeight="7"
                                orient="auto-start-reverse"
                              >
                                <path d="M 0 0 L 10 5 L 0 10 z" fill="#a855f7" />
                              </marker>
                            </defs>

                            {/* Render Directed Edges */}
                            {dossier.lateral_traces.map((trace) => {
                              const srcPos = positions[trace.source_host];
                              const tgtPos = positions[trace.target_host];
                              if (!srcPos || !tgtPos) return null;

                              const isSelected = selectedTopologyTraceId === trace.trace_id;
                              const isSrcSelected = selectedTopologyHost === trace.source_host;
                              const isTgtSelected = selectedTopologyHost === trace.target_host;
                              const isHighlighted = isSelected || isSrcSelected || isTgtSelected;

                              const startX = srcPos.x + 78;
                              const startY = srcPos.y;
                              const endX = tgtPos.x - 78;
                              const endY = tgtPos.y;

                              const deltaX = Math.abs(endX - startX) * 0.5;
                              const pathD = `M ${startX} ${startY} C ${startX + deltaX} ${startY}, ${endX - deltaX} ${endY}, ${endX} ${endY}`;
                              const midX = (startX + endX) / 2;
                              const midY = (startY + endY) / 2;

                              return (
                                <g
                                  key={trace.trace_id}
                                  style={{ cursor: "pointer" }}
                                  onClick={() => {
                                    setSelectedTopologyTraceId(trace.trace_id);
                                    setSelectedTopologyHost(null);
                                  }}
                                >
                                  <path
                                    d={pathD}
                                    fill="none"
                                    stroke={isHighlighted ? "#a855f7" : "#6366f1"}
                                    strokeWidth={isHighlighted ? "3" : "1.8"}
                                    strokeDasharray={trace.epistemic_status === "INFERRED" ? "4,4" : undefined}
                                    markerEnd={isHighlighted ? "url(#topo-arrow-selected)" : "url(#topo-arrow)"}
                                  />
                                  {/* Hop badge on edge */}
                                  <rect
                                    x={midX - 52}
                                    y={midY - 11}
                                    width="104"
                                    height="22"
                                    rx="11"
                                    fill={isHighlighted ? "#581c87" : "#1e1b4b"}
                                    stroke={isHighlighted ? "#c084fc" : "#818cf8"}
                                    strokeWidth="1"
                                  />
                                  <text
                                    x={midX}
                                    y={midY + 4}
                                    textAnchor="middle"
                                    fill="#f1f5f9"
                                    fontSize="10"
                                    fontFamily="var(--font-mono, monospace)"
                                    fontWeight="600"
                                  >
                                    {trace.hop_count} Hop · {trace.actor || "lateral"}
                                  </text>
                                </g>
                              );
                            })}

                            {/* Render Host Nodes */}
                            {traceHostIds.map((hostId) => {
                              const pos = positions[hostId];
                              if (!pos) return null;

                              const isSelected = selectedTopologyHost === hostId;
                              const hostSummary = dossier.participating_hosts.find((h) => h.host_id === hostId);
                              const isUnknown = hostSummary?.epistemic_status === "UNKNOWN";

                              return (
                                <g
                                  key={hostId}
                                  style={{ cursor: "pointer" }}
                                  onClick={() => {
                                    setSelectedTopologyHost(hostId);
                                    setSelectedTopologyTraceId(null);
                                  }}
                                >
                                  {/* Host Card Outer Box */}
                                  <rect
                                    x={pos.x - 78}
                                    y={pos.y - 28}
                                    width="156"
                                    height="56"
                                    rx="6"
                                    fill={isSelected ? "#312e81" : "var(--bg-surface, #1e1e2e)"}
                                    stroke={
                                      isSelected
                                        ? "#a855f7"
                                        : isUnknown
                                        ? "#f59e0b"
                                        : "var(--border-subtle, #4b5563)"
                                    }
                                    strokeWidth={isSelected ? "2.5" : "1.2"}
                                  />

                                  {/* Host Name / Title */}
                                  <text
                                    x={pos.x}
                                    y={pos.y - 8}
                                    textAnchor="middle"
                                    fill="var(--text-primary, #f9fafb)"
                                    fontSize="11"
                                    fontWeight="700"
                                    fontFamily="var(--font-mono, monospace)"
                                  >
                                    {hostSummary?.hostname || hostId}
                                  </text>

                                  {/* Sub-label with ID / In-Out counts */}
                                  <text
                                    x={pos.x}
                                    y={pos.y + 8}
                                    textAnchor="middle"
                                    fill="var(--text-secondary, #9ca3af)"
                                    fontSize="9"
                                    fontFamily="var(--font-mono, monospace)"
                                  >
                                    in: {inDegrees[hostId] || 0} · out: {outDegrees[hostId] || 0}
                                  </text>

                                  {/* Status badge at bottom of node */}
                                  <rect
                                    x={pos.x - 36}
                                    y={pos.y + 13}
                                    width="72"
                                    height="12"
                                    rx="6"
                                    fill={isUnknown ? "#78350f" : "#065f46"}
                                  />
                                  <text
                                    x={pos.x}
                                    y={pos.y + 22}
                                    textAnchor="middle"
                                    fill="#ecfdf5"
                                    fontSize="7.5"
                                    fontWeight="600"
                                  >
                                    {hostSummary?.epistemic_status || "OBSERVED"}
                                  </text>
                                </g>
                              );
                            })}
                          </svg>
                        </div>

                        {/* Interactive Inspector Panel for Selected Node or Edge */}
                        {selectedHostData && (
                          <div
                            className="panel"
                            style={{
                              padding: "12px 16px",
                              background: "var(--bg-surface)",
                              border: "1px solid var(--border-subtle)",
                              borderLeft: "3px solid #6366f1",
                              borderRadius: "2px",
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                              flexWrap: "wrap",
                              gap: "10px",
                            }}
                          >
                            <div>
                              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                <span style={{ fontSize: "12px", fontWeight: 700 }}>
                                  Selected Host: {selectedHostData.hostname} ({selectedHostData.host_id})
                                </span>
                                <span className="badge badge-notice" style={{ fontSize: "9px" }}>
                                  {selectedHostData.epistemic_status}
                                </span>
                                {selectedHostData.os_name && (
                                  <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                                    {selectedHostData.os_name} {selectedHostData.os_version || ""}
                                  </span>
                                )}
                              </div>
                              <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "4px" }}>
                                Events: {selectedHostData.event_count} · Alerts: {selectedHostData.alert_count} · Inbound Hops: {selectedHostData.inbound_lateral_hops} · Outbound Hops: {selectedHostData.outbound_lateral_hops}
                              </div>
                            </div>

                            <div style={{ display: "flex", gap: "8px" }}>
                              <button
                                className="btn btn-primary"
                                style={{ padding: "4px 10px", fontSize: "10px" }}
                                onClick={() => handleSelectHostForTimeline(selectedHostData.host_id)}
                              >
                                View Single Host Timeline &rarr;
                              </button>
                              <button
                                className="btn btn-secondary"
                                style={{ padding: "4px 10px", fontSize: "10px" }}
                                onClick={() => {
                                  setSelectedComparativeHosts([selectedHostData.host_id]);
                                  setTimelineMode("comparative");
                                  setActiveSubTab("timeline");
                                }}
                              >
                                Slice in Swimlanes &rarr;
                              </button>
                            </div>
                          </div>
                        )}

                        {selectedTraceData && (
                          <div
                            className="panel"
                            style={{
                              padding: "12px 16px",
                              background: "var(--bg-surface)",
                              border: "1px solid var(--border-subtle)",
                              borderLeft: "3px solid #a855f7",
                              borderRadius: "2px",
                              display: "flex",
                              justifyContent: "space-between",
                              alignItems: "center",
                              flexWrap: "wrap",
                              gap: "10px",
                            }}
                          >
                            <div>
                              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                <span style={{ fontSize: "12px", fontWeight: 700 }}>
                                  Selected Trace: {selectedTraceData.trace_id}
                                </span>
                                <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                                  {selectedTraceData.hop_count} Hop(s)
                                </span>
                                <span className="badge badge-notice" style={{ fontSize: "9px" }}>
                                  {selectedTraceData.epistemic_status}
                                </span>
                              </div>
                              <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "4px" }}>
                                Progression: <strong>{selectedTraceData.source_host}</strong> &rarr; <strong>{selectedTraceData.target_host}</strong> (Actor: {selectedTraceData.actor})
                              </div>
                              <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "2px" }}>
                                Window: {formatSafeTimestamp(selectedTraceData.start_time)} to {formatSafeTimestamp(selectedTraceData.end_time)}
                              </div>
                            </div>

                            <div style={{ display: "flex", gap: "6px" }}>
                              <button
                                className="btn btn-secondary"
                                style={{ padding: "4px 8px", fontSize: "10px" }}
                                onClick={() => handleSelectHostForTimeline(selectedTraceData.source_host)}
                              >
                                Source Host: {selectedTraceData.source_host}
                              </button>
                              <button
                                className="btn btn-secondary"
                                style={{ padding: "4px 8px", fontSize: "10px" }}
                                onClick={() => handleSelectHostForTimeline(selectedTraceData.target_host)}
                              >
                                Target Host: {selectedTraceData.target_host}
                              </button>
                            </div>
                          </div>
                        )}
                      </div>
                    );
                  })()}
                </div>
              ) : (
                /* Detailed Cards View */
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {dossier.lateral_traces.map((trace) => (
                    <div
                      key={trace.trace_id}
                      className="panel"
                      style={{
                        padding: "12px 16px",
                        background: "var(--bg-surface)",
                        borderLeft: "3px solid #6366f1",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700 }}>
                            {trace.trace_id}
                          </span>
                          <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                            {trace.hop_count} Hop(s)
                          </span>
                          <span className="badge badge-notice" style={{ fontSize: "9px" }}>
                            {trace.epistemic_status}
                          </span>
                        </div>
                        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                          Actor:{" "}
                          <strong
                            style={{
                              cursor: onSelectEntityKey ? "pointer" : "default",
                              color: onSelectEntityKey ? "var(--color-primary, #6366f1)" : "inherit",
                              textDecoration: onSelectEntityKey ? "underline" : "none",
                            }}
                            onClick={() => {
                              if (onSelectEntityKey && trace.actor) {
                                onSelectEntityKey(`user:${trace.actor}`);
                              }
                            }}
                            title={onSelectEntityKey ? "Click to pivot to user in Entity Pivot Modal" : undefined}
                          >
                            {trace.actor}
                          </strong>
                        </div>
                      </div>

                      {/* Directional Hop Banner */}
                      <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "8px 0", fontSize: "12px", fontWeight: 600 }}>
                        <span
                          style={{ fontFamily: "var(--font-mono)", color: "var(--text-primary)", cursor: "pointer", textDecoration: "underline" }}
                          onClick={() => handleSelectHostForTimeline(trace.source_host)}
                          title="Click to view host timeline"
                        >
                          {trace.source_host}
                        </span>
                        <span style={{ color: "#6366f1" }}>&rarr; (Lateral Movement) &rarr;</span>
                        <span
                          style={{ fontFamily: "var(--font-mono)", color: "var(--text-primary)", cursor: "pointer", textDecoration: "underline" }}
                          onClick={() => handleSelectHostForTimeline(trace.target_host)}
                          title="Click to view host timeline"
                        >
                          {trace.target_host}
                        </span>
                      </div>

                      <div style={{ fontSize: "11px", color: "var(--text-muted)", display: "flex", gap: "16px" }}>
                        <span>Start: {formatSafeTimestamp(trace.start_time)}</span>
                        <span>End: {formatSafeTimestamp(trace.end_time)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* =========================================================================
              TAB 3: CROSS-HOST ENTITY CONTINUITY (M7.12.3)
          ========================================================================= */}
          {activeSubTab === "continuity" && (
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
                Entities correlated across multiple participating hosts (shared user accounts, common external/source IPs). Preserves source-host attribution and evidence provenance.
              </div>

              {!dossier.entity_continuity || dossier.entity_continuity.length === 0 ? (
                <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)", border: "1px dashed var(--border-subtle)" }}>
                  No cross-host entity continuities identified in current case scope.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {dossier.entity_continuity.map((cont) => (
                    <div
                      key={cont.continuity_id}
                      className="panel"
                      style={{
                        padding: "12px 16px",
                        background: "var(--bg-surface)",
                        borderLeft: cont.continuity_type === "SAME_ACCOUNT_ACROSS_HOSTS" ? "3px solid #10b981" : "3px solid #f59e0b",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "8px", flexWrap: "wrap", gap: "6px" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700 }}>
                            {cont.continuity_id}
                          </span>
                          <span className={cont.continuity_type === "SAME_ACCOUNT_ACROSS_HOSTS" ? "badge badge-notice" : "badge badge-neutral"} style={{ fontSize: "9px" }}>
                            {cont.continuity_type === "SAME_ACCOUNT_ACROSS_HOSTS" ? "SHARED ACCOUNT" : "SHARED SOURCE IP"}
                          </span>
                          <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                            {cont.occurrences_count} Occurrences
                          </span>
                        </div>

                        {onSelectEntityKey && (
                          <button
                            className="btn btn-secondary"
                            style={{ padding: "3px 8px", fontSize: "10px" }}
                            onClick={() => onSelectEntityKey(cont.entity_key)}
                            title={`Pivot to ${cont.entity_key} in Entity Pivot Modal`}
                          >
                            Pivot Entity &rarr;
                          </button>
                        )}
                      </div>

                      {/* Correlated Entity Key */}
                      <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "6px" }}>
                        <span style={{ fontSize: "11px", color: "var(--text-secondary)" }}>Entity Key:</span>
                        <span
                          style={{
                            fontFamily: "var(--font-mono)",
                            fontSize: "12px",
                            fontWeight: 700,
                            color: onSelectEntityKey ? "var(--color-primary, #6366f1)" : "var(--text-primary)",
                            cursor: onSelectEntityKey ? "pointer" : "default",
                            textDecoration: onSelectEntityKey ? "underline" : "none",
                          }}
                          onClick={() => {
                            if (onSelectEntityKey) onSelectEntityKey(cont.entity_key);
                          }}
                          title={onSelectEntityKey ? "Click to open Entity Pivot Modal" : undefined}
                        >
                          {cont.entity_key}
                        </span>
                      </div>

                      {/* Description */}
                      <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginBottom: "8px" }}>
                        {cont.description}
                      </div>

                      {/* Participating Hosts */}
                      <div style={{ display: "flex", alignItems: "center", gap: "6px", flexWrap: "wrap", fontSize: "11px" }}>
                        <span style={{ color: "var(--text-muted)" }}>Participating Hosts:</span>
                        {cont.participating_hosts.map((hostId) => (
                          <span
                            key={hostId}
                            className="badge badge-neutral"
                            style={{
                              fontFamily: "var(--font-mono)",
                              fontSize: "10px",
                              cursor: "pointer",
                            }}
                            onClick={() => handleSelectHostForTimeline(hostId)}
                            title="Click to view host timeline"
                          >
                            {hostId}
                          </span>
                        ))}
                      </div>

                      {/* Evidence Citations */}
                      {cont.evidence_references && cont.evidence_references.length > 0 && (
                        <div style={{ display: "flex", gap: "6px", alignItems: "center", marginTop: "8px", paddingTop: "6px", borderTop: "1px solid var(--border-subtle)", fontSize: "10px" }}>
                          <span style={{ color: "var(--text-muted)" }}>Evidence Citations:</span>
                          {cont.evidence_references.map((ev, idx) => {
                            const tag = ev.citation_tag || `[${ev.source_type}:${ev.source_id}]`;
                            return (
                              <span
                                key={idx}
                                className="badge badge-neutral"
                                style={{ fontSize: "9px", fontFamily: "var(--font-mono)", cursor: "pointer" }}
                                onClick={() => {
                                  if (ev.source_type === "event" && onSelectEventId) {
                                    onSelectEventId(String(ev.source_id));
                                  } else if (ev.source_type === "alert" && onSelectAlertId) {
                                    onSelectAlertId(parseInt(String(ev.source_id), 10));
                                  }
                                }}
                              >
                                {tag}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* =========================================================================
              TAB 4: COMPARATIVE TIMELINE SWIMLANES & SINGLE HOST TIMELINE (M7.12.4)
          ========================================================================= */}
          {activeSubTab === "timeline" && (
            <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
              {/* Mode Toggle & Shared Query Controls */}
              <div
                className="panel"
                style={{
                  padding: "12px",
                  background: "var(--bg-surface)",
                  border: "1px solid var(--border-subtle)",
                  borderRadius: "2px",
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  flexWrap: "wrap",
                  gap: "10px",
                }}
              >
                {/* View Mode Toggle */}
                <div style={{ display: "flex", gap: "4px" }}>
                  <button
                    className={`btn btn-secondary ${timelineMode === "comparative" ? "active" : ""}`}
                    style={{
                      padding: "4px 10px",
                      fontSize: "10px",
                      fontWeight: timelineMode === "comparative" ? 600 : 400,
                    }}
                    onClick={() => setTimelineMode("comparative")}
                  >
                    Comparative Swimlanes ({selectedComparativeHosts.length} Hosts)
                  </button>
                  <button
                    className={`btn btn-secondary ${timelineMode === "single" ? "active" : ""}`}
                    style={{
                      padding: "4px 10px",
                      fontSize: "10px",
                      fontWeight: timelineMode === "single" ? 600 : 400,
                    }}
                    onClick={() => setTimelineMode("single")}
                  >
                    Single Host View {selectedHostId ? `(${selectedHostId})` : ""}
                  </button>
                </div>

                {/* Time Range Filters */}
                <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                  <label style={{ fontSize: "11px" }}>From:</label>
                  <input
                    type="text"
                    placeholder="YYYY-MM-DDTHH:MM:SSZ"
                    value={timelineTimeStart}
                    onChange={(e) => setTimelineTimeStart(e.target.value)}
                    style={{ padding: "4px 6px", fontSize: "10px", width: "150px", border: "1px solid var(--border-subtle)", background: "var(--bg-surface)" }}
                  />
                  <label style={{ fontSize: "11px" }}>To:</label>
                  <input
                    type="text"
                    placeholder="YYYY-MM-DDTHH:MM:SSZ"
                    value={timelineTimeEnd}
                    onChange={(e) => setTimelineTimeEnd(e.target.value)}
                    style={{ padding: "4px 6px", fontSize: "10px", width: "150px", border: "1px solid var(--border-subtle)", background: "var(--bg-surface)" }}
                  />
                  {timelineMode === "comparative" ? (
                    <button
                      className="btn btn-secondary"
                      style={{ padding: "4px 8px", fontSize: "10px" }}
                      onClick={() => loadComparativeTimeline(selectedComparativeHosts)}
                    >
                      Refresh Swimlanes
                    </button>
                  ) : (
                    <button
                      className="btn btn-secondary"
                      style={{ padding: "4px 8px", fontSize: "10px" }}
                      onClick={() => {
                        if (selectedHostId) {
                          setTimelineOffset(0);
                          loadHostTimeline(selectedHostId, 0);
                        }
                      }}
                    >
                      Apply Filter
                    </button>
                  )}
                </div>
              </div>

              {/* COMPARATIVE SWIMLANES VIEW */}
              {timelineMode === "comparative" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                  {/* Host Selector Pills */}
                  <div
                    className="panel"
                    style={{
                      padding: "8px 12px",
                      background: "var(--bg-surface-subtle)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "2px",
                      display: "flex",
                      flexDirection: "column",
                      gap: "6px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span style={{ fontSize: "10px", fontWeight: 600, color: "var(--text-secondary)" }}>
                        Select Participating Hosts to Align in Parallel Swimlanes:
                      </span>
                      <div style={{ display: "flex", gap: "6px" }}>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "2px 6px", fontSize: "9px" }}
                          onClick={() => {
                            const allIds = dossier.participating_hosts.map((h) => h.host_id);
                            setSelectedComparativeHosts(allIds);
                            loadComparativeTimeline(allIds);
                          }}
                        >
                          Select All ({dossier.participating_hosts.length})
                        </button>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "2px 6px", fontSize: "9px" }}
                          onClick={() => {
                            setSelectedComparativeHosts([]);
                            setComparativeData(null);
                          }}
                        >
                          Clear
                        </button>
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                      {dossier.participating_hosts.map((h) => {
                        const isSelected = selectedComparativeHosts.includes(h.host_id);
                        return (
                          <button
                            key={h.host_id}
                            className={`badge ${isSelected ? "badge-neutral active" : "badge-neutral"}`}
                            style={{
                              padding: "4px 8px",
                              fontSize: "10px",
                              fontFamily: "var(--font-mono)",
                              cursor: "pointer",
                              border: isSelected ? "1px solid #6366f1" : "1px solid var(--border-subtle)",
                              background: isSelected ? "#312e81" : "var(--bg-surface)",
                              color: isSelected ? "#e0e7ff" : "var(--text-secondary)",
                            }}
                            onClick={() => {
                              const updated = isSelected
                                ? selectedComparativeHosts.filter((id) => id !== h.host_id)
                                : [...selectedComparativeHosts, h.host_id];
                              setSelectedComparativeHosts(updated);
                              loadComparativeTimeline(updated);
                            }}
                          >
                            {isSelected ? "✓ " : "+ "}
                            {h.hostname || h.host_id} ({h.event_count} ev)
                          </button>
                        );
                      })}
                    </div>
                  </div>

                  {/* Aligned Window Summary Banner */}
                  {comparativeData && (
                    <div
                      style={{
                        padding: "6px 12px",
                        background: "var(--bg-surface)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        fontSize: "10px",
                        color: "var(--text-muted)",
                      }}
                    >
                      <div>
                        Synchronized Time Bounds:{" "}
                        <strong style={{ color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>
                          {formatSafeTimestamp(comparativeData.aligned_min_time)}
                        </strong>{" "}
                        &rarr;{" "}
                        <strong style={{ color: "var(--text-primary)", fontFamily: "var(--font-mono)" }}>
                          {formatSafeTimestamp(comparativeData.aligned_max_time)}
                        </strong>
                      </div>
                      <div>
                        Total Events Across Lanes: <strong>{comparativeData.total_events}</strong>
                      </div>
                    </div>
                  )}

                  {/* Loading & Error States */}
                  {comparativeLoading && (
                    <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                      Synchronizing comparative multi-host swimlanes...
                    </div>
                  )}

                  {comparativeError && (
                    <div style={{ padding: "12px", background: "var(--badge-alert-bg)", border: "1px solid var(--badge-alert-border)", color: "var(--badge-alert-text)", fontSize: "11px" }}>
                      {comparativeError}
                    </div>
                  )}

                  {/* Empty state when no hosts selected */}
                  {selectedComparativeHosts.length === 0 && !comparativeLoading && (
                    <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)", border: "1px dashed var(--border-subtle)" }}>
                      No hosts selected for comparative swimlanes. Use the host pills above to select hosts.
                    </div>
                  )}

                  {/* Render Lanes */}
                  {!comparativeLoading && comparativeData && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                      {comparativeData.lanes.map((lane) => (
                        <div
                          key={lane.host_id}
                          className="panel"
                          style={{
                            padding: "10px 14px",
                            background: "var(--bg-surface)",
                            border: "1px solid var(--border-subtle)",
                            borderRadius: "3px",
                            display: "flex",
                            flexDirection: "column",
                            gap: "8px",
                          }}
                        >
                          {/* Lane Header */}
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                              <span style={{ fontSize: "12px", fontWeight: 700, fontFamily: "var(--font-mono)" }}>
                                {lane.hostname || lane.host_id}
                              </span>
                              <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                                {lane.total} Events in Window
                              </span>
                              {lane.first_seen && (
                                <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                                  ({formatSafeTimestamp(lane.first_seen)} &rarr; {formatSafeTimestamp(lane.last_seen)})
                                </span>
                              )}
                            </div>

                            <button
                              className="btn btn-secondary"
                              style={{ padding: "2px 8px", fontSize: "9px" }}
                              onClick={() => {
                                setSelectedHostId(lane.host_id);
                                setTimelineMode("single");
                              }}
                            >
                              Focus Single Host Timeline &rarr;
                            </button>
                          </div>

                          {/* Horizontal Swimlane Track */}
                          {lane.items.length === 0 ? (
                            <div style={{ padding: "12px", textAlign: "center", fontSize: "10px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)", borderRadius: "2px" }}>
                              Zero events observed on this host within the active time window.
                            </div>
                          ) : (
                            <div
                              style={{
                                display: "flex",
                                gap: "8px",
                                overflowX: "auto",
                                padding: "6px 2px",
                              }}
                            >
                              {lane.items.map((item) => {
                                const isSelected = selectedEventDetail?.timeline_id === item.timeline_id;
                                return (
                                  <div
                                    key={item.timeline_id}
                                    style={{
                                      minWidth: "170px",
                                      maxWidth: "200px",
                                      padding: "8px",
                                      background: isSelected ? "#312e81" : "var(--bg-surface-subtle)",
                                      border: isSelected ? "1px solid #818cf8" : "1px solid var(--border-subtle)",
                                      borderRadius: "3px",
                                      cursor: "pointer",
                                      fontSize: "10px",
                                      display: "flex",
                                      flexDirection: "column",
                                      gap: "3px",
                                      flexShrink: 0,
                                    }}
                                    onClick={() => setSelectedEventDetail(item)}
                                    title="Click to view full event citations and details"
                                  >
                                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                      <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-muted)", fontSize: "9px" }}>
                                        {formatSafeTimeOnly(item.timestamp)}
                                      </span>
                                      <span className="badge badge-neutral" style={{ fontSize: "8px" }}>
                                        {item.source_layer}
                                      </span>
                                    </div>
                                    <div style={{ fontWeight: 600, color: "var(--text-primary)", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                                      {item.event_type}
                                    </div>
                                    <div style={{ color: "var(--text-secondary)", fontSize: "9px", overflow: "hidden", display: "-webkit-box", WebkitLineClamp: 2, WebkitBoxOrient: "vertical" }}>
                                      {item.display_summary}
                                    </div>
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Event Detail Modal / Drawer */}
                  {selectedEventDetail && (
                    <div
                      className="panel"
                      style={{
                        padding: "12px 16px",
                        background: "var(--bg-surface)",
                        border: "1px solid #6366f1",
                        borderRadius: "3px",
                        display: "flex",
                        flexDirection: "column",
                        gap: "6px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontSize: "12px", fontWeight: 700 }}>
                            Event Detail: {selectedEventDetail.event_type} ({selectedEventDetail.timeline_id})
                          </span>
                          <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                            {selectedEventDetail.source_layer}
                          </span>
                          <span className="badge badge-notice" style={{ fontSize: "9px" }}>
                            {selectedEventDetail.epistemic_status}
                          </span>
                        </div>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "2px 8px", fontSize: "10px" }}
                          onClick={() => setSelectedEventDetail(null)}
                        >
                          ✕ Close Detail
                        </button>
                      </div>

                      <div style={{ fontSize: "11px", color: "var(--text-primary)", marginTop: "2px" }}>
                        {selectedEventDetail.display_summary}
                      </div>

                      <div style={{ fontSize: "10px", color: "var(--text-muted)", display: "flex", gap: "16px", marginTop: "2px" }}>
                        <span>Host: <strong>{selectedEventDetail.host_id}</strong></span>
                        <span>Timestamp: <strong>{formatSafeTimestamp(selectedEventDetail.timestamp)}</strong></span>
                      </div>

                      {/* Evidence Citations */}
                      {selectedEventDetail.evidence_refs && selectedEventDetail.evidence_refs.length > 0 && (
                        <div style={{ display: "flex", gap: "4px", alignItems: "center", marginTop: "4px" }}>
                          <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>Evidence Citations:</span>
                          {selectedEventDetail.evidence_refs.map((tag) => (
                            <span
                              key={tag}
                              className="badge badge-neutral"
                              style={{ fontSize: "9px", fontFamily: "var(--font-mono)", cursor: "pointer" }}
                              onClick={() => {
                                if (tag.startsWith("[event:") && onSelectEventId) {
                                  onSelectEventId(tag.replace("[event:", "").replace("]", ""));
                                } else if (tag.startsWith("[alert:") && onSelectAlertId) {
                                  onSelectAlertId(parseInt(tag.replace("[alert:", "").replace("]", ""), 10));
                                }
                              }}
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* SINGLE HOST VIEW */}
              {timelineMode === "single" && (
                <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                  {/* Single Host Selector */}
                  <div
                    className="panel"
                    style={{
                      padding: "10px 14px",
                      background: "var(--bg-surface)",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "2px",
                      display: "flex",
                      alignItems: "center",
                      gap: "8px",
                    }}
                  >
                    <label style={{ fontSize: "11px", fontWeight: 600 }}>Active Host:</label>
                    <select
                      value={selectedHostId || ""}
                      onChange={(e) => {
                        if (e.target.value) {
                          setSelectedHostId(e.target.value);
                          setTimelineOffset(0);
                        }
                      }}
                      style={{
                        padding: "4px 8px",
                        fontSize: "11px",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                        background: "var(--bg-surface)",
                        minWidth: "220px",
                      }}
                    >
                      <option value="">Select a host to slice timeline...</option>
                      {dossier.participating_hosts.map((h) => (
                        <option key={h.host_id} value={h.host_id}>
                          {h.hostname} ({h.host_id}) - {h.event_count} events
                        </option>
                      ))}
                    </select>
                  </div>

                  {/* Single Host Items Listing */}
                  {!selectedHostId && (
                    <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
                      Select a host from the dropdown above or click "Focus Single Host Timeline" in any swimlane.
                    </div>
                  )}

                  {selectedHostId && timelineLoading && (
                    <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                      Retrieving unified timeline projection for host '{selectedHostId}'...
                    </div>
                  )}

                  {selectedHostId && timelineError && (
                    <div style={{ padding: "12px", background: "var(--badge-alert-bg)", border: "1px solid var(--badge-alert-border)", color: "var(--badge-alert-text)", fontSize: "11px" }}>
                      {timelineError}
                    </div>
                  )}

                  {selectedHostId && !timelineLoading && timelineData && (
                    <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                      {/* Layer and Epistemic breakdown */}
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: "11px", color: "var(--text-muted)" }}>
                        <span>
                          Total Events for <strong>{timelineData.hostname}</strong>: {timelineData.total}
                        </span>
                        <div style={{ display: "flex", gap: "6px" }}>
                          {Object.entries(timelineData.epistemic_breakdown || {}).map(([status, cnt]) => (
                            <span key={status} className="badge badge-neutral" style={{ fontSize: "9px" }}>
                              {status}: {cnt}
                            </span>
                          ))}
                        </div>
                      </div>

                      {timelineData.items.length === 0 ? (
                        <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)" }}>
                          No timeline events observed for host '{selectedHostId}' within the requested parameters.
                        </div>
                      ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                          {timelineData.items.map((item) => (
                            <div
                              key={item.timeline_id}
                              className="panel"
                              style={{
                                padding: "8px 12px",
                                background: "var(--bg-surface)",
                                border: "1px solid var(--border-subtle)",
                                borderRadius: "2px",
                              }}
                            >
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "4px" }}>
                                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-muted)" }}>
                                    {formatSafeTimestamp(item.timestamp)}
                                  </span>
                                  <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                                    {item.source_layer}
                                  </span>
                                  <span style={{ fontSize: "11px", fontWeight: 600 }}>{item.event_type}</span>
                                </div>
                                <span className="badge badge-neutral" style={{ fontSize: "9px" }}>
                                  {item.epistemic_status}
                                </span>
                              </div>
                              <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
                                {item.display_summary}
                              </div>
                              {item.evidence_refs && item.evidence_refs.length > 0 && (
                                <div style={{ display: "flex", gap: "4px", marginTop: "4px" }}>
                                  {item.evidence_refs.map((r) => (
                                    <span
                                      key={r}
                                      className="badge badge-notice"
                                      style={{ fontSize: "8px", fontFamily: "var(--font-mono)", cursor: "pointer" }}
                                      onClick={() => {
                                        if (r.startsWith("[event:") && onSelectEventId) {
                                          onSelectEventId(r.replace("[event:", "").replace("]", ""));
                                        } else if (r.startsWith("[alert:") && onSelectAlertId) {
                                          onSelectAlertId(parseInt(r.replace("[alert:", "").replace("]", ""), 10));
                                        }
                                      }}
                                    >
                                      {r}
                                    </span>
                                  ))}
                                </div>
                              )}
                            </div>
                          ))}

                          {/* Pagination Controls */}
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "8px", fontSize: "11px" }}>
                            <button
                              className="btn btn-secondary"
                              disabled={timelineOffset === 0}
                              onClick={() => setTimelineOffset(Math.max(0, timelineOffset - timelineLimit))}
                              style={{ padding: "4px 8px", fontSize: "10px" }}
                            >
                              &larr; Previous Page
                            </button>
                            <span>
                              Showing {timelineOffset + 1} - {Math.min(timelineOffset + timelineLimit, timelineData.total)} of {timelineData.total}
                            </span>
                            <button
                              className="btn btn-secondary"
                              disabled={timelineOffset + timelineLimit >= timelineData.total}
                              onClick={() => setTimelineOffset(timelineOffset + timelineLimit)}
                              style={{ padding: "4px 8px", fontSize: "10px" }}
                            >
                              Next Page &rarr;
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* =========================================================================
              TAB 4: VISIBILITY GAPS & COMPLETENESS LIMITATIONS
          ========================================================================= */}
          {activeSubTab === "gaps" && (
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
                Forensic visibility boundaries strictly separate observed evidence from missing or unmonitored endpoints.
                <strong> Absence of telemetry does not constitute proof that an event did not occur.</strong>
              </div>

              {/* Overall Completeness Limitations */}
              <div className="panel" style={{ padding: "12px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px" }}>Forensic Boundaries & Epistemic Limitations</div>
                <ul style={{ margin: 0, paddingLeft: "18px", fontSize: "11px", color: "var(--text-secondary)", display: "flex", flexDirection: "column", gap: "4px" }}>
                  {dossier.completeness_limitations.map((lim, idx) => (
                    <li key={idx}>{lim}</li>
                  ))}
                </ul>
              </div>

              {/* Visibility Gaps Listing */}
              <div style={{ fontSize: "12px", fontWeight: 700 }}>Telemetry Visibility Gaps ({dossier.overall_visibility_gaps.length})</div>
              {dossier.overall_visibility_gaps.length === 0 ? (
                <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)" }}>
                  No collection or visibility gaps identified for the active case.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  {dossier.overall_visibility_gaps.map((gap: HostVisibilityGap, idx: number) => (
                    <div
                      key={idx}
                      className="panel"
                      style={{
                        padding: "10px 14px",
                        background: "var(--bg-surface)",
                        borderLeft: "3px solid #f59e0b",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                      }}
                    >
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <span style={{ fontSize: "11px", fontWeight: 700, color: "var(--badge-warn-text)" }}>
                          [{gap.gap_type}] {gap.host_identifier}
                        </span>
                      </div>
                      <div style={{ fontSize: "11px", color: "var(--text-primary)", marginTop: "4px" }}>
                        {gap.description}
                      </div>
                      {gap.remedy_suggestion && (
                        <div style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "4px", fontStyle: "italic" }}>
                          Remedy Recommendation: {gap.remedy_suggestion}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {/* Provenance Footer */}
              <div style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", marginTop: "10px" }}>
                Provenance Digest: {dossier.provenance_hash} (Generated: {dossier.generated_at})
              </div>
            </div>
          )}

          {/* =========================================================================
              TAB 5: SCOPE EDITOR
          ========================================================================= */}
          {activeSubTab === "scope" && (
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
                Explicitly target or bound analysis to specific hosts. When target hosts are configured, the multi-host dossier marks any scoped host with zero telemetry as <strong>UNKNOWN</strong>. If no target hosts are configured, scope is dynamic and encompasses all evidence-backed hosts.
              </div>

              {scopeMessage && (
                <div
                  style={{
                    padding: "8px 12px",
                    borderRadius: "2px",
                    fontSize: "11px",
                    background: scopeMessage.isError ? "var(--badge-alert-bg)" : "var(--badge-success-bg)",
                    border: scopeMessage.isError ? "1px solid var(--badge-alert-border)" : "1px solid var(--badge-success-border)",
                    color: scopeMessage.isError ? "var(--badge-alert-text)" : "var(--badge-success-text)",
                  }}
                >
                  {scopeMessage.text}
                </div>
              )}

              {/* Add target host input */}
              <div className="panel" style={{ padding: "12px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}>
                <div style={{ fontSize: "12px", fontWeight: 700, marginBottom: "8px" }}>Add Target Host to Investigation Scope</div>
                <div style={{ display: "flex", gap: "8px" }}>
                  <input
                    type="text"
                    placeholder="Enter hostname or host identifier (e.g. srv-dc01)..."
                    value={newTargetHostInput}
                    onChange={(e) => setNewTargetHostInput(e.target.value)}
                    style={{
                      padding: "6px 10px",
                      fontSize: "11px",
                      border: "1px solid var(--border-subtle)",
                      borderRadius: "2px",
                      flex: 1,
                      background: "var(--bg-surface)",
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") handleAddTargetHost();
                    }}
                  />
                  <button
                    className="btn btn-primary"
                    disabled={scopeSaving || !newTargetHostInput.trim()}
                    onClick={handleAddTargetHost}
                    style={{ padding: "6px 12px", fontSize: "11px" }}
                  >
                    {scopeSaving ? "Updating Scope..." : "Add Target Host"}
                  </button>
                </div>
              </div>

              {/* Current target hosts */}
              <div style={{ fontSize: "12px", fontWeight: 700 }}>
                Currently Configured Target Hosts ({dossier.scope_target_hosts.length})
              </div>

              {dossier.scope_target_hosts.length === 0 ? (
                <div style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)", background: "var(--bg-surface-subtle)" }}>
                  No target hosts configured. Scope is currently dynamic across all evidence hosts.
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                  {dossier.scope_target_hosts.map((hostName) => (
                    <div
                      key={hostName}
                      className="panel"
                      style={{
                        padding: "8px 12px",
                        background: "var(--bg-surface)",
                        border: "1px solid var(--border-subtle)",
                        borderRadius: "2px",
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                      }}
                    >
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "12px", fontWeight: 600 }}>
                        {hostName}
                      </span>
                      <button
                        className="btn btn-secondary"
                        disabled={scopeSaving}
                        onClick={() => handleRemoveTargetHost(hostName)}
                        style={{ padding: "2px 8px", fontSize: "10px", color: "var(--badge-alert-text)" }}
                      >
                        Remove from Scope
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Export Multi-Host Dossier Modal (M7.12.5) */}
      {exportModalOpen && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.6)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={() => setExportModalOpen(false)}
        >
          <div
            className="panel"
            style={{
              width: "780px",
              maxHeight: "85vh",
              display: "flex",
              flexDirection: "column",
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "4px",
              boxShadow: "0 10px 25px rgba(0,0,0,0.5)",
              overflow: "hidden",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div
              style={{
                padding: "12px 16px",
                borderBottom: "1px solid var(--border-subtle)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "13px", fontWeight: 700 }}>
                  Export Multi-Host Investigation Dossier
                </span>
                <span className="badge badge-neutral" style={{ fontSize: "10px", fontFamily: "var(--font-mono)" }}>
                  Case #{caseId}
                </span>
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: "2px 8px", fontSize: "11px" }}
                onClick={() => setExportModalOpen(false)}
              >
                ✕
              </button>
            </div>

            {/* Format Toggle & Action Bar */}
            <div
              style={{
                padding: "8px 16px",
                background: "var(--bg-surface-subtle)",
                borderBottom: "1px solid var(--border-subtle)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
              }}
            >
              <div style={{ display: "flex", gap: "6px" }}>
                <button
                  className={`btn btn-secondary ${exportFormat === "markdown" ? "active" : ""}`}
                  style={{
                    padding: "4px 10px",
                    fontSize: "10px",
                    fontWeight: exportFormat === "markdown" ? 600 : 400,
                  }}
                  onClick={() => handleSwitchExportFormat("markdown")}
                >
                  Markdown Report (.md)
                </button>
                <button
                  className={`btn btn-secondary ${exportFormat === "json" ? "active" : ""}`}
                  style={{
                    padding: "4px 10px",
                    fontSize: "10px",
                    fontWeight: exportFormat === "json" ? 600 : 400,
                  }}
                  onClick={() => handleSwitchExportFormat("json")}
                >
                  Raw JSON Dossier (.json)
                </button>
              </div>

              {exportData && (
                <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                  <span style={{ fontSize: "9px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                    Digest: {exportData.root_digest.substring(0, 18)}...
                  </span>
                  <button
                    className="btn btn-primary"
                    style={{ padding: "4px 10px", fontSize: "10px" }}
                    onClick={handleCopyExportContent}
                  >
                    {exportCopied ? "✓ Copied!" : "Copy Content"}
                  </button>
                </div>
              )}
            </div>

            {/* Modal Body */}
            <div style={{ padding: "16px", flex: 1, overflowY: "auto" }}>
              {exportLoading && (
                <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
                  Generating case-scoped multi-host export artifact...
                </div>
              )}

              {exportError && (
                <div style={{ padding: "12px", background: "var(--badge-alert-bg)", border: "1px solid var(--badge-alert-border)", color: "var(--badge-alert-text)", fontSize: "11px" }}>
                  {exportError}
                </div>
              )}

              {!exportLoading && exportData && (
                <pre
                  style={{
                    margin: 0,
                    padding: "12px",
                    background: "var(--bg-surface-subtle)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "3px",
                    fontFamily: "var(--font-mono)",
                    fontSize: "10.5px",
                    lineHeight: "1.5",
                    color: "var(--text-primary)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-word",
                    maxHeight: "55vh",
                    overflowY: "auto",
                  }}
                >
                  {exportData.content}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
