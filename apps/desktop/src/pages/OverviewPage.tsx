import React, { useEffect, useState } from "react";
import { OutcomeBadge, SeverityBadge } from "../components/StatusBadge";
import { DistributionBarChart, DistributionItem } from "../components/charts/DistributionBarChart";
import { TimeSeriesChart } from "../components/charts/TimeSeriesChart";
import { fetchAlerts, fetchIncidents } from "../lib/api";
import { Alert } from "../types/detection";
import {
  CanonicalEvent,
  EventStatistics,
  SystemStatus,
  TelemetryHealthReport,
} from "../types/events";
import { Incident } from "../types/incidents";

interface OverviewPageProps {
  stats: EventStatistics | null;
  health: TelemetryHealthReport | null;
  status: SystemStatus | null;
  openAlertsCount?: number;
  ackAlertsCount?: number;
  resolvedAlertsCount?: number;
  falsePositiveAlertsCount?: number;
  activeIncidentsCount?: number;
  onSelectEvent: (event: CanonicalEvent) => void;
  onSelectAlert?: (alertId: number) => void;
  onSelectIncident?: (incidentId: number) => void;
  onOpenHealth?: () => void;
  onNavigateToActivity: (filter?: { severity?: string; source?: string }) => void;
  onNavigateToAlerts?: (filter?: { status?: string }) => void;
  onNavigateToIncidents?: (filter?: { status?: string }) => void;
  onNavigateToCases?: () => void;
  onNavigateToDiagnostics?: () => void;
  onTimeWindowChange?: (hours: number) => void;
  currentHours?: number;
  isLoadingStats?: boolean;
  backendConnected?: boolean;
  backendError?: string | null;
  onRetryConnection?: () => void;
}

export function OverviewPage({
  stats,
  health,
  status,
  openAlertsCount = 0,
  ackAlertsCount = 0,
  resolvedAlertsCount = 0,
  falsePositiveAlertsCount = 0,
  activeIncidentsCount = 0,
  onSelectEvent,
  onSelectAlert,
  onSelectIncident,
  onOpenHealth,
  onNavigateToActivity,
  onNavigateToAlerts,
  onNavigateToIncidents,
  onNavigateToCases,
  onNavigateToDiagnostics,
  onTimeWindowChange,
  currentHours = 24,
  isLoadingStats = false,
  backendConnected = true,
  backendError = null,
  onRetryConnection,
}: OverviewPageProps) {
  // Local state for recent alerts and recent incidents lists
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [recentIncidents, setRecentIncidents] = useState<Incident[]>([]);
  const [alertsLoading, setAlertsLoading] = useState<boolean>(true);
  const [incidentsLoading, setIncidentsLoading] = useState<boolean>(true);

  useEffect(() => {
    let isMounted = true;
    async function loadRecentFeeds() {
      try {
        setAlertsLoading(true);
        const alertsResp = await fetchAlerts({ limit: 5 });
        if (isMounted && alertsResp && Array.isArray(alertsResp.items)) {
          setRecentAlerts(alertsResp.items);
        }
      } catch (err) {
        console.error("Failed to load recent alerts on overview:", err);
      } finally {
        if (isMounted) setAlertsLoading(false);
      }

      try {
        setIncidentsLoading(true);
        const incResp = await fetchIncidents({ limit: 5 });
        if (isMounted && incResp && Array.isArray(incResp.items)) {
          setRecentIncidents(incResp.items);
        }
      } catch (err) {
        console.error("Failed to load recent incidents on overview:", err);
      } finally {
        if (isMounted) setIncidentsLoading(false);
      }
    }

    loadRecentFeeds();
    return () => {
      isMounted = false;
    };
  }, []);

  const totalEventsAllTime = status?.total_events || stats?.total_events || 0;
  const windowEvents = stats?.window_events || 0;
  const bySource = stats?.by_source || {};
  const bySeverity = stats?.by_severity || {};
  const byType = stats?.by_type || {};
  const securityEvents = stats?.recent_alerts || []; // security-relevant raw events from stats

  // Transform sources for DistributionBarChart
  const sourceItems: DistributionItem[] = Object.entries(bySource).map(([src, count]) => ({
    key: src,
    label: src,
    count,
  }));

  // Transform event types for DistributionBarChart
  const typeItems: DistributionItem[] = Object.entries(byType).map(([type, count]) => ({
    key: type,
    label: type,
    count,
  }));

  const windowOptions = [
    { label: "6h", hours: 6 },
    { label: "12h", hours: 12 },
    { label: "24h", hours: 24 },
    { label: "3d", hours: 72 },
    { label: "7d", hours: 168 },
  ];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      {/* Backend Engine Disconnected Banner */}
      {!backendConnected && (
        <div
          className="panel"
          style={{
            background: "rgba(239, 68, 68, 0.08)",
            border: "1px solid var(--badge-alert-border)",
            padding: "12px 16px",
            marginBottom: "4px",
          }}
        >
          <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
              <span className="badge badge-alert" style={{ fontSize: "11px", fontWeight: 700 }}>
                ENGINE DISCONNECTED
              </span>
              <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                {backendError || "LogIntel backend is unreachable at 127.0.0.1:41721. Operational metrics and live telemetry are unavailable."}
              </span>
            </div>
            {onRetryConnection && (
              <button
                className="btn btn-primary btn-sm"
                onClick={onRetryConnection}
                style={{ padding: "4px 10px", fontSize: "11px" }}
              >
                Retry Connection
              </button>
            )}
          </div>
        </div>
      )}

      {/* ====================================================================== */}
      {/* TIER 1: OPERATIONAL TELEMETRY & SECURITY KPI STRIP                     */}
      {/* ====================================================================== */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(6, 1fr)",
          gap: "10px",
        }}
      >
        {/* Metric 1: Total Events */}
        <div className="kpi-card">
          <span className="kpi-label">Total Telemetry</span>
          <span className="kpi-value">
            {backendConnected ? totalEventsAllTime.toLocaleString() : "—"}
          </span>
          <span className="kpi-subtext">
            {backendConnected
              ? totalEventsAllTime === 0
                ? "Database empty (0 events)"
                : `${windowEvents.toLocaleString()} in ${currentHours >= 24 ? `${(currentHours / 24).toFixed(0)}d` : `${currentHours}h`}`
              : "Backend offline"}
          </span>
        </div>

        {/* Metric 2: Open Alerts */}
        <div
          className="kpi-card kpi-card-clickable"
          onClick={() => onNavigateToAlerts?.({ status: "OPEN" })}
          title="Filter alerts by OPEN status"
        >
          <span className="kpi-label">Open Alerts</span>
          <span className="kpi-value">
            <span style={{ color: backendConnected && openAlertsCount > 0 ? "var(--badge-alert-text)" : "inherit" }}>
              {backendConnected ? openAlertsCount : "—"}
            </span>
            <span
              className={`badge ${
                !backendConnected
                  ? "badge-neutral"
                  : openAlertsCount > 0
                  ? "badge-alert"
                  : "badge-neutral"
              }`}
              style={{ fontSize: "9px" }}
            >
              {!backendConnected ? "N/A" : openAlertsCount > 0 ? "ATTN" : "OK"}
            </span>
          </span>
          <span className="kpi-subtext">
            {backendConnected ? "Requires analyst triage" : "Backend offline"}
          </span>
        </div>

        {/* Metric 3: Acknowledged Alerts */}
        <div
          className="kpi-card kpi-card-clickable"
          onClick={() => onNavigateToAlerts?.({ status: "ACKNOWLEDGED" })}
          title="Filter alerts by ACKNOWLEDGED status"
        >
          <span className="kpi-label">In Triage</span>
          <span className="kpi-value">{backendConnected ? ackAlertsCount : "—"}</span>
          <span className="kpi-subtext">
            {backendConnected ? "Acknowledged" : "Backend offline"}
          </span>
        </div>

        {/* Metric 4: Resolved Alerts */}
        <div
          className="kpi-card kpi-card-clickable"
          onClick={() => onNavigateToAlerts?.({ status: "RESOLVED" })}
          title="Filter alerts by RESOLVED status"
        >
          <span className="kpi-label">Resolved</span>
          <span className="kpi-value">{backendConnected ? resolvedAlertsCount : "—"}</span>
          <span className="kpi-subtext">
            {backendConnected ? `${falsePositiveAlertsCount} marked false-pos` : "Backend offline"}
          </span>
        </div>

        {/* Metric 5: Active Incidents */}
        <div
          className="kpi-card kpi-card-clickable"
          onClick={() => onNavigateToIncidents?.()}
          title="Navigate to Incidents workbench"
        >
          <span className="kpi-label">Active Incidents</span>
          <span className="kpi-value">
            <span style={{ color: backendConnected && activeIncidentsCount > 0 ? "var(--badge-warn-text)" : "inherit" }}>
              {backendConnected ? activeIncidentsCount : "—"}
            </span>
          </span>
          <span className="kpi-subtext">
            {backendConnected ? "Correlated cases" : "Backend offline"}
          </span>
        </div>

        {/* Metric 6: Live Ingestion Pipeline */}
        <div
          className="kpi-card kpi-card-clickable"
          onClick={onNavigateToDiagnostics || onOpenHealth}
          title="Click to view full system diagnostics"
        >
          <span className="kpi-label">Telemetry Pipeline</span>
          <span className="kpi-value" style={{ fontSize: "14px", marginTop: "4px" }}>
            <span
              className={`badge ${
                !backendConnected
                  ? "badge-alert"
                  : status?.ingestion_running
                  ? "badge-success"
                  : "badge-neutral"
              }`}
            >
              {!backendConnected ? "OFFLINE" : status?.ingestion_running ? "RUNNING" : "STANDBY"}
            </span>
          </span>
          <span className="kpi-subtext mono-cell">
            {backendConnected
              ? `${health?.active_sources_count || 0}/${health?.total_sources_count || 4} sources active`
              : "Service unreachable"}
          </span>
        </div>
      </div>

      {/* ====================================================================== */}
      {/* TIER 2: TEMPORAL TELEMETRY & ALERT DYNAMICS                            */}
      {/* ====================================================================== */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: "14px" }}>
        {/* Left: Time Series Activity Chart */}
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-header">
            <span className="panel-title">Event Activity Over Time</span>
            <div style={{ display: "flex", gap: "4px" }}>
              {windowOptions.map((opt) => (
                <button
                  key={opt.hours}
                  type="button"
                  className={`btn btn-sm ${currentHours === opt.hours ? "btn-primary" : ""}`}
                  onClick={() => onTimeWindowChange?.(opt.hours)}
                  style={{ minWidth: "32px", padding: "2px 6px" }}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
          <div className="panel-body">
            <TimeSeriesChart
              data={stats?.timeline || []}
              hours={currentHours}
              height={175}
              loading={isLoadingStats}
            />
          </div>
        </div>

        {/* Right: Alert Distribution (Severity & Lifecycle Status) */}
        <div className="panel" style={{ margin: 0, display: "flex", flexDirection: "column" }}>
          <div className="panel-header">
            <span className="panel-title">Alert & Severity Dynamics</span>
            <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
              Window Stats
            </span>
          </div>
          <div className="panel-body" style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
            {/* Severity Distribution */}
            <div>
              <div
                style={{
                  fontSize: "10px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  color: "var(--text-muted)",
                  marginBottom: "6px",
                }}
              >
                Telemetry Severity Breakdown
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                {["CRITICAL", "ALERT", "WARNING", "NOTICE", "INFORMATIONAL"].map((sev) => {
                  const count = bySeverity[sev] || 0;
                  return (
                    <div
                      key={sev}
                      style={{
                        display: "flex",
                        justifyContent: "space-between",
                        alignItems: "center",
                        padding: "3px 4px",
                        cursor: "pointer",
                        borderRadius: "2px",
                      }}
                      onClick={() => onNavigateToActivity({ severity: sev })}
                      title={`Filter activity by ${sev}`}
                      className="nav-item"
                    >
                      <SeverityBadge severity={sev as any} />
                      <span className="mono-cell" style={{ fontWeight: count > 0 && ["CRITICAL", "ALERT"].includes(sev) ? 700 : 400 }}>
                        {count.toLocaleString()}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Alert Status Lifecycle */}
            <div style={{ borderTop: "1px solid var(--border-subtle)", paddingTop: "8px" }}>
              <div
                style={{
                  fontSize: "10px",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  color: "var(--text-muted)",
                  marginBottom: "6px",
                }}
              >
                Alert Lifecycle Status
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "6px" }}>
                <div
                  style={{
                    padding: "6px 8px",
                    background: "var(--bg-surface-subtle)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "2px",
                    cursor: "pointer",
                  }}
                  onClick={() => onNavigateToAlerts?.({ status: "OPEN" })}
                  title="View Open alerts"
                >
                  <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>OPEN</div>
                  <div className="mono-cell" style={{ fontWeight: 700, fontSize: "14px" }}>
                    {openAlertsCount}
                  </div>
                </div>
                <div
                  style={{
                    padding: "6px 8px",
                    background: "var(--bg-surface-subtle)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "2px",
                    cursor: "pointer",
                  }}
                  onClick={() => onNavigateToAlerts?.({ status: "ACKNOWLEDGED" })}
                  title="View Acknowledged alerts"
                >
                  <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>ACK</div>
                  <div className="mono-cell" style={{ fontWeight: 700, fontSize: "14px" }}>
                    {ackAlertsCount}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* ====================================================================== */}
      {/* TIER 3: TAXONOMY & CLASSIFICATION                                      */}
      {/* ====================================================================== */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
        {/* Top Sources */}
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-header">
            <span className="panel-title">Top Ingestion Sources</span>
            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>By Volume</span>
          </div>
          <div className="panel-body">
            <DistributionBarChart
              items={sourceItems}
              total={windowEvents}
              emptyMessage="No source records observed in this window."
              onSelectItem={(item) => onNavigateToActivity({ source: item.key })}
              maxDisplay={6}
            />
          </div>
        </div>

        {/* Top Classifications */}
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-header">
            <span className="panel-title">Prominent Event Classifications</span>
            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Normalized Types</span>
          </div>
          <div className="panel-body">
            <DistributionBarChart
              items={typeItems}
              total={windowEvents}
              emptyMessage="No normalized classifications available."
              maxDisplay={6}
            />
          </div>
        </div>
      </div>

      {/* ====================================================================== */}
      {/* TIER 4: ACTIONABLE INVESTIGATION WORKBENCH FEEDS                        */}
      {/* ====================================================================== */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "14px" }}>
        {/* Left: Recent Security Detections */}
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-header">
            <span className="panel-title">Recent Security Detections</span>
            <button
              type="button"
              className="btn btn-sm"
              onClick={() => onNavigateToAlerts?.()}
              title="Navigate to all alerts"
            >
              All Alerts &rarr;
            </button>
          </div>
          <div className="panel-body" style={{ padding: 0 }}>
            {alertsLoading ? (
              <div style={{ padding: "16px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                Loading recent alerts...
              </div>
            ) : recentAlerts.length === 0 ? (
              <div style={{ padding: "16px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                No detection alerts registered.
              </div>
            ) : (
              <div className="tech-table-container" style={{ border: "none" }}>
                <table className="tech-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Severity</th>
                      <th>Title</th>
                      <th>Host</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentAlerts.map((alt) => (
                      <tr
                        key={alt.id}
                        onClick={() => alt.id && onSelectAlert?.(alt.id)}
                        title="Click to view alert forensics and detections"
                      >
                        <td className="mono-cell" style={{ whiteSpace: "nowrap" }}>
                          {new Date(alt.last_seen).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                        </td>
                        <td>
                          <SeverityBadge severity={alt.severity} />
                        </td>
                        <td style={{ maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                          {alt.title}
                        </td>
                        <td className="mono-cell">{alt.host}</td>
                        <td>
                          <span
                            className={`badge ${
                              alt.status === "OPEN"
                                ? "badge-alert"
                                : alt.status === "ACKNOWLEDGED"
                                ? "badge-warning"
                                : "badge-neutral"
                            }`}
                          >
                            {alt.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Right: Ingestion Source Health & Telemetry State */}
        <div className="panel" style={{ margin: 0 }}>
          <div className="panel-header">
            <span className="panel-title">Telemetry Ingestion Sources</span>
            <button
              type="button"
              className="btn btn-sm"
              onClick={onOpenHealth}
              title="Inspect collector health"
            >
              Health Diagnostics &rarr;
            </button>
          </div>
          <div className="panel-body" style={{ padding: 0 }}>
            {(!health || !health.sources || health.sources.length === 0) ? (
              <div style={{ padding: "16px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
                No telemetry sources configured.
              </div>
            ) : (
              <div className="tech-table-container" style={{ border: "none" }}>
                <table className="tech-table">
                  <thead>
                    <tr>
                      <th>Collector</th>
                      <th>Type</th>
                      <th>Status</th>
                      <th>Records</th>
                      <th>Last Seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {health.sources.map((src) => (
                      <tr
                        key={src.name}
                        onClick={onOpenHealth}
                        title={src.error_reason ? `Error: ${src.error_reason}. ${src.action_hint || ""}` : "Click to view collector diagnostics"}
                      >
                        <td className="mono-cell" style={{ fontWeight: 600 }}>
                          {src.name}
                        </td>
                        <td className="mono-cell" style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                          {src.source_type}
                        </td>
                        <td>
                          <span
                            className={`badge ${src.available ? "badge-success" : "badge-alert"}`}
                          >
                            {src.available ? "ACTIVE" : "UNAVAILABLE"}
                          </span>
                        </td>
                        <td className="mono-cell">
                          {src.total_records.toLocaleString()}
                        </td>
                        <td className="mono-cell" style={{ fontSize: "11px", color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                          {src.last_collected_at ? new Date(src.last_collected_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Recent Security-Relevant Telemetry Events (Failures / Critical) */}
      <div className="panel" style={{ margin: 0 }}>
        <div className="panel-header">
          <span className="panel-title">Recent Telemetry Security Events & Failures</span>
          <button
            type="button"
            className="btn btn-sm"
            onClick={() => onNavigateToActivity()}
            title="Open forensic event log"
          >
            All Events &rarr;
          </button>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          {securityEvents.length === 0 ? (
            <div style={{ padding: "16px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
              No security failures, warnings, or elevated privilege events in the active telemetry window.
            </div>
          ) : (
            <div className="tech-table-container" style={{ border: "none" }}>
              <table className="tech-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Classification</th>
                    <th>Actor</th>
                    <th>Source IP</th>
                    <th>Outcome</th>
                    <th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {securityEvents.slice(0, 6).map((evt) => (
                    <tr key={evt.id} onClick={() => onSelectEvent(evt)} title="Click to view event forensics">
                      <td className="mono-cell" style={{ whiteSpace: "nowrap" }}>
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                      </td>
                      <td>
                        <SeverityBadge severity={evt.severity} />
                      </td>
                      <td className="mono-cell" style={{ fontSize: "11px" }}>
                        {evt.event_type}
                      </td>
                      <td className="mono-cell">{evt.actor?.username || "—"}</td>
                      <td className="mono-cell">{evt.network?.src_ip || "—"}</td>
                      <td>
                        <OutcomeBadge outcome={evt.outcome} />
                      </td>
                      <td style={{ maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {evt.summary}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
