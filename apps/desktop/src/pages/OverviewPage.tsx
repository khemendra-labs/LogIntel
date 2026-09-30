import React from "react";
import { OutcomeBadge, SeverityBadge } from "../components/StatusBadge";
import {
  CanonicalEvent,
  EventStatistics,
  SystemStatus,
  TelemetryHealthReport,
} from "../types/events";

interface OverviewPageProps {
  stats: EventStatistics | null;
  health: TelemetryHealthReport | null;
  status: SystemStatus | null;
  openAlertsCount?: number;
  onSelectEvent: (event: CanonicalEvent) => void;
  onNavigateToActivity: (filter?: { severity?: string; source?: string }) => void;
  onNavigateToAlerts?: (filter?: { status?: string }) => void;
}

export function OverviewPage({
  stats,
  health,
  status,
  openAlertsCount = 0,
  onSelectEvent,
  onNavigateToActivity,
  onNavigateToAlerts,
}: OverviewPageProps) {
  const totalEvents = stats?.total_events || 0;
  const bySource = stats?.by_source || {};
  const bySeverity = stats?.by_severity || {};
  const byType = stats?.by_type || {};
  const recentAlerts = stats?.recent_alerts || [];

  return (
    <div>
      {/* Telemetry Status Summary */}
      <div className="panel" style={{ marginBottom: "16px" }}>
        <div className="panel-header">
          <span className="panel-title">Telemetry Ingestion Status</span>
          <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
            Engine Host: {status?.host || "localhost"}
          </span>
        </div>
        <div className="panel-body">
          <div className="property-grid" style={{ gridTemplateColumns: "repeat(5, 1fr)" }}>
            <div className="property-item">
              <span className="property-label">Total Telemetry Events</span>
              <span className="property-value mono-cell" style={{ fontSize: "18px", fontWeight: 700 }}>
                {totalEvents.toLocaleString()}
              </span>
            </div>
            <div className="property-item">
              <span className="property-label">Sources Health</span>
              <span className="property-value mono-cell" style={{ fontSize: "14px" }}>
                {health?.active_sources_count || 0} / {health?.total_sources_count || 4} Active
              </span>
            </div>
            <div className="property-item">
              <span className="property-label">Live Ingestion Engine</span>
              <span className="property-value mono-cell">
                <span className={`badge ${status?.ingestion_running ? "badge-success" : "badge-neutral"}`}>
                  {status?.ingestion_running ? "RUNNING (POLLING)" : "STANDBY"}
                </span>
              </span>
            </div>
            <div className="property-item">
              <span className="property-label">Database Store</span>
              <span className="property-value mono-cell" style={{ fontSize: "12px" }}>
                SQLite WAL ({(health?.database_size_bytes ? health.database_size_bytes / (1024 * 1024) : 0).toFixed(2)} MB)
              </span>
            </div>
            <div
              className="property-item"
              style={{ cursor: "pointer" }}
              onClick={() => onNavigateToAlerts?.({ status: "OPEN" })}
              title="View Open Security Alerts"
            >
              <span className="property-label">Open Alerts</span>
              <span className="property-value mono-cell" style={{ display: "flex", alignItems: "center", gap: "6px" }}>
                <span style={{ fontSize: "18px", fontWeight: 700, color: openAlertsCount > 0 ? "var(--badge-alert-text)" : "inherit" }}>
                  {openAlertsCount}
                </span>
                <span className={`badge ${openAlertsCount > 0 ? "badge-alert" : "badge-neutral"}`} style={{ fontSize: "10px" }}>
                  {openAlertsCount > 0 ? "ATTENTION" : "CLEARED"}
                </span>
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Grid: Sources breakdown & Severity breakdown */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px", marginBottom: "16px" }}>
        {/* Source breakdown */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Events by Source</span>
            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Past 24 Hours</span>
          </div>
          <div className="panel-body" style={{ padding: "10px 14px" }}>
            {Object.keys(bySource).length === 0 ? (
              <div style={{ padding: "12px", color: "var(--text-muted)", fontSize: "12px" }}>
                No events recorded in current time window.
              </div>
            ) : (
              Object.entries(bySource).map(([src, count]) => {
                const pct = totalEvents > 0 ? ((count / totalEvents) * 100).toFixed(1) : "0";
                return (
                  <div
                    key={src}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      padding: "6px 0",
                      borderBottom: "1px solid var(--border-subtle)",
                      cursor: "pointer",
                    }}
                    onClick={() => onNavigateToActivity({ source: src })}
                    title={`Filter by source: ${src}`}
                  >
                    <span className="mono-cell" style={{ fontWeight: 500 }}>
                      {src}
                    </span>
                    <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                      <span className="mono-cell" style={{ color: "var(--text-secondary)" }}>
                        {count.toLocaleString()} ({pct}%)
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Severity breakdown */}
        <div className="panel">
          <div className="panel-header">
            <span className="panel-title">Events by Severity</span>
            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Distribution</span>
          </div>
          <div className="panel-body" style={{ padding: "10px 14px" }}>
            {Object.keys(bySeverity).length === 0 ? (
              <div style={{ padding: "12px", color: "var(--text-muted)", fontSize: "12px" }}>
                No events categorized yet.
              </div>
            ) : (
              ["CRITICAL", "ALERT", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"].map((sev) => {
                const count = bySeverity[sev] || 0;
                if (count === 0 && !["ALERT", "WARNING"].includes(sev)) return null;
                return (
                  <div
                    key={sev}
                    style={{
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      padding: "6px 0",
                      borderBottom: "1px solid var(--border-subtle)",
                      cursor: "pointer",
                    }}
                    onClick={() => onNavigateToActivity({ severity: sev })}
                    title={`Filter by severity: ${sev}`}
                  >
                    <SeverityBadge severity={sev as any} />
                    <span className="mono-cell" style={{ fontWeight: count > 0 && ["ALERT", "CRITICAL"].includes(sev) ? 700 : 400 }}>
                      {count.toLocaleString()}
                    </span>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </div>

      {/* Top Event Types */}
      <div className="panel" style={{ marginBottom: "16px" }}>
        <div className="panel-header">
          <span className="panel-title">Prominent Event Classifications</span>
          <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Normalized Types</span>
        </div>
        <div className="panel-body" style={{ padding: "8px 14px" }}>
          {Object.keys(byType).length === 0 ? (
            <div style={{ padding: "10px", color: "var(--text-muted)", fontSize: "12px" }}>
              No event classifications available.
            </div>
          ) : (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(2, 1fr)", gap: "8px" }}>
              {Object.entries(byType).map(([type, count]) => (
                <div
                  key={type}
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    padding: "6px 10px",
                    background: "var(--bg-surface-subtle)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "2px",
                  }}
                >
                  <span className="mono-cell" style={{ fontSize: "11px" }}>{type}</span>
                  <span className="mono-cell" style={{ fontWeight: 600 }}>{count.toLocaleString()}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Recent Security-Relevant Events */}
      <div className="panel">
        <div className="panel-header">
          <span className="panel-title">Recent Security-Relevant Events</span>
          <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
            Failures, Alerts & Elevated Privileges
          </span>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          {recentAlerts.length === 0 ? (
            <div style={{ padding: "24px", textAlign: "center", color: "var(--text-secondary)" }}>
              No security alerts, failures, or critical events observed in the active telemetry window.
            </div>
          ) : (
            <div className="tech-table-container" style={{ border: "none" }}>
              <table className="tech-table">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>User</th>
                    <th>Source IP</th>
                    <th>Outcome</th>
                    <th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.map((evt) => (
                    <tr key={evt.id} onClick={() => onSelectEvent(evt)}>
                      <td className="mono-cell" style={{ whiteSpace: "nowrap" }}>
                        {new Date(evt.timestamp).toLocaleTimeString()}
                      </td>
                      <td>
                        <SeverityBadge severity={evt.severity} />
                      </td>
                      <td className="mono-cell" style={{ fontSize: "11px" }}>
                        {evt.event_type}
                      </td>
                      <td className="mono-cell">{evt.actor.username || "—"}</td>
                      <td className="mono-cell">{evt.network.src_ip || "—"}</td>
                      <td>
                        <OutcomeBadge outcome={evt.outcome} />
                      </td>
                      <td style={{ maxWidth: "340px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
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
