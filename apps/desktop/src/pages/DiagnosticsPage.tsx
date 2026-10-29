import React, { useState } from "react";
import { CheckIcon, DatabaseIcon, RefreshIcon, ServerIcon } from "../components/Icons";
import { SystemStatus, TelemetryHealthReport } from "../types/events";
import { triggerIngestionCycle } from "../lib/api";

interface DiagnosticsPageProps {
  status: SystemStatus | null;
  health: TelemetryHealthReport | null;
  onRefresh: () => Promise<void>;
  backendConnected?: boolean;
}

export function DiagnosticsPage({
  status,
  health,
  onRefresh,
  backendConnected = true,
}: DiagnosticsPageProps) {
  const [syncing, setSyncing] = useState<boolean>(false);
  const [syncMessage, setSyncMessage] = useState<string | null>(null);

  const handleSync = async () => {
    setSyncing(true);
    setSyncMessage(null);
    try {
      const res = await triggerIngestionCycle();
      setSyncMessage(
        `Ingestion cycle completed successfully: ${res.ingested_records || 0} new event(s) parsed.`
      );
      await onRefresh();
    } catch (err: any) {
      setSyncMessage(`Ingestion cycle error: ${err.message || "Failed to trigger ingestion"}`);
    } finally {
      setSyncing(false);
    }
  };

  const isHealthy = health?.overall_status === "HEALTHY" || health?.overall_status === "DEGRADED";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      {/* Top Banner: Engine Status & Ingestion Trigger */}
      <div className="panel" style={{ padding: "16px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
            <ServerIcon />
            <div>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontWeight: 700, fontSize: "16px" }}>Linux Telemetry & System Diagnostics</span>
                <span className={`health-pill ${health?.overall_status.toLowerCase() || (backendConnected ? "healthy" : "offline")}`}>
                  {health?.overall_status || (backendConnected ? "ONLINE" : "DISCONNECTED")}
                </span>
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                Local Linux log sources, ingestion state tracking, SQLite forensic store invariants, and engine process health
              </div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <button
              className="btn btn-primary"
              onClick={handleSync}
              disabled={syncing || !backendConnected}
              style={{ padding: "6px 14px", fontSize: "12px" }}
            >
              <RefreshIcon />
              <span>{syncing ? "Running Ingestion Cycle..." : "Run Ingestion Cycle Now"}</span>
            </button>

            <button
              className="btn btn-secondary"
              onClick={onRefresh}
              disabled={syncing}
              style={{ padding: "6px 10px", fontSize: "12px" }}
              title="Refresh diagnostic metrics"
            >
              <RefreshIcon /> Refresh
            </button>
          </div>
        </div>

        {syncMessage && (
          <div
            style={{
              marginTop: "12px",
              padding: "8px 12px",
              background: "var(--bg-surface)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "2px",
              fontSize: "12px",
              color: syncMessage.includes("error") ? "var(--badge-alert-text)" : "var(--badge-success-text)",
            }}
          >
            {syncMessage}
          </div>
        )}
      </div>

      {/* Metric Cards Banner */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
          gap: "12px",
        }}
      >
        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Engine Process
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px" }}>
            {backendConnected ? "RUNNING" : "OFFLINE"}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px", fontFamily: "var(--font-mono)" }}>
            Port 41721 • Host {status?.host || "localhost"} • Uptime {Math.floor((status?.uptime_seconds || 0) / 60)}m
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Telemetry Sources
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px", color: isHealthy ? "var(--badge-success-text)" : "var(--badge-warn-text)" }}>
            {health?.active_sources_count || 0} / {health?.total_sources_count || 4} Operational
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
            auth, syslog, auditd, systemd-journal
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Authoritative Events
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px" }}>
            {(status?.total_events || health?.total_events_in_db || 0).toLocaleString()}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Persisted in logintel.db
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Storage Footprint
          </div>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px" }}>
            {health?.database_size_bytes
              ? `${(health.database_size_bytes / (1024 * 1024)).toFixed(2)} MB`
              : "—"}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
            SQLite WAL Mode (0600 file / 0700 dir)
          </div>
        </div>
      </div>

      {/* Telemetry Sources Table */}
      <div className="panel">
        <div className="panel-header" style={{ padding: "12px 16px", borderBottom: "1px solid var(--border-subtle)" }}>
          <div style={{ fontWeight: 600, fontSize: "13px" }}>Configured Linux Telemetry Sources</div>
          <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
            Audited live: {health ? new Date(health.timestamp).toLocaleTimeString() : "—"}
          </div>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          <div className="tech-table-container">
            <table className="tech-table" style={{ width: "100%" }}>
              <thead>
                <tr>
                  <th>Source Name</th>
                  <th>Source Type</th>
                  <th>Status</th>
                  <th>Target Path / Stream</th>
                  <th>Events Ingested</th>
                  <th>Permissions / Diagnostic Info</th>
                </tr>
              </thead>
              <tbody>
                {health?.sources && health.sources.length > 0 ? (
                  health.sources.map((src) => (
                    <tr key={src.name}>
                      <td style={{ fontWeight: 600 }}>{src.name}</td>
                      <td className="mono-cell">{src.source_type}</td>
                      <td>
                        <span className={`badge ${src.available ? "badge-success" : "badge-alert"}`}>
                          {src.available ? "AVAILABLE" : "UNAVAILABLE"}
                        </span>
                      </td>
                      <td className="mono-cell">{src.file_path || "systemd-journal"}</td>
                      <td className="mono-cell">{src.total_records.toLocaleString()}</td>
                      <td>
                        {src.available ? (
                          <span style={{ color: "var(--text-secondary)", fontSize: "11px" }}>
                            Mode: {src.file_permissions || "direct"} • Size:{" "}
                            {src.file_size_bytes ? `${(src.file_size_bytes / 1024).toFixed(1)} KB` : "live stream"}
                          </span>
                        ) : (
                          <div style={{ color: "var(--badge-alert-text)", fontSize: "11px" }}>
                            <strong>{src.error_reason || "Access denied or file missing"}</strong>
                            {src.action_hint && (
                              <div style={{ marginTop: "2px", color: "var(--text-secondary)" }}>
                                {src.action_hint}
                              </div>
                            )}
                          </div>
                        )}
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} style={{ textAlign: "center", padding: "20px", color: "var(--text-muted)" }}>
                      {backendConnected ? "No telemetry source data available." : "Backend disconnected: Cannot read telemetry source health."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      {/* Forensic Storage & Security Invariants Panel */}
      <div className="panel" style={{ padding: "16px" }}>
        <div style={{ fontWeight: 600, fontSize: "13px", marginBottom: "12px", display: "flex", alignItems: "center", gap: "6px" }}>
          <DatabaseIcon /> Forensic Storage Architecture & Security Invariants
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
            gap: "12px",
            fontSize: "12px",
          }}
        >
          <div style={{ padding: "10px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}>
            <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>1. Telemetry Immutability</div>
            <div style={{ color: "var(--text-secondary)", marginTop: "4px", fontSize: "11px" }}>
              Authoritative forensic database (<code>logintel.db</code>) has zero SQL mutation routes. Canonical raw events are write-once upon ingestion and strictly immutable.
            </div>
          </div>

          <div style={{ padding: "10px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}>
            <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>2. Case Isolation & Provenance</div>
            <div style={{ color: "var(--text-secondary)", marginTop: "4px", fontSize: "11px" }}>
              Analyst cases and annotations reside in <code>cases.db</code>. Every operation enforces case authorization and tenant isolation. Evidence items are verified with Blake2b cryptographic hashes.
            </div>
          </div>

          <div style={{ padding: "10px", background: "var(--bg-surface)", border: "1px solid var(--border-subtle)", borderRadius: "2px" }}>
            <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>3. Local-First IPC Security</div>
            <div style={{ color: "var(--text-secondary)", marginTop: "4px", fontSize: "11px" }}>
              FastAPI engine binds exclusively to <code>127.0.0.1:41721</code>. Communication requires a single-use IPC bearer token stored with 0600 permissions. Zero telemetry is sent to cloud servers.
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
