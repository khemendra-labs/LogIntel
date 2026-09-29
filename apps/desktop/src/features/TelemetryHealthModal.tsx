import React from "react";
import { CloseIcon, ServerIcon } from "../components/Icons";
import { TelemetryHealthReport } from "../types/events";

interface TelemetryHealthModalProps {
  health: TelemetryHealthReport | null;
  onClose: () => void;
  onRefresh: () => void;
}

export function TelemetryHealthModal({
  health,
  onClose,
  onRefresh,
}: TelemetryHealthModalProps) {
  if (!health) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <ServerIcon />
            <span className="modal-title">Linux Telemetry Health Diagnostics</span>
            <span className={`health-pill ${health.overall_status.toLowerCase()}`}>
              {health.overall_status}
            </span>
          </div>
          <button className="btn" style={{ padding: "4px" }} onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="modal-body">
          <div className="panel" style={{ marginBottom: "16px" }}>
            <div className="panel-header">
              <span className="panel-title">Subsystem Metrics</span>
              <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                Audited: {new Date(health.timestamp).toLocaleTimeString()}
              </span>
            </div>
            <div className="panel-body">
              <div className="property-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
                <div className="property-item">
                  <span className="property-label">Active Sources</span>
                  <span className="property-value mono-cell">
                    {health.active_sources_count} of {health.total_sources_count} operational
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">Events Persisted</span>
                  <span className="property-value mono-cell">
                    {health.total_events_in_db.toLocaleString()}
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">Database Store Size</span>
                  <span className="property-value mono-cell">
                    {(health.database_size_bytes / (1024 * 1024)).toFixed(2)} MB
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="tech-table-container">
            <table className="tech-table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Path / Target</th>
                  <th>Events Ingested</th>
                  <th>Permissions / Diagnostic Info</th>
                </tr>
              </thead>
              <tbody>
                {health.sources.map((src) => (
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
                          {src.file_size_bytes ? `${(src.file_size_bytes / 1024).toFixed(1)} KB` : "live"}
                        </span>
                      ) : (
                        <div style={{ color: "var(--badge-alert-text)", fontSize: "11px" }}>
                          <strong>{src.error_reason}</strong>
                          {src.action_hint && (
                            <div style={{ marginTop: "2px", color: "var(--text-secondary)" }}>
                              Fix: <code>{src.action_hint}</code>
                            </div>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn" onClick={onRefresh}>
            Recheck Sources
          </button>
          <button className="btn btn-primary" onClick={onClose}>
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
