import React, { useEffect, useState } from "react";
import { CloseIcon, DatabaseIcon, ExternalLinkIcon, RefreshIcon } from "../components/Icons";
import { EntityTypeBadge, SeverityBadge } from "../components/StatusBadge";
import { inspectEntityPivot } from "../lib/api";
import { EntityPivotSummary } from "../types/investigation";

interface EntityPivotModalProps {
  entityKey: string;
  onClose: () => void;
  onSelectEventId?: (eventId: string) => void;
  onSelectIncidentId?: (incidentId: number) => void;
}

export function EntityPivotModal({
  entityKey,
  onClose,
  onSelectEventId,
  onSelectIncidentId,
}: EntityPivotModalProps) {
  const [pivot, setPivot] = useState<EntityPivotSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadPivot = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await inspectEntityPivot(entityKey);
      setPivot(data);
    } catch (err: any) {
      setError(err.message || "Failed to load entity pivot dossier");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadPivot();
  }, [entityKey]);

  return (
    <div className="modal-overlay" onClick={onClose} style={{ zIndex: 1100 }}>
      <div
        className="modal-dialog"
        style={{ width: "880px", maxWidth: "90vw", maxHeight: "88vh", display: "flex", flexDirection: "column" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "12px", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Entity Pivot Forensics
            </span>
            {pivot && <EntityTypeBadge entityType={pivot.entity_type} />}
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "14px", fontWeight: 700 }}>
              {pivot?.label || entityKey}
            </span>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <button className="btn btn-secondary" style={{ padding: "4px" }} onClick={loadPivot} title="Refresh pivot">
              <RefreshIcon />
            </button>
            <button className="btn btn-secondary" style={{ padding: "4px" }} onClick={onClose}>
              <CloseIcon />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="modal-body" style={{ flex: 1, overflowY: "auto", display: "flex", flexDirection: "column", gap: "14px" }}>
          {loading && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
              Traversing entity lineage and evidence relationships...
            </div>
          )}

          {error && (
            <div className="panel" style={{ padding: "12px", border: "1px solid var(--badge-alert-border)", background: "var(--badge-alert-bg)" }}>
              <span style={{ color: "var(--badge-alert-text)", fontWeight: 600 }}>{error}</span>
            </div>
          )}

          {pivot && !loading && (
            <>
              {/* Entity Overview Bar */}
              <div
                className="panel"
                style={{
                  padding: "10px 14px",
                  background: "var(--bg-surface-subtle)",
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
                  gap: "10px",
                }}
              >
                <div>
                  <span className="property-label">Entity Key:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px", wordBreak: "break-all" }}>
                    {pivot.entity_key}
                  </div>
                </div>
                <div>
                  <span className="property-label">First Seen:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                    {pivot.first_seen ? new Date(pivot.first_seen).toISOString().slice(0, 19).replace("T", " ") : "N/A"}
                  </div>
                </div>
                <div>
                  <span className="property-label">Last Seen:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                    {pivot.last_seen ? new Date(pivot.last_seen).toISOString().slice(0, 19).replace("T", " ") : "N/A"}
                  </div>
                </div>
                <div>
                  <span className="property-label">Total Events:</span>
                  <div style={{ fontSize: "14px", fontWeight: 700 }}>
                    {pivot.total_events.toLocaleString()}
                  </div>
                </div>
                <div>
                  <span className="property-label">Correlated Alerts:</span>
                  <div>
                    <span className="badge badge-alert" style={{ fontSize: "11px" }}>
                      {pivot.alert_count ?? pivot.total_alerts ?? 0}
                    </span>
                  </div>
                </div>
                <div>
                  <span className="property-label">Incidents:</span>
                  <div>
                    <span className="badge badge-neutral" style={{ fontSize: "11px" }}>
                      {pivot.incident_count ?? pivot.total_incidents ?? 0}
                    </span>
                  </div>
                </div>
              </div>

              {/* Associated Dimensions Grid */}
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))", gap: "10px" }}>
                {/* Associated Hosts */}
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600, color: "var(--text-secondary)" }}>
                    Contacted / Associated Hosts ({(pivot.associated_hosts || []).length})
                  </span>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginTop: "6px" }}>
                    {(pivot.associated_hosts || []).length > 0 ? (
                      pivot.associated_hosts.map((h) => (
                        <span key={h} className="badge badge-neutral" style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                          {h}
                        </span>
                      ))
                    ) : (
                      <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>None observed</span>
                    )}
                  </div>
                </div>

                {/* Associated Users */}
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600, color: "var(--text-secondary)" }}>
                    Associated Users ({(pivot.associated_users || []).length})
                  </span>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginTop: "6px" }}>
                    {(pivot.associated_users || []).length > 0 ? (
                      pivot.associated_users.map((u) => (
                        <span key={u} className="badge badge-neutral" style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                          {u}
                        </span>
                      ))
                    ) : (
                      <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>None observed</span>
                    )}
                  </div>
                </div>

                {/* Associated IPs */}
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600, color: "var(--text-secondary)" }}>
                    Network IPs Contacted ({(pivot.associated_ips || []).length})
                  </span>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginTop: "6px" }}>
                    {(pivot.associated_ips || []).length > 0 ? (
                      pivot.associated_ips.map((ip) => (
                        <span key={ip} className="badge badge-notice" style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                          {ip}
                        </span>
                      ))
                    ) : (
                      <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>None observed</span>
                    )}
                  </div>
                </div>

                {/* Associated Processes */}
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600, color: "var(--text-secondary)" }}>
                    Processes Executed ({(pivot.associated_processes || []).length})
                  </span>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "4px", marginTop: "6px" }}>
                    {(pivot.associated_processes || []).length > 0 ? (
                      pivot.associated_processes.map((p) => (
                        <span key={p} className="badge badge-neutral" style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                          {p}
                        </span>
                      ))
                    ) : (
                      <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>None observed</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Commands Executed (if applicable) */}
              {(pivot.associated_commands || []).length > 0 && (
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600, color: "var(--text-secondary)" }}>
                    Commands Recorded ({(pivot.associated_commands || []).length})
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "6px" }}>
                    {pivot.associated_commands!.map((cmd, idx) => (
                      <pre
                        key={idx}
                        style={{
                          margin: 0,
                          padding: "4px 8px",
                          background: "var(--bg-surface-subtle)",
                          border: "1px solid var(--border-subtle)",
                          fontSize: "11px",
                          fontFamily: "var(--font-mono)",
                          whiteSpace: "pre-wrap",
                          wordBreak: "break-all",
                        }}
                      >
                        {cmd}
                      </pre>
                    ))}
                  </div>
                </div>
              )}

              {/* Related Incidents */}
              {(pivot.incidents || []).length > 0 && (
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600, color: "var(--text-secondary)" }}>
                    Associated Security Incidents ({(pivot.incidents || []).length})
                  </span>
                  <table className="data-table" style={{ width: "100%", marginTop: "6px" }}>
                    <thead>
                      <tr>
                        <th>Key</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Status</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pivot.incidents!.map((inc) => (
                        <tr key={inc.id}>
                          <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700 }}>
                            {inc.incident_key}
                          </td>
                          <td><strong>{inc.title}</strong></td>
                          <td><SeverityBadge severity={inc.severity} /></td>
                          <td>
                            <span className="badge badge-neutral" style={{ fontSize: "10px" }}>{inc.status}</span>
                          </td>
                          <td>
                            {onSelectIncidentId && (
                              <button
                                className="btn btn-secondary"
                                style={{ padding: "2px 6px", fontSize: "10px" }}
                                onClick={() => {
                                  onClose();
                                  onSelectIncidentId(inc.id);
                                }}
                              >
                                Open Incident &rarr;
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* Recent Activity Timeline Events */}
              <div>
                <h4 style={{ fontSize: "12px", marginBottom: "8px" }}>
                  Recent Supporting Telemetry Events ({pivot.recent_events.length})
                </h4>
                {pivot.recent_events.length === 0 ? (
                  <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>No recent events found.</div>
                ) : (
                  <table className="data-table" style={{ width: "100%" }}>
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Host</th>
                        <th>Source</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Summary</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pivot.recent_events.map((evt) => (
                        <tr key={evt.id}>
                          <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px", whiteSpace: "nowrap" }}>
                            {new Date(evt.timestamp).toISOString().slice(0, 19).replace("T", " ")}
                          </td>
                          <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>{evt.host}</td>
                          <td><span className="badge badge-neutral" style={{ fontSize: "10px" }}>{evt.source}</span></td>
                          <td style={{ fontSize: "11px" }}>{evt.event_type}</td>
                          <td><SeverityBadge severity={evt.severity} /></td>
                          <td style={{ fontSize: "11px", maxWidth: "260px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                            {evt.summary || evt.raw_message}
                          </td>
                          <td>
                            {onSelectEventId && (
                              <button
                                className="btn btn-secondary"
                                style={{ padding: "2px 6px", fontSize: "10px" }}
                                onClick={() => onSelectEventId(evt.id)}
                              >
                                Inspect Forensics &rarr;
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
