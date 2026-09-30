import React, { useEffect, useState } from "react";
import { CheckIcon, CloseIcon, EyeIcon } from "../components/Icons";
import { AlertStatusBadge, SeverityBadge } from "../components/StatusBadge";
import { fetchAlertDetail, updateAlertStatus } from "../lib/api";
import { AlertDetailResponse, AlertStatus } from "../types/detection";

interface AlertDetailModalProps {
  alertId: number;
  onClose: () => void;
  onStatusUpdated: () => void;
  onSelectEventId: (eventId: string) => void;
}

export function AlertDetailModal({
  alertId,
  onClose,
  onStatusUpdated,
  onSelectEventId,
}: AlertDetailModalProps) {
  const [detail, setDetail] = useState<AlertDetailResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Status transition state
  const [transitioning, setTransitioning] = useState<boolean>(false);
  const [showNoteInput, setShowNoteInput] = useState<boolean>(false);
  const [targetStatus, setTargetStatus] = useState<AlertStatus | null>(null);
  const [resolutionNote, setResolutionNote] = useState<string>("");

  const loadAlert = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchAlertDetail(alertId);
      setDetail(data);
    } catch (err: any) {
      setError(err.message || "Failed to load alert detail");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlert();
  }, [alertId]);

  const handleStatusChange = async (newStatus: AlertStatus, note?: string) => {
    if (newStatus === "RESOLVED" || newStatus === "FALSE_POSITIVE") {
      if (!showNoteInput || targetStatus !== newStatus) {
        setTargetStatus(newStatus);
        setShowNoteInput(true);
        return;
      }
    }

    setTransitioning(true);
    setError(null);
    try {
      await updateAlertStatus(alertId, newStatus, note || resolutionNote || undefined);
      setShowNoteInput(false);
      setTargetStatus(null);
      setResolutionNote("");
      await loadAlert();
      onStatusUpdated();
    } catch (err: any) {
      setError(err.message || "Failed to update alert status");
    } finally {
      setTransitioning(false);
    }
  };

  if (loading) {
    return (
      <div className="modal-backdrop" onClick={onClose}>
        <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "800px" }}>
          <div className="modal-header">
            <h3>Alert Investigation #{alertId}</h3>
            <button className="icon-button" onClick={onClose}><CloseIcon /></button>
          </div>
          <div className="modal-body" style={{ padding: "32px", textAlign: "center", color: "var(--text-muted)" }}>
            Loading alert investigation details...
          </div>
        </div>
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="modal-backdrop" onClick={onClose}>
        <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "800px" }}>
          <div className="modal-header">
            <h3>Alert Investigation #{alertId}</h3>
            <button className="icon-button" onClick={onClose}><CloseIcon /></button>
          </div>
          <div className="modal-body" style={{ padding: "20px" }}>
            <div style={{ color: "var(--badge-alert-text)", background: "var(--badge-alert-bg)", padding: "12px", borderRadius: "3px" }}>
              {error || "Alert details could not be found."}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const { alert, detections } = detail;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div
        className="modal-dialog"
        onClick={(e) => e.stopPropagation()}
        style={{ maxWidth: "880px", maxHeight: "88vh", display: "flex", flexDirection: "column" }}
      >
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: "14px", color: "var(--text-muted)" }}>
              ALERT #{alert.id}
            </span>
            <SeverityBadge severity={alert.severity} />
            <AlertStatusBadge status={alert.status} />
          </div>
          <button className="icon-button" onClick={onClose}><CloseIcon /></button>
        </div>

        <div className="modal-body" style={{ overflowY: "auto", padding: "18px 24px" }}>
          {/* Title & Description */}
          <div style={{ marginBottom: "16px" }}>
            <h2 style={{ fontSize: "18px", fontWeight: 600, color: "var(--text-primary)", marginBottom: "6px" }}>
              {alert.title}
            </h2>
            <p style={{ color: "var(--text-secondary)", fontSize: "13px", lineHeight: 1.5 }}>
              {alert.description}
            </p>
          </div>

          {/* Alert Lifecycle Triage Actions */}
          <div className="panel" style={{ marginBottom: "18px", background: "var(--bg-surface-subtle)" }}>
            <div className="panel-header" style={{ padding: "8px 12px" }}>
              <span className="panel-title" style={{ fontSize: "12px" }}>Triage & Lifecycle Action</span>
              <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>Current: <strong>{alert.status}</strong></span>
            </div>
            <div className="panel-body" style={{ padding: "12px" }}>
              <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", alignItems: "center" }}>
                {alert.status === "OPEN" && (
                  <>
                    <button
                      className="btn btn-secondary"
                      disabled={transitioning}
                      onClick={() => handleStatusChange("ACKNOWLEDGED")}
                    >
                      <CheckIcon /> Acknowledge Alert
                    </button>
                    <button
                      className="btn btn-primary"
                      disabled={transitioning}
                      onClick={() => handleStatusChange("RESOLVED")}
                    >
                      Resolve Threat
                    </button>
                    <button
                      className="btn btn-secondary"
                      disabled={transitioning}
                      onClick={() => handleStatusChange("FALSE_POSITIVE")}
                    >
                      Mark False Positive
                    </button>
                  </>
                )}

                {alert.status === "ACKNOWLEDGED" && (
                  <>
                    <button
                      className="btn btn-primary"
                      disabled={transitioning}
                      onClick={() => handleStatusChange("RESOLVED")}
                    >
                      Resolve Threat
                    </button>
                    <button
                      className="btn btn-secondary"
                      disabled={transitioning}
                      onClick={() => handleStatusChange("FALSE_POSITIVE")}
                    >
                      Mark False Positive
                    </button>
                    <button
                      className="btn btn-secondary"
                      disabled={transitioning}
                      onClick={() => handleStatusChange("OPEN")}
                    >
                      Reopen to Open
                    </button>
                  </>
                )}

                {(alert.status === "RESOLVED" || alert.status === "FALSE_POSITIVE") && (
                  <button
                    className="btn btn-secondary"
                    disabled={transitioning}
                    onClick={() => handleStatusChange("OPEN")}
                  >
                    Reopen Investigation
                  </button>
                )}
              </div>

              {/* Note input for Resolution / False Positive */}
              {showNoteInput && targetStatus && (
                <div style={{ marginTop: "12px", paddingTop: "12px", borderTop: "1px solid var(--border-subtle)" }}>
                  <label style={{ display: "block", fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)", marginBottom: "4px" }}>
                    Resolution Note (optional rationale for {targetStatus}):
                  </label>
                  <div style={{ display: "flex", gap: "8px" }}>
                    <input
                      type="text"
                      className="filter-input"
                      placeholder="e.g. Malicious IP blocked on perimeter firewall..."
                      value={resolutionNote}
                      onChange={(e) => setResolutionNote(e.target.value)}
                      style={{ flex: 1 }}
                    />
                    <button
                      className="btn btn-primary"
                      disabled={transitioning}
                      onClick={() => handleStatusChange(targetStatus, resolutionNote)}
                    >
                      Confirm {targetStatus}
                    </button>
                    <button
                      className="btn btn-secondary"
                      onClick={() => {
                        setShowNoteInput(false);
                        setTargetStatus(null);
                        setResolutionNote("");
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* Display existing resolution note if present */}
              {alert.resolution_note && (
                <div style={{ marginTop: "10px", fontSize: "12px", color: "var(--text-secondary)" }}>
                  <strong>Resolution Note:</strong> {alert.resolution_note}
                </div>
              )}
            </div>
          </div>

          {/* Alert Metadata Grid */}
          <div className="panel" style={{ marginBottom: "18px" }}>
            <div className="panel-header" style={{ padding: "8px 12px" }}>
              <span className="panel-title" style={{ fontSize: "12px" }}>Alert Metadata</span>
            </div>
            <div className="panel-body" style={{ padding: "12px" }}>
              <div className="property-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", rowGap: "12px" }}>
                <div className="property-item">
                  <span className="property-label">Detection Rule</span>
                  <span className="property-value mono-cell" style={{ fontWeight: 600 }}>{alert.rule_id}</span>
                </div>
                <div className="property-item">
                  <span className="property-label">Target Host</span>
                  <span className="property-value mono-cell">{alert.host}</span>
                </div>
                <div className="property-item">
                  <span className="property-label">Occurrence Count</span>
                  <span className="property-value mono-cell" style={{ fontWeight: 700 }}>
                    {alert.occurrence_count} detection(s)
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">First Seen</span>
                  <span className="property-value mono-cell" style={{ fontSize: "11px" }}>
                    {new Date(alert.first_seen).toLocaleString()}
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">Last Seen</span>
                  <span className="property-value mono-cell" style={{ fontSize: "11px" }}>
                    {new Date(alert.last_seen).toLocaleString()}
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">Deduplication Key</span>
                  <span className="property-value mono-cell" style={{ fontSize: "11px", wordBreak: "break-all" }}>
                    {alert.dedup_key}
                  </span>
                </div>
              </div>
            </div>
          </div>

          {/* Detections & Evidence Lineage */}
          <div className="panel">
            <div className="panel-header" style={{ padding: "8px 12px" }}>
              <span className="panel-title" style={{ fontSize: "12px" }}>
                Evidence Lineage ({detections.length} Detection Occurrence{detections.length > 1 ? "s" : ""})
              </span>
            </div>
            <div className="panel-body" style={{ padding: "10px" }}>
              {detections.map((det, idx) => (
                <div
                  key={det.id}
                  style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "4px",
                    padding: "12px",
                    marginBottom: idx < detections.length - 1 ? "12px" : "0",
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                    <span style={{ fontWeight: 600, fontSize: "13px" }}>
                      Detection #{det.id}: {det.summary}
                    </span>
                    <span className="mono-cell" style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                      {new Date(det.matched_at).toLocaleString()}
                    </span>
                  </div>

                  {det.details && Object.keys(det.details).length > 0 && (
                    <div style={{ marginBottom: "10px" }}>
                      <pre style={{
                        background: "var(--bg-surface-subtle)",
                        padding: "8px",
                        borderRadius: "3px",
                        fontSize: "11px",
                        fontFamily: "var(--font-mono)",
                        overflowX: "auto",
                      }}>
                        {JSON.stringify(det.details, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Backing Evidence Events Table */}
                  <div>
                    <div style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-muted)", marginBottom: "4px" }}>
                      Backing Canonical Evidence Events:
                    </div>
                    <table className="data-table" style={{ fontSize: "11px" }}>
                      <thead>
                        <tr>
                          <th>Event ID</th>
                          <th>Role</th>
                          <th>Matched Timestamp</th>
                          <th style={{ width: "60px", textAlign: "center" }}>Inspect</th>
                        </tr>
                      </thead>
                      <tbody>
                        {det.evidence.map((ev) => (
                          <tr key={ev.id}>
                            <td className="mono-cell" style={{ fontWeight: 600 }}>{ev.event_id}</td>
                            <td>
                              <span className={`badge ${ev.role === "TRIGGER" ? "badge-alert" : "badge-neutral"}`}>
                                {ev.role}
                              </span>
                            </td>
                            <td className="mono-cell">{new Date(ev.matched_at).toLocaleString()}</td>
                            <td style={{ textAlign: "center" }}>
                              <button
                                className="icon-button"
                                title="Inspect Canonical Event"
                                onClick={() => onSelectEventId(ev.event_id)}
                              >
                                <EyeIcon />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
