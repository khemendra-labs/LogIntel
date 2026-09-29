import React, { useEffect } from "react";
import { CloseIcon } from "../components/Icons";
import { OutcomeBadge, SeverityBadge } from "../components/StatusBadge";
import { CanonicalEvent } from "../types/events";

interface EventDetailModalProps {
  event: CanonicalEvent | null;
  onClose: () => void;
}

export function EventDetailModal({ event, onClose }: EventDetailModalProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose]);

  if (!event) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <SeverityBadge severity={event.severity} />
            <OutcomeBadge outcome={event.outcome} />
            <span className="modal-title">{event.summary || event.event_type}</span>
          </div>
          <button className="btn" style={{ padding: "4px" }} onClick={onClose} aria-label="Close">
            <CloseIcon />
          </button>
        </div>

        <div className="modal-body">
          <div className="panel" style={{ marginBottom: "14px" }}>
            <div className="panel-header">
              <span className="panel-title">Normalized Security Attributes</span>
              <span style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                ID: {event.id}
              </span>
            </div>
            <div className="panel-body">
              <div className="property-grid">
                <div className="property-item">
                  <span className="property-label">Timestamp</span>
                  <span className="property-value mono-cell">
                    {new Date(event.timestamp).toLocaleString()} ({event.timestamp})
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">Host</span>
                  <span className="property-value mono-cell">{event.host}</span>
                </div>

                <div className="property-item">
                  <span className="property-label">Event Type</span>
                  <span className="property-value mono-cell">{event.event_type}</span>
                </div>
                <div className="property-item">
                  <span className="property-label">Source</span>
                  <span className="property-value mono-cell">{event.source}</span>
                </div>

                <div className="property-item">
                  <span className="property-label">Actor / Username</span>
                  <span className="property-value mono-cell">
                    {event.actor.username ? `${event.actor.username} ${event.actor.uid !== null && event.actor.uid !== undefined ? `(UID: ${event.actor.uid})` : ""}` : "—"}
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">Process</span>
                  <span className="property-value mono-cell">
                    {event.process.name ? `${event.process.name} ${event.process.pid ? `[PID: ${event.process.pid}]` : ""}` : "—"}
                  </span>
                </div>

                {event.process.command_line && (
                  <div className="property-item" style={{ gridColumn: "span 2" }}>
                    <span className="property-label">Command Line</span>
                    <span className="property-value mono-cell" style={{ wordBreak: "break-all" }}>
                      {event.process.command_line}
                    </span>
                  </div>
                )}

                <div className="property-item">
                  <span className="property-label">Network Source</span>
                  <span className="property-value mono-cell">
                    {event.network.src_ip ? `${event.network.src_ip}${event.network.src_port ? `:${event.network.src_port}` : ""}` : "—"}
                  </span>
                </div>
                <div className="property-item">
                  <span className="property-label">Network Destination</span>
                  <span className="property-value mono-cell">
                    {event.network.dst_ip || event.network.dst_port ? `${event.network.dst_ip || "local"}:${event.network.dst_port || ""}` : "—"}
                  </span>
                </div>

                <div className="property-item">
                  <span className="property-label">Parser Provenance</span>
                  <span className="property-value mono-cell">{event.parser}</span>
                </div>
                <div className="property-item">
                  <span className="property-label">Evidence Location</span>
                  <span className="property-value mono-cell">
                    {event.source_file || event.source} {event.source_offset ? `(offset: ${event.source_offset})` : ""}
                  </span>
                </div>
              </div>

              {event.iocs && event.iocs.length > 0 && (
                <div style={{ marginTop: "10px" }}>
                  <span className="property-label" style={{ display: "block", marginBottom: "4px" }}>
                    Extracted Indicators (IOCs)
                  </span>
                  <div style={{ display: "flex", gap: "6px", flexWrap: "wrap" }}>
                    {event.iocs.map((ioc) => (
                      <span key={ioc} className="badge badge-neutral">
                        {ioc}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "6px" }}>
              <span className="property-label">Original Raw Telemetry Evidence</span>
              <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                Immutable raw record
              </span>
            </div>
            <pre className="evidence-box">{event.raw_message}</pre>
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
