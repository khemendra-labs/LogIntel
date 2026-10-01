import React, { useEffect, useState } from "react";
import { CloseIcon, DatabaseIcon, ExternalLinkIcon, RefreshIcon } from "../components/Icons";
import { AlertStatusBadge, ConfidenceBadge, EntityTypeBadge, OutcomeBadge, SeverityBadge } from "../components/StatusBadge";
import { inspectEventForensics } from "../lib/api";
import { EventForensics } from "../types/investigation";

interface EventForensicsModalProps {
  eventId: string;
  onClose: () => void;
  onSelectEntityKey?: (entityKey: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectIncidentId?: (incidentId: number) => void;
}

export function EventForensicsModal({
  eventId,
  onClose,
  onSelectEntityKey,
  onSelectAlertId,
  onSelectIncidentId,
}: EventForensicsModalProps) {
  const [forensics, setForensics] = useState<EventForensics | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadForensics = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await inspectEventForensics(eventId);
      setForensics(data);
    } catch (err: any) {
      setError(err.message || "Failed to load event forensic reconstruction");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadForensics();
  }, [eventId]);

  const event = forensics?.event;

  return (
    <div className="modal-overlay" onClick={onClose} style={{ zIndex: 1150 }}>
      <div
        className="modal-dialog"
        style={{ width: "940px", maxWidth: "95vw", maxHeight: "90vh", display: "flex", flexDirection: "column" }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="modal-header">
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "12px", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px" }}>
              Event Forensic Lineage
            </span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: "13px", fontWeight: 700 }}>
              {eventId.slice(0, 16)}...
            </span>
            {event && <SeverityBadge severity={event.severity} />}
            {event && <OutcomeBadge outcome={event.outcome} />}
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <button className="btn btn-secondary" style={{ padding: "4px" }} onClick={loadForensics} title="Refresh forensics">
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
              Extracting canonical event provenance, detections, and correlation lineage...
            </div>
          )}

          {error && (
            <div className="panel" style={{ padding: "12px", border: "1px solid var(--badge-alert-border)", background: "var(--badge-alert-bg)" }}>
              <span style={{ color: "var(--badge-alert-text)", fontWeight: 600 }}>{error}</span>
            </div>
          )}

          {forensics && event && !loading && (
            <>
              {/* Event Metadata Banner */}
              <div
                className="panel"
                style={{
                  padding: "10px 14px",
                  background: "var(--bg-surface-subtle)",
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
                  gap: "10px",
                }}
              >
                <div>
                  <span className="property-label">Event Timestamp:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 600 }}>
                    {new Date(event.timestamp).toISOString().replace("T", " ")}
                  </div>
                </div>
                <div>
                  <span className="property-label">Ingested At:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                    {new Date(event.ingested_at).toISOString().replace("T", " ")}
                  </div>
                </div>
                <div>
                  <span className="property-label">Host / Source:</span>
                  <div style={{ fontSize: "12px", fontWeight: 600 }}>
                    {event.host} <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>({event.source})</span>
                  </div>
                </div>
                <div>
                  <span className="property-label">Event Type / Action:</span>
                  <div style={{ fontSize: "12px", fontWeight: 600 }}>
                    {event.event_type} {event.action ? `/ ${event.action}` : ""}
                  </div>
                </div>
              </div>

              {/* Attribution Context */}
              <div
                className="panel"
                style={{
                  padding: "10px 14px",
                  display: "grid",
                  gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
                  gap: "10px",
                }}
              >
                <div>
                  <span className="property-label">Actor / Username:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "12px", fontWeight: 600 }}>
                    {event.actor?.user || event.actor?.raw_user || "N/A"}
                  </div>
                  {event.actor?.uid && (
                    <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>UID: {event.actor.uid}</div>
                  )}
                </div>
                <div>
                  <span className="property-label">Process & PID:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "12px", fontWeight: 600 }}>
                    {event.process?.name || "N/A"} {event.process?.pid ? `[PID: ${event.process.pid}]` : ""}
                  </div>
                  {event.process?.command && (
                    <div style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-secondary)", marginTop: "2px", wordBreak: "break-all" }}>
                      cmd: {event.process.command}
                    </div>
                  )}
                </div>
                <div>
                  <span className="property-label">Network Coordinates:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "12px" }}>
                    {event.network?.src_ip || "N/A"}
                    {event.network?.src_port ? `:${event.network.src_port}` : ""}
                    {event.network?.dest_ip ? ` &rarr; ${event.network.dest_ip}:${event.network.dest_port || ""}` : ""}
                  </div>
                </div>
                <div>
                  <span className="property-label">Parser & Ingestion Provenance:</span>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                    Parser: {event.parser}
                  </div>
                  <div style={{ fontFamily: "var(--font-mono)", fontSize: "10px", color: "var(--text-muted)" }}>
                    Offset: {event.source_offset ?? "N/A"} | File: {event.source_file || "system"}
                  </div>
                </div>
              </div>

              {/* Raw Log Evidence (Immutable) */}
              <div className="panel" style={{ padding: "10px 12px" }}>
                <span className="property-label" style={{ fontWeight: 600, color: "var(--text-secondary)" }}>
                  Canonical Raw Message Evidence (Preserved & Immutable)
                </span>
                <pre
                  style={{
                    margin: "6px 0 0 0",
                    padding: "8px 10px",
                    background: "var(--bg-surface-subtle)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "2px",
                    fontSize: "11px",
                    fontFamily: "var(--font-mono)",
                    whiteSpace: "pre-wrap",
                    wordBreak: "break-all",
                    maxHeight: "120px",
                    overflowY: "auto",
                  }}
                >
                  {event.raw_message}
                </pre>
              </div>

              {/* Lineage: Detections & Alerts */}
              <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
                {/* Detections */}
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600 }}>
                    Triggered Detections ({forensics.detections.length})
                  </span>
                  {forensics.detections.length === 0 ? (
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "6px" }}>
                      No direct detection matches for this single event.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "6px" }}>
                      {forensics.detections.map((det) => (
                        <div
                          key={det.id}
                          style={{
                            padding: "6px 8px",
                            border: "1px solid var(--border-subtle)",
                            borderRadius: "2px",
                            background: "var(--bg-surface)",
                          }}
                        >
                          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                            <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700 }}>
                              {det.rule_id}
                            </span>
                            <SeverityBadge severity={det.severity} />
                          </div>
                          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
                            {det.summary}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Alerts */}
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600 }}>
                    Associated Operational Alerts ({forensics.alerts.length})
                  </span>
                  {forensics.alerts.length === 0 ? (
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "6px" }}>
                      No operational alerts generated directly from this event.
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "6px" }}>
                      {forensics.alerts.map((al) => (
                        <div
                          key={al.id}
                          style={{
                            padding: "6px 8px",
                            border: "1px solid var(--border-subtle)",
                            borderRadius: "2px",
                            background: "var(--bg-surface)",
                            display: "flex",
                            justifyContent: "space-between",
                            alignItems: "center",
                          }}
                        >
                          <div>
                            <div style={{ fontWeight: 600, fontSize: "11px" }}>#{al.id} — {al.title}</div>
                            <div style={{ fontSize: "10px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                              {al.rule_id} | occ: {al.occurrence_count}
                            </div>
                          </div>
                          {onSelectAlertId && (
                            <button
                              className="btn btn-secondary"
                              style={{ padding: "2px 6px", fontSize: "10px" }}
                              onClick={() => {
                                onClose();
                                onSelectAlertId(al.id);
                              }}
                            >
                              View Alert &rarr;
                            </button>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* Incidents Provenance */}
              {forensics.incidents.length > 0 && (
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600 }}>
                    Correlated Security Incidents ({forensics.incidents.length})
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px", marginTop: "6px" }}>
                    {forensics.incidents.map((inc) => (
                      <div
                        key={inc.id}
                        style={{
                          padding: "6px 10px",
                          border: "1px solid var(--border-subtle)",
                          background: "var(--bg-surface)",
                          display: "flex",
                          justifyContent: "space-between",
                          alignItems: "center",
                        }}
                      >
                        <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 700 }}>
                            {inc.incident_key}
                          </span>
                          <SeverityBadge severity={inc.severity} />
                          <span style={{ fontSize: "12px", fontWeight: 600 }}>{inc.title}</span>
                        </div>
                        {onSelectIncidentId && (
                          <button
                            className="btn btn-secondary"
                            style={{ padding: "2px 6px", fontSize: "10px" }}
                            onClick={() => {
                              onClose();
                              onSelectIncidentId(inc.id);
                            }}
                          >
                            Open Investigation &rarr;
                          </button>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Directly Extracted Graph Entities */}
              {forensics.entities && forensics.entities.length > 0 && (
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600 }}>
                    Extracted Entity Nodes ({forensics.entities.length})
                  </span>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "6px", marginTop: "6px" }}>
                    {forensics.entities.map((node, idx) => {
                      const nodeKey = typeof node === "string" ? node : node.id;
                      const nodeLabel = typeof node === "string" ? node : node.label;
                      const nodeType = typeof node === "string" ? "entity" : node.entity_type;
                      return (
                        <div
                          key={nodeKey || idx}
                          style={{
                            display: "inline-flex",
                            alignItems: "center",
                            gap: "6px",
                            padding: "3px 8px",
                            border: "1px solid var(--border-subtle)",
                            borderRadius: "3px",
                            background: "var(--bg-surface)",
                          }}
                        >
                          <EntityTypeBadge entityType={nodeType} />
                          <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", fontWeight: 600 }}>
                            {nodeLabel}
                          </span>
                          {onSelectEntityKey && (
                            <button
                              className="btn btn-secondary"
                              style={{ padding: "1px 5px", fontSize: "10px" }}
                              onClick={() => onSelectEntityKey(nodeKey)}
                              title="Pivot on entity"
                            >
                              Pivot
                            </button>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Supported Graph Relationships */}
              {forensics.relationships && forensics.relationships.length > 0 && (
                <div className="panel" style={{ padding: "10px 12px" }}>
                  <span className="property-label" style={{ fontWeight: 600 }}>
                    Supported Attributed Relationships ({forensics.relationships.length})
                  </span>
                  <div style={{ display: "flex", flexDirection: "column", gap: "4px", marginTop: "6px" }}>
                    {forensics.relationships.map((rel: any, idx: number) => (
                      <div
                        key={rel.id || idx}
                        style={{
                          fontSize: "11px",
                          padding: "4px 8px",
                          border: "1px solid var(--border-subtle)",
                          background: "var(--bg-surface)",
                          display: "flex",
                          alignItems: "center",
                          gap: "8px",
                        }}
                      >
                        <span style={{ fontFamily: "var(--font-mono)" }}>{rel.source}</span>
                        <span className="badge badge-notice" style={{ fontSize: "9px" }}>{rel.relationship_type}</span>
                        <span style={{ fontFamily: "var(--font-mono)" }}>&rarr; {rel.target}</span>
                        <ConfidenceBadge confidence={rel.confidence} />
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
