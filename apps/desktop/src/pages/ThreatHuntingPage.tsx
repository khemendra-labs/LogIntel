import React, { useState } from "react";
import { FilterIcon, HuntIcon, RefreshIcon, SearchIcon } from "../components/Icons";
import { OutcomeBadge, SeverityBadge } from "../components/StatusBadge";
import { huntEvents } from "../lib/api";
import { CanonicalEvent, Severity } from "../types/events";
import { ThreatHuntFilter, ThreatHuntResponse } from "../types/investigation";

interface ThreatHuntingPageProps {
  onSelectEventForensics: (eventId: string) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function ThreatHuntingPage({
  onSelectEventForensics,
  onSelectEntityKey,
}: ThreatHuntingPageProps) {
  // Hunting filters
  const [query, setQuery] = useState<string>("");
  const [eventType, setEventType] = useState<string>("");
  const [source, setSource] = useState<string>("");
  const [host, setHost] = useState<string>("");
  const [username, setUsername] = useState<string>("");
  const [ip, setIp] = useState<string>("");
  const [processName, setProcessName] = useState<string>("");
  const [command, setCommand] = useState<string>("");
  const [action, setAction] = useState<string>("");
  const [outcome, setOutcome] = useState<string>("");
  const [severity, setSeverity] = useState<string>("");
  const [ioc, setIoc] = useState<string>("");
  const [detectionRule, setDetectionRule] = useState<string>("");
  const [startTime, setStartTime] = useState<string>("");
  const [endTime, setEndTime] = useState<string>("");

  // Pagination & Sort
  const [page, setPage] = useState<number>(0);
  const pageSize = 50;

  // State
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [huntResults, setHuntResults] = useState<ThreatHuntResponse | null>(null);
  const [hasExecuted, setHasExecuted] = useState<boolean>(false);

  const executeHunt = async (pageIndex: number = 0) => {
    setLoading(true);
    setError(null);
    try {
      const filter: ThreatHuntFilter = {
        limit: pageSize,
        offset: pageIndex * pageSize,
      };
      if (query.trim()) {
        filter.search_text = query.trim();
        filter.query = query.trim();
      }
      if (eventType) filter.event_type = eventType;
      if (source) filter.source = source;
      if (host.trim()) filter.host = host.trim();
      if (username.trim()) filter.username = username.trim();
      if (ip.trim()) {
        filter.src_ip = ip.trim();
        filter.ip = ip.trim();
      }
      if (processName.trim()) {
        filter.process_name = processName.trim();
        filter.process = processName.trim();
      }
      if (command.trim()) filter.command = command.trim();
      if (action.trim()) filter.action = action.trim();
      if (outcome) filter.outcome = outcome;
      if (severity) filter.severity = severity as Severity;
      if (ioc.trim()) filter.ioc = ioc.trim();
      if (detectionRule.trim()) {
        filter.rule_id = detectionRule.trim();
        filter.detection_rule = detectionRule.trim();
      }
      if (startTime) filter.start_time = new Date(startTime).toISOString();
      if (endTime) filter.end_time = new Date(endTime).toISOString();

      const data = await huntEvents(filter);
      setHuntResults(data);
      setPage(pageIndex);
      setHasExecuted(true);
    } catch (err: any) {
      setError(err.message || "Threat hunting query failed");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setQuery("");
    setEventType("");
    setSource("");
    setHost("");
    setUsername("");
    setIp("");
    setProcessName("");
    setCommand("");
    setAction("");
    setOutcome("");
    setSeverity("");
    setIoc("");
    setDetectionRule("");
    setStartTime("");
    setEndTime("");
    setPage(0);
    setHuntResults(null);
    setHasExecuted(false);
  };

  const totalResults = huntResults?.total_matches ?? huntResults?.total ?? 0;
  const totalPages = Math.ceil(totalResults / pageSize);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
      {/* Search Header Banner */}
      <div className="panel" style={{ padding: "14px 18px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <HuntIcon className="" />
            <div>
              <h2 style={{ fontSize: "16px", fontWeight: 700, margin: 0 }}>
                Deterministic Threat Hunting Workspace
              </h2>
              <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                Execute bounded, multi-parameter correlation and canonical evidence queries across all ingested telemetry.
              </span>
            </div>
          </div>
          <div style={{ display: "flex", gap: "8px" }}>
            <button
              className="btn btn-secondary"
              onClick={handleReset}
              disabled={loading}
              style={{ fontSize: "12px", padding: "5px 12px" }}
            >
              Clear Filters
            </button>
            <button
              className="btn btn-primary"
              onClick={() => executeHunt(0)}
              disabled={loading}
              style={{ fontSize: "12px", padding: "5px 16px" }}
            >
              {loading ? "Hunting..." : "Execute Hunt"}
            </button>
          </div>
        </div>

        {/* Primary Filter Grid */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
            gap: "10px",
          }}
        >
          {/* Free-text Query */}
          <div>
            <label className="property-label">Full-Text / Message Query</label>
            <input
              type="text"
              className="input-control"
              placeholder="Substring match in raw log or summary..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* Event Type */}
          <div>
            <label className="property-label">Event Type</label>
            <select
              className="input-control"
              value={eventType}
              onChange={(e) => setEventType(e.target.value)}
              style={{ width: "100%", marginTop: "3px" }}
            >
              <option value="">All Event Types</option>
              <option value="auth">auth</option>
              <option value="sudo">sudo</option>
              <option value="exec">exec</option>
              <option value="network">network</option>
              <option value="kernel">kernel</option>
              <option value="syslog">syslog</option>
            </select>
          </div>

          {/* Source */}
          <div>
            <label className="property-label">Telemetry Source</label>
            <select
              className="input-control"
              value={source}
              onChange={(e) => setSource(e.target.value)}
              style={{ width: "100%", marginTop: "3px" }}
            >
              <option value="">All Sources</option>
              <option value="auth.log">auth.log</option>
              <option value="syslog">syslog</option>
              <option value="dpkg.log">dpkg.log</option>
              <option value="journald">journald</option>
            </select>
          </div>

          {/* Host */}
          <div>
            <label className="property-label">Target Hostname</label>
            <input
              type="text"
              className="input-control"
              placeholder="e.g. server-01"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* Username */}
          <div>
            <label className="property-label">Actor Username</label>
            <input
              type="text"
              className="input-control"
              placeholder="e.g. root, khemendra"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* IP Address */}
          <div>
            <label className="property-label">Network IP (Src or Dest)</label>
            <input
              type="text"
              className="input-control"
              placeholder="e.g. 192.168.1.100"
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* Process */}
          <div>
            <label className="property-label">Process Name</label>
            <input
              type="text"
              className="input-control"
              placeholder="e.g. sshd, sudo, bash"
              value={processName}
              onChange={(e) => setProcessName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* Command Substring */}
          <div>
            <label className="property-label">Command Line</label>
            <input
              type="text"
              className="input-control"
              placeholder="Command substring..."
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* Outcome */}
          <div>
            <label className="property-label">Outcome</label>
            <select
              className="input-control"
              value={outcome}
              onChange={(e) => setOutcome(e.target.value)}
              style={{ width: "100%", marginTop: "3px" }}
            >
              <option value="">All Outcomes</option>
              <option value="success">Success</option>
              <option value="failure">Failure</option>
              <option value="unknown">Unknown</option>
            </select>
          </div>

          {/* Severity */}
          <div>
            <label className="property-label">Severity Threshold</label>
            <select
              className="input-control"
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              style={{ width: "100%", marginTop: "3px" }}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
              <option value="INFORMATIONAL">INFORMATIONAL</option>
            </select>
          </div>

          {/* Detection Rule ID */}
          <div>
            <label className="property-label">Triggered Detection Rule</label>
            <input
              type="text"
              className="input-control"
              placeholder="e.g. auth.ssh_bruteforce"
              value={detectionRule}
              onChange={(e) => setDetectionRule(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* IOC Substring */}
          <div>
            <label className="property-label">Indicator of Compromise (IOC)</label>
            <input
              type="text"
              className="input-control"
              placeholder="IP, hash, or domain IOC..."
              value={ioc}
              onChange={(e) => setIoc(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && executeHunt(0)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* Start Time */}
          <div>
            <label className="property-label">Temporal Window Start</label>
            <input
              type="datetime-local"
              className="input-control"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>

          {/* End Time */}
          <div>
            <label className="property-label">Temporal Window End</label>
            <input
              type="datetime-local"
              className="input-control"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
              style={{ width: "100%", marginTop: "3px" }}
            />
          </div>
        </div>
      </div>

      {/* Query Error State */}
      {error && (
        <div className="panel" style={{ padding: "12px", border: "1px solid var(--badge-alert-border)", background: "var(--badge-alert-bg)" }}>
          <span style={{ color: "var(--badge-alert-text)", fontWeight: 600 }}>{error}</span>
        </div>
      )}

      {/* Hunt Results Section */}
      <div className="panel">
        <div
          className="panel-header"
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            padding: "10px 14px",
            borderBottom: "1px solid var(--border-subtle)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ fontSize: "13px", fontWeight: 700 }}>
              Search Results
            </span>
            {hasExecuted && (
              <span className="badge badge-neutral" style={{ fontSize: "11px" }}>
                {totalResults.toLocaleString()} match{totalResults !== 1 ? "es" : ""}
              </span>
            )}
          </div>
          {huntResults && (
            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
              Page {page + 1} of {totalPages || 1}
            </span>
          )}
        </div>

        <div className="panel-body" style={{ padding: 0 }}>
          {loading && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
              Scanning indexed canonical log repository...
            </div>
          )}

          {!loading && !hasExecuted && (
            <div style={{ textAlign: "center", padding: "50px 20px", color: "var(--text-muted)" }}>
              <HuntIcon className="" />
              <p style={{ marginTop: "10px", fontWeight: 500 }}>
                Configure query filters above and click "Execute Hunt" to begin investigation.
              </p>
            </div>
          )}

          {!loading && hasExecuted && huntResults && huntResults.items.length === 0 && (
            <div style={{ textAlign: "center", padding: "40px", color: "var(--text-muted)" }}>
              No canonical telemetry events matched the combined hunting criteria.
            </div>
          )}

          {!loading && huntResults && huntResults.items.length > 0 && (
            <div style={{ overflowX: "auto" }}>
              <table className="data-table" style={{ width: "100%" }}>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Host</th>
                    <th>Source</th>
                    <th>Type / Action</th>
                    <th>Severity</th>
                    <th>Outcome</th>
                    <th>Actor / User</th>
                    <th>Network IP</th>
                    <th>Summary / Message</th>
                    <th>Forensic Action</th>
                  </tr>
                </thead>
                <tbody>
                  {huntResults.items.map((evt) => (
                    <tr
                      key={evt.id}
                      style={{ cursor: "pointer" }}
                      onClick={() => onSelectEventForensics(evt.id)}
                    >
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px", whiteSpace: "nowrap" }}>
                        {new Date(evt.timestamp).toISOString().slice(0, 19).replace("T", " ")}
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                        {evt.host}
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ fontSize: "10px" }}>{evt.source}</span>
                      </td>
                      <td style={{ fontSize: "11px" }}>
                        <div>{evt.event_type}</div>
                        {evt.action && <div style={{ fontSize: "10px", color: "var(--text-muted)" }}>{evt.action}</div>}
                      </td>
                      <td>
                        <SeverityBadge severity={evt.severity} />
                      </td>
                      <td>
                        <OutcomeBadge outcome={evt.outcome} />
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                        {evt.actor?.user || evt.actor?.raw_user || "—"}
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                        {evt.network?.src_ip || "—"}
                      </td>
                      <td
                        style={{
                          fontSize: "11px",
                          maxWidth: "280px",
                          overflow: "hidden",
                          textOverflow: "ellipsis",
                          whiteSpace: "nowrap",
                        }}
                      >
                        {evt.summary || evt.raw_message}
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "2px 8px", fontSize: "10px" }}
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectEventForensics(evt.id);
                          }}
                        >
                          Forensics &rarr;
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div
            style={{
              padding: "10px 14px",
              borderTop: "1px solid var(--border-subtle)",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              background: "var(--bg-surface-subtle)",
            }}
          >
            <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>
              Showing {page * pageSize + 1}–{Math.min(totalResults, (page + 1) * pageSize)} of {totalResults} matches
            </span>

            <div style={{ display: "flex", gap: "6px" }}>
              <button
                className="btn btn-secondary"
                disabled={page === 0 || loading}
                onClick={() => executeHunt(page - 1)}
                style={{ padding: "3px 8px", fontSize: "11px" }}
              >
                Previous
              </button>
              <span style={{ fontSize: "11px", padding: "4px 8px" }}>
                Page {page + 1} of {totalPages}
              </span>
              <button
                className="btn btn-secondary"
                disabled={page >= totalPages - 1 || loading}
                onClick={() => executeHunt(page + 1)}
                style={{ padding: "3px 8px", fontSize: "11px" }}
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
