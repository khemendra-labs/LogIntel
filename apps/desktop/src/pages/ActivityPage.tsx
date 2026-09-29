import React, { useEffect, useState } from "react";
import { FilterIcon, SearchIcon } from "../components/Icons";
import { OutcomeBadge, SeverityBadge } from "../components/StatusBadge";
import { EventQueryParams, fetchEvents } from "../lib/api";
import { CanonicalEvent } from "../types/events";

interface ActivityPageProps {
  initialFilter?: { severity?: string; source?: string } | null;
  onSelectEvent: (event: CanonicalEvent) => void;
  refreshTrigger: number;
}

export function ActivityPage({
  initialFilter,
  onSelectEvent,
  refreshTrigger,
}: ActivityPageProps) {
  const [events, setEvents] = useState<CanonicalEvent[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filter states
  const [page, setPage] = useState<number>(0);
  const pageSize = 50;

  const [source, setSource] = useState<string>(initialFilter?.source || "");
  const [severity, setSeverity] = useState<string>(initialFilter?.severity || "");
  const [eventType, setEventType] = useState<string>("");
  const [outcome, setOutcome] = useState<string>("");
  const [username, setUsername] = useState<string>("");
  const [ip, setIp] = useState<string>("");
  const [search, setSearch] = useState<string>("");
  const [sortOrder, setSortOrder] = useState<"DESC" | "ASC">("DESC");

  // Load events
  const loadEvents = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: EventQueryParams = {
        limit: pageSize,
        offset: page * pageSize,
        sortOrder,
      };
      if (source) params.source = source;
      if (severity) params.severity = severity;
      if (eventType) params.eventType = eventType;
      if (outcome) params.outcome = outcome;
      if (username) params.username = username;
      if (ip) params.ip = ip;
      if (search) params.search = search;

      const data = await fetchEvents(params);
      setEvents(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || "Failed to query telemetry events");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadEvents();
  }, [page, source, severity, eventType, outcome, username, ip, sortOrder, refreshTrigger]);

  // Debounced search
  useEffect(() => {
    const handler = setTimeout(() => {
      setPage(0);
      loadEvents();
    }, 300);
    return () => clearTimeout(handler);
  }, [search]);

  const totalPages = Math.ceil(total / pageSize);

  const resetFilters = () => {
    setSource("");
    setSeverity("");
    setEventType("");
    setOutcome("");
    setUsername("");
    setIp("");
    setSearch("");
    setPage(0);
  };

  return (
    <div>
      {/* Filtering Toolbar */}
      <div className="panel" style={{ marginBottom: "14px" }}>
        <div className="panel-body" style={{ padding: "10px 14px" }}>
          <div className="toolbar-row" style={{ marginBottom: 0 }}>
            <div className="filter-group">
              {/* Text Search */}
              <div style={{ display: "flex", alignItems: "center", position: "relative" }}>
                <input
                  type="text"
                  placeholder="Search raw message, summary, user..."
                  className="input-control"
                  style={{ width: "240px", paddingLeft: "26px" }}
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
                <span style={{ position: "absolute", left: "8px", top: "7px", color: "var(--text-muted)", pointerEvents: "none" }}>
                  <SearchIcon />
                </span>
              </div>

              {/* Source Filter */}
              <select
                className="input-control"
                value={source}
                onChange={(e) => {
                  setSource(e.target.value);
                  setPage(0);
                }}
              >
                <option value="">All Sources</option>
                <option value="journald">journald</option>
                <option value="auth.log">auth.log</option>
                <option value="syslog">syslog</option>
                <option value="kern.log">kern.log</option>
              </select>

              {/* Severity Filter */}
              <select
                className="input-control"
                value={severity}
                onChange={(e) => {
                  setSeverity(e.target.value);
                  setPage(0);
                }}
              >
                <option value="">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="ALERT">ALERT</option>
                <option value="WARNING">WARNING</option>
                <option value="NOTICE">NOTICE</option>
                <option value="INFORMATIONAL">INFORMATIONAL</option>
                <option value="DEBUG">DEBUG</option>
              </select>

              {/* Outcome Filter */}
              <select
                className="input-control"
                value={outcome}
                onChange={(e) => {
                  setOutcome(e.target.value);
                  setPage(0);
                }}
              >
                <option value="">All Outcomes</option>
                <option value="SUCCESS">SUCCESS</option>
                <option value="FAILURE">FAILURE</option>
                <option value="ATTEMPT">ATTEMPT</option>
              </select>

              {/* Sort Order */}
              <select
                className="input-control"
                value={sortOrder}
                onChange={(e) => setSortOrder(e.target.value as "DESC" | "ASC")}
              >
                <option value="DESC">Newest First</option>
                <option value="ASC">Oldest First</option>
              </select>

              {/* User filter */}
              <input
                type="text"
                placeholder="Filter user..."
                className="input-control"
                style={{ width: "110px" }}
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  setPage(0);
                }}
              />

              {/* IP filter */}
              <input
                type="text"
                placeholder="Filter IP..."
                className="input-control"
                style={{ width: "110px" }}
                value={ip}
                onChange={(e) => {
                  setIp(e.target.value);
                  setPage(0);
                }}
              />

              {(source || severity || eventType || outcome || username || ip || search) && (
                <button className="btn" onClick={resetFilters}>
                  Clear Filters
                </button>
              )}
            </div>

            <div style={{ fontSize: "11px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
              Matching: <strong>{total.toLocaleString()}</strong> events
            </div>
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="panel" style={{ borderColor: "var(--badge-alert-border)", background: "var(--badge-alert-bg)" }}>
          <div className="panel-body" style={{ color: "var(--badge-alert-text)" }}>
            <strong>Query Error:</strong> {error}
          </div>
        </div>
      )}

      {/* Technical Events Table */}
      <div className="tech-table-container">
        <table className="tech-table">
          <thead>
            <tr>
              <th style={{ width: "140px" }}>Time (UTC)</th>
              <th style={{ width: "85px" }}>Severity</th>
              <th style={{ width: "150px" }}>Event Type</th>
              <th style={{ width: "90px" }}>User</th>
              <th style={{ width: "110px" }}>Process</th>
              <th style={{ width: "90px" }}>Source</th>
              <th style={{ width: "120px" }}>Remote IP</th>
              <th style={{ width: "80px" }}>Outcome</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={9} style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                  Querying local SQLite telemetry store...
                </td>
              </tr>
            ) : events.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ textAlign: "center", padding: "30px", color: "var(--text-muted)" }}>
                  No telemetry events match current filter criteria.
                </td>
              </tr>
            ) : (
              events.map((event) => (
                <tr key={event.id} onClick={() => onSelectEvent(event)}>
                  <td className="mono-cell" style={{ whiteSpace: "nowrap" }}>
                    {new Date(event.timestamp).toISOString().replace("T", " ").substring(0, 19)}
                  </td>
                  <td>
                    <SeverityBadge severity={event.severity} />
                  </td>
                  <td className="mono-cell" style={{ fontSize: "11px" }}>
                    {event.event_type}
                  </td>
                  <td className="mono-cell" style={{ color: event.actor.username ? "var(--text-primary)" : "var(--text-muted)" }}>
                    {event.actor.username || "—"}
                  </td>
                  <td className="mono-cell" style={{ color: event.process.name ? "var(--text-primary)" : "var(--text-muted)" }}>
                    {event.process.name ? `${event.process.name}${event.process.pid ? `[${event.process.pid}]` : ""}` : "—"}
                  </td>
                  <td className="mono-cell">{event.source}</td>
                  <td className="mono-cell" style={{ color: event.network.src_ip ? "var(--text-primary)" : "var(--text-muted)" }}>
                    {event.network.src_ip || "—"}
                  </td>
                  <td>
                    <OutcomeBadge outcome={event.outcome} />
                  </td>
                  <td
                    style={{
                      maxWidth: "400px",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={event.summary}
                  >
                    {event.summary}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "12px" }}>
        <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
          Showing {events.length > 0 ? page * pageSize + 1 : 0} to{" "}
          {Math.min((page + 1) * pageSize, total)} of {total.toLocaleString()} events
        </div>

        <div style={{ display: "flex", gap: "6px" }}>
          <button
            className="btn"
            disabled={page === 0 || loading}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            Previous
          </button>
          <span style={{ display: "flex", alignItems: "center", padding: "0 8px", fontSize: "11px", fontFamily: "var(--font-mono)" }}>
            Page {page + 1} of {Math.max(1, totalPages)}
          </span>
          <button
            className="btn"
            disabled={page + 1 >= totalPages || loading}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
