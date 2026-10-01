import React, { useEffect, useState } from "react";
import { CorrelateIcon, FilterIcon, IncidentIcon, RefreshIcon, SearchIcon } from "../components/Icons";
import { IncidentStatusBadge, SeverityBadge } from "../components/StatusBadge";
import { fetchIncidents, triggerIncidentCorrelation } from "../lib/api";
import { Severity } from "../types/events";
import { Incident, IncidentQueryParams, IncidentStatus } from "../types/incidents";

interface IncidentsPageProps {
  onSelectIncident: (incidentId: number) => void;
  refreshTrigger: number;
}

export function IncidentsPage({ onSelectIncident, refreshTrigger }: IncidentsPageProps) {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Status breakdown metrics
  const [metrics, setMetrics] = useState<{
    open: number;
    investigating: number;
    contained: number;
    resolved: number;
  }>({ open: 0, investigating: 0, contained: 0, resolved: 0 });

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [hostFilter, setHostFilter] = useState<string>("");
  const [userFilter, setUserFilter] = useState<string>("");
  const [page, setPage] = useState<number>(0);
  const pageSize = 20;

  // Correlation triggering
  const [correlating, setCorrelating] = useState<boolean>(false);
  const [correlationNotice, setCorrelationNotice] = useState<string | null>(null);

  const loadIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: IncidentQueryParams = {
        limit: pageSize,
        offset: page * pageSize,
      };
      if (statusFilter) params.status = statusFilter as IncidentStatus;
      if (severityFilter) params.severity = severityFilter as Severity;
      if (hostFilter) params.host = hostFilter;
      if (userFilter) params.user = userFilter;

      const data = await fetchIncidents(params);
      setIncidents(data.items);
      setTotal(data.total);

      // Also compute quick metric counts
      const [openRes, invRes, contRes, resRes] = await Promise.all([
        fetchIncidents({ status: "OPEN", limit: 1 }).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "INVESTIGATING", limit: 1 }).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "CONTAINED", limit: 1 }).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "RESOLVED", limit: 1 }).catch(() => ({ total: 0 })),
      ]);

      setMetrics({
        open: openRes.total,
        investigating: invRes.total,
        contained: contRes.total,
        resolved: resRes.total,
      });
    } catch (err: any) {
      setError(err.message || "Failed to load security incidents");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadIncidents();
  }, [page, statusFilter, severityFilter, hostFilter, userFilter, refreshTrigger]);

  const handleTriggerCorrelation = async () => {
    setCorrelating(true);
    setCorrelationNotice(null);
    try {
      const res = await triggerIncidentCorrelation();
      if (res.correlated_incidents_count > 0) {
        setCorrelationNotice(`Correlated ${res.correlated_incidents_count} new security incident(s)!`);
      } else {
        setCorrelationNotice("Correlation engine ran: all operational alerts are already clustered.");
      }
      await loadIncidents();
    } catch (err: any) {
      setCorrelationNotice(`Correlation error: ${err.message || "Engine failure"}`);
    } finally {
      setCorrelating(false);
    }
  };

  const totalPages = Math.ceil(total / pageSize);

  const resetFilters = () => {
    setStatusFilter("");
    setSeverityFilter("");
    setHostFilter("");
    setUserFilter("");
    setPage(0);
  };

  return (
    <div>
      {/* Metric Cards Banner */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "12px",
          marginBottom: "16px",
        }}
      >
        <div className="panel" style={{ padding: "12px 16px" }}>
          <span className="property-label">Total Incidents</span>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px" }}>
            {total}
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px", borderLeft: "3px solid #dc2626" }}>
          <span className="property-label" style={{ color: "#991b1b" }}>Active / Open</span>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px", color: "#991b1b" }}>
            {metrics.open}
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px", borderLeft: "3px solid #d97706" }}>
          <span className="property-label" style={{ color: "#92400e" }}>Under Investigation</span>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px", color: "#92400e" }}>
            {metrics.investigating}
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px", borderLeft: "3px solid #0284c7" }}>
          <span className="property-label" style={{ color: "#0369a1" }}>Contained</span>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px", color: "#0369a1" }}>
            {metrics.contained}
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px", borderLeft: "3px solid #16a34a" }}>
          <span className="property-label" style={{ color: "#166534" }}>Resolved</span>
          <div style={{ fontSize: "20px", fontWeight: 700, marginTop: "4px", color: "#166534" }}>
            {metrics.resolved}
          </div>
        </div>
      </div>

      {/* Notice Banner */}
      {correlationNotice && (
        <div
          className="panel"
          style={{
            marginBottom: "12px",
            padding: "10px 14px",
            background: "var(--badge-notice-bg)",
            border: "1px solid var(--badge-notice-border)",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span style={{ fontSize: "12px", color: "var(--badge-notice-text)", fontWeight: 600 }}>
            {correlationNotice}
          </span>
          <button
            className="btn btn-secondary"
            style={{ padding: "2px 6px", fontSize: "10px" }}
            onClick={() => setCorrelationNotice(null)}
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Filter and Correlation Action Toolbar */}
      <div className="panel" style={{ marginBottom: "14px" }}>
        <div className="panel-body" style={{ padding: "10px 14px" }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              flexWrap: "wrap",
              gap: "10px",
            }}
          >
            {/* Status Quick Filter Chips */}
            <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
              <button
                className={`btn btn-secondary ${statusFilter === "" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => { setStatusFilter(""); setPage(0); }}
              >
                All Statuses
              </button>
              <button
                className={`btn btn-secondary ${statusFilter === "OPEN" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px", fontWeight: statusFilter === "OPEN" ? 700 : 400 }}
                onClick={() => { setStatusFilter("OPEN"); setPage(0); }}
              >
                Open
              </button>
              <button
                className={`btn btn-secondary ${statusFilter === "INVESTIGATING" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => { setStatusFilter("INVESTIGATING"); setPage(0); }}
              >
                Investigating
              </button>
              <button
                className={`btn btn-secondary ${statusFilter === "CONTAINED" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => { setStatusFilter("CONTAINED"); setPage(0); }}
              >
                Contained
              </button>
              <button
                className={`btn btn-secondary ${statusFilter === "RESOLVED" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => { setStatusFilter("RESOLVED"); setPage(0); }}
              >
                Resolved
              </button>
            </div>

            {/* On-Demand Correlation Trigger */}
            <button
              className="btn btn-primary"
              disabled={correlating}
              onClick={handleTriggerCorrelation}
              style={{ padding: "5px 12px", fontSize: "11px" }}
            >
              <CorrelateIcon />
              <span>{correlating ? "Correlating Alerts..." : "Correlate Alerts Now"}</span>
            </button>
          </div>

          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "10px",
              marginTop: "10px",
              paddingTop: "10px",
              borderTop: "1px solid var(--border-subtle)",
              alignItems: "center",
            }}
          >
            {/* Severity Filter */}
            <select
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(0); }}
              style={{
                padding: "4px 8px",
                fontSize: "11px",
                border: "1px solid var(--border-strong)",
                borderRadius: "2px",
                background: "var(--bg-surface)",
              }}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="ALERT">Alert</option>
              <option value="WARNING">Warning</option>
              <option value="NOTICE">Notice</option>
            </select>

            {/* Host Search */}
            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
              <SearchIcon />
              <input
                type="text"
                placeholder="Filter by host..."
                value={hostFilter}
                onChange={(e) => { setHostFilter(e.target.value); setPage(0); }}
                style={{
                  padding: "4px 8px",
                  fontSize: "11px",
                  width: "140px",
                  border: "1px solid var(--border-strong)",
                  borderRadius: "2px",
                }}
              />
            </div>

            {/* User Search */}
            <div style={{ display: "flex", alignItems: "center", gap: "4px" }}>
              <input
                type="text"
                placeholder="Filter by user..."
                value={userFilter}
                onChange={(e) => { setUserFilter(e.target.value); setPage(0); }}
                style={{
                  padding: "4px 8px",
                  fontSize: "11px",
                  width: "130px",
                  border: "1px solid var(--border-strong)",
                  borderRadius: "2px",
                }}
              />
            </div>

            {(statusFilter || severityFilter || hostFilter || userFilter) && (
              <button
                className="btn btn-secondary"
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={resetFilters}
              >
                Reset Filters
              </button>
            )}

            <button
              className="btn btn-secondary"
              style={{ padding: "4px 8px", fontSize: "11px", marginLeft: "auto" }}
              onClick={loadIncidents}
            >
              <RefreshIcon /> Refresh
            </button>
          </div>
        </div>
      </div>

      {/* Incidents Data Table */}
      <div className="panel">
        <div className="panel-body" style={{ padding: 0 }}>
          {loading && (
            <div style={{ padding: "30px", textAlign: "center", color: "var(--text-muted)" }}>
              Loading correlated security incidents...
            </div>
          )}

          {error && (
            <div style={{ padding: "20px", color: "var(--badge-alert-text)", textAlign: "center" }}>
              {error}
            </div>
          )}

          {!loading && !error && incidents.length === 0 && (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
              <IncidentIcon className="" />
              <p style={{ marginTop: "8px", fontWeight: 500 }}>No security incidents found.</p>
              <p style={{ fontSize: "11px", marginTop: "4px" }}>
                Click "Correlate Alerts Now" above to aggregate unassigned operational alerts into incidents.
              </p>
            </div>
          )}

          {!loading && !error && incidents.length > 0 && (
            <div style={{ overflowX: "auto" }}>
              <table className="data-table" style={{ width: "100%" }}>
                <thead>
                  <tr>
                    <th>Key</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Incident Title & Summary</th>
                    <th>Primary Host / User</th>
                    <th>Alerts</th>
                    <th>Events</th>
                    <th>Temporal Window</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr
                      key={inc.id}
                      style={{ cursor: "pointer" }}
                      onClick={() => onSelectIncident(inc.id)}
                    >
                      <td style={{ fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: "11px" }}>
                        {inc.incident_key}
                      </td>
                      <td>
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td>
                        <IncidentStatusBadge status={inc.status} />
                      </td>
                      <td>
                        <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>{inc.title}</div>
                        <div
                          style={{
                            fontSize: "11px",
                            color: "var(--text-muted)",
                            maxWidth: "340px",
                            whiteSpace: "nowrap",
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                          }}
                        >
                          {inc.summary}
                        </div>
                      </td>
                      <td>
                        <div style={{ fontWeight: 500 }}>{inc.primary_host}</div>
                        {inc.primary_user && (
                          <div style={{ fontSize: "11px", color: "var(--text-muted)" }}>
                            user: {inc.primary_user}
                          </div>
                        )}
                      </td>
                      <td>
                        <span className="badge badge-alert" style={{ fontSize: "10px", padding: "1px 6px" }}>
                          {inc.alert_count}
                        </span>
                      </td>
                      <td>
                        <span className="badge badge-neutral" style={{ fontSize: "10px", padding: "1px 6px" }}>
                          {inc.event_count}
                        </span>
                      </td>
                      <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px", whiteSpace: "nowrap" }}>
                        <div>{new Date(inc.first_seen).toISOString().slice(0, 16).replace("T", " ")}</div>
                        <div style={{ color: "var(--text-muted)", fontSize: "10px" }}>
                          to {new Date(inc.last_seen).toISOString().slice(11, 16)}
                        </div>
                      </td>
                      <td>
                        <button
                          className="btn btn-secondary"
                          style={{ padding: "3px 8px", fontSize: "11px" }}
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectIncident(inc.id);
                          }}
                        >
                          Investigate &rarr;
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Pagination Bar */}
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
              Showing {page * pageSize + 1}–{Math.min(total, (page + 1) * pageSize)} of {total} incidents
            </span>

            <div style={{ display: "flex", gap: "6px" }}>
              <button
                className="btn btn-secondary"
                disabled={page === 0}
                onClick={() => setPage((p) => Math.max(0, p - 1))}
                style={{ padding: "3px 8px", fontSize: "11px" }}
              >
                Previous
              </button>
              <span style={{ fontSize: "11px", padding: "4px 8px" }}>
                Page {page + 1} of {totalPages}
              </span>
              <button
                className="btn btn-secondary"
                disabled={page >= totalPages - 1}
                onClick={() => setPage((p) => p + 1)}
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
