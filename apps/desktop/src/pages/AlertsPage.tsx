import React, { useEffect, useState } from "react";
import { FilterIcon, RefreshIcon, SearchIcon } from "../components/Icons";
import { AlertStatusBadge, SeverityBadge } from "../components/StatusBadge";
import { fetchAlerts } from "../lib/api";
import { Alert, AlertQueryParams, AlertStatus } from "../types/detection";
import { Severity } from "../types/events";

interface AlertsPageProps {
  onSelectAlert: (alertId: number) => void;
  refreshTrigger: number;
}

export function AlertsPage({ onSelectAlert, refreshTrigger }: AlertsPageProps) {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [hostFilter, setHostFilter] = useState<string>("");
  const [ruleIdFilter, setRuleIdFilter] = useState<string>("");
  const [page, setPage] = useState<number>(0);
  const pageSize = 25;

  const loadAlerts = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: AlertQueryParams = {
        limit: pageSize,
        offset: page * pageSize,
      };
      if (statusFilter) params.status = statusFilter as AlertStatus;
      if (severityFilter) params.severity = severityFilter as Severity;
      if (hostFilter) params.host = hostFilter;
      if (ruleIdFilter) params.rule_id = ruleIdFilter;

      const data = await fetchAlerts(params);
      setAlerts(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || "Failed to load alerts");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, statusFilter, severityFilter, hostFilter, ruleIdFilter, refreshTrigger]);

  const totalPages = Math.ceil(total / pageSize);

  const resetFilters = () => {
    setStatusFilter("");
    setSeverityFilter("");
    setHostFilter("");
    setRuleIdFilter("");
    setPage(0);
  };

  return (
    <div>
      {/* Filtering Toolbar */}
      <div className="panel" style={{ marginBottom: "14px" }}>
        <div className="panel-body" style={{ padding: "10px 14px" }}>
          <div className="toolbar-row" style={{ marginBottom: 0, display: "flex", flexWrap: "wrap", gap: "10px", alignItems: "center" }}>
            {/* Status Quick Filter Chips */}
            <div style={{ display: "flex", gap: "4px" }}>
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
                className={`btn btn-secondary ${statusFilter === "ACKNOWLEDGED" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => { setStatusFilter("ACKNOWLEDGED"); setPage(0); }}
              >
                Acknowledged
              </button>
              <button
                className={`btn btn-secondary ${statusFilter === "RESOLVED" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => { setStatusFilter("RESOLVED"); setPage(0); }}
              >
                Resolved
              </button>
              <button
                className={`btn btn-secondary ${statusFilter === "FALSE_POSITIVE" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => { setStatusFilter("FALSE_POSITIVE"); setPage(0); }}
              >
                False Positive
              </button>
            </div>

            <div style={{ height: "16px", width: "1px", background: "var(--border-subtle)", margin: "0 4px" }} />

            {/* Severity Filter */}
            <select
              className="filter-input"
              value={severityFilter}
              onChange={(e) => { setSeverityFilter(e.target.value); setPage(0); }}
              style={{ fontSize: "11px", padding: "4px 8px" }}
            >
              <option value="">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="ALERT">Alert</option>
              <option value="HIGH">High</option>
              <option value="WARNING">Warning</option>
              <option value="NOTICE">Notice</option>
            </select>

            {/* Host Filter */}
            <input
              type="text"
              className="filter-input"
              placeholder="Filter Host..."
              value={hostFilter}
              onChange={(e) => { setHostFilter(e.target.value); setPage(0); }}
              style={{ fontSize: "11px", padding: "4px 8px", width: "130px" }}
            />

            {/* Rule ID Filter */}
            <input
              type="text"
              className="filter-input"
              placeholder="Filter Rule ID..."
              value={ruleIdFilter}
              onChange={(e) => { setRuleIdFilter(e.target.value); setPage(0); }}
              style={{ fontSize: "11px", padding: "4px 8px", width: "160px" }}
            />

            {(statusFilter || severityFilter || hostFilter || ruleIdFilter) && (
              <button
                className="btn btn-secondary"
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={resetFilters}
              >
                Clear Filters
              </button>
            )}

            <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Total: <strong>{total}</strong> alert{total !== 1 ? "s" : ""}
              </span>
              <button
                className="btn btn-secondary"
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={loadAlerts}
                title="Refresh alerts"
              >
                <RefreshIcon />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Error state */}
      {error && (
        <div className="panel" style={{ marginBottom: "14px", border: "1px solid var(--badge-alert-border)", background: "var(--badge-alert-bg)" }}>
          <div className="panel-body" style={{ color: "var(--badge-alert-text)", padding: "10px 14px", fontSize: "12px" }}>
            {error}
          </div>
        </div>
      )}

      {/* Alerts Table */}
      <div className="panel">
        <div className="panel-body" style={{ padding: 0 }}>
          {loading ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
              Querying security alerts...
            </div>
          ) : alerts.length === 0 ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
              No security alerts match the selected criteria.
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: "80px" }}>Severity</th>
                  <th style={{ width: "110px" }}>Status</th>
                  <th>Alert Title & Finding</th>
                  <th>Detection Rule</th>
                  <th>Host</th>
                  <th style={{ width: "70px", textAlign: "center" }}>Hits</th>
                  <th>Last Seen</th>
                  <th style={{ width: "80px", textAlign: "center" }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((alert) => (
                  <tr
                    key={alert.id}
                    onClick={() => onSelectAlert(alert.id)}
                    style={{ cursor: "pointer" }}
                  >
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <AlertStatusBadge status={alert.status} />
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: "var(--text-primary)", fontSize: "12px" }}>
                        {alert.title}
                      </div>
                      <div style={{ color: "var(--text-muted)", fontSize: "11px", marginTop: "2px" }}>
                        {alert.description.length > 80 ? `${alert.description.substring(0, 80)}...` : alert.description}
                      </div>
                    </td>
                    <td className="mono-cell" style={{ fontSize: "11px" }}>
                      {alert.rule_id}
                    </td>
                    <td className="mono-cell" style={{ fontSize: "11px" }}>
                      {alert.host}
                    </td>
                    <td style={{ textAlign: "center" }}>
                      <span className="mono-cell" style={{ fontWeight: 700, fontSize: "11px" }}>
                        {alert.occurrence_count}
                      </span>
                    </td>
                    <td className="mono-cell" style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
                      {new Date(alert.last_seen).toLocaleString()}
                    </td>
                    <td style={{ textAlign: "center" }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: "3px 8px", fontSize: "11px" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectAlert(alert.id);
                        }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "12px", padding: "0 4px" }}>
          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
            Showing page {page + 1} of {totalPages} ({total} total alerts)
          </span>
          <div style={{ display: "flex", gap: "6px" }}>
            <button
              className="btn btn-secondary"
              disabled={page === 0}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              style={{ fontSize: "11px", padding: "4px 8px" }}
            >
              Previous
            </button>
            <button
              className="btn btn-secondary"
              disabled={page >= totalPages - 1}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              style={{ fontSize: "11px", padding: "4px 8px" }}
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
