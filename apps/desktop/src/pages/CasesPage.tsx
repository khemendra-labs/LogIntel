import React, { useEffect, useState } from "react";
import { CaseIcon, FilterIcon, RefreshIcon, SearchIcon } from "../components/Icons";
import { fetchCases, createOrOpenCase } from "../lib/api";
import { CaseStatus, InvestigationCase } from "../types/investigation";

interface CasesPageProps {
  onSelectCase: (caseId: number, incidentId: number) => void;
  refreshTrigger?: number;
}

export function CasesPage({ onSelectCase, refreshTrigger = 0 }: CasesPageProps) {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchQuery, setSearchQuery] = useState<string>("");

  // Create Case Modal
  const [createModalOpen, setCreateModalOpen] = useState<boolean>(false);
  const [newIncidentId, setNewIncidentId] = useState<string>("");
  const [newTitle, setNewTitle] = useState<string>("");
  const [newDescription, setNewDescription] = useState<string>("");
  const [creating, setCreating] = useState<boolean>(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const loadCases = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchCases(statusFilter || undefined, 100);
      setCases(data);
    } catch (err: any) {
      console.error("Failed to load investigation cases:", err);
      setError(err.message || "Failed to load investigation cases from cases.db");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, [statusFilter, refreshTrigger]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    const incId = parseInt(newIncidentId.trim(), 10);
    if (isNaN(incId) || incId <= 0) {
      setCreateError("Please provide a valid numeric Incident ID.");
      return;
    }
    if (!newTitle.trim()) {
      setCreateError("Case title is required.");
      return;
    }

    setCreating(true);
    setCreateError(null);
    try {
      const newCase = await createOrOpenCase(incId, newTitle.trim(), newDescription.trim() || undefined);
      setCreateModalOpen(false);
      setNewIncidentId("");
      setNewTitle("");
      setNewDescription("");
      await loadCases();
      onSelectCase(newCase.case_id, newCase.incident_id);
    } catch (err: any) {
      setCreateError(err.message || "Failed to create investigation case.");
    } finally {
      setCreating(false);
    }
  };

  // Filtered by client search query
  const filteredCases = cases.filter((c) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      c.title.toLowerCase().includes(q) ||
      (c.description && c.description.toLowerCase().includes(q)) ||
      c.case_id.toString().includes(q) ||
      c.owner.toLowerCase().includes(q) ||
      (c.scope?.target_hosts && c.scope.target_hosts.some((h) => h.toLowerCase().includes(q)))
    );
  });

  const totalCount = cases.length;
  const openCount = cases.filter((c) => c.status === "OPEN" || (c.status as string) === "CaseStatus.OPEN").length;
  const inProgressCount = cases.filter((c) => c.status === "ACTIVE" || c.status === "READY_FOR_REVIEW" || (c.status as string) === "CaseStatus.ACTIVE").length;
  const closedCount = cases.filter((c) => c.status === "CLOSED" || (c.status as string) === "CaseStatus.CLOSED").length;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      {/* KPI Header Bar */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
          gap: "12px",
        }}
      >
        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Total Cases (cases.db)
          </div>
          <div style={{ fontSize: "24px", fontWeight: 700, marginTop: "4px" }}>
            {loading ? "..." : totalCount.toLocaleString()}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Isolated analyst dossiers
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Open Cases
          </div>
          <div style={{ fontSize: "24px", fontWeight: 700, marginTop: "4px", color: "var(--badge-alert-text)" }}>
            {loading ? "..." : openCount}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Active investigations
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            In Progress / Review
          </div>
          <div style={{ fontSize: "24px", fontWeight: 700, marginTop: "4px", color: "var(--badge-warn-text)" }}>
            {loading ? "..." : inProgressCount}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Under forensic evaluation
          </div>
        </div>

        <div className="panel" style={{ padding: "12px 16px" }}>
          <div style={{ fontSize: "11px", color: "var(--text-muted)", textTransform: "uppercase", fontWeight: 600 }}>
            Closed Cases
          </div>
          <div style={{ fontSize: "24px", fontWeight: 700, marginTop: "4px", color: "var(--badge-success-text)" }}>
            {loading ? "..." : closedCount}
          </div>
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "2px" }}>
            Completed & audited
          </div>
        </div>
      </div>

      {/* Control Bar: Filters & Actions */}
      <div className="panel" style={{ padding: "12px 16px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "10px" }}>
          <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: "10px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <FilterIcon />
              <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                style={{
                  padding: "4px 8px",
                  fontSize: "11px",
                  border: "1px solid var(--border-strong)",
                  borderRadius: "2px",
                  background: "var(--bg-surface)",
                }}
              >
                <option value="">All Statuses</option>
                <option value="OPEN">Open</option>
                <option value="IN_PROGRESS">In Progress</option>
                <option value="CLOSED">Closed</option>
                <option value="ARCHIVED">Archived</option>
              </select>
            </div>

            <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <SearchIcon />
              <input
                type="text"
                placeholder="Search cases by title, host, owner..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  padding: "4px 8px",
                  fontSize: "11px",
                  width: "240px",
                  border: "1px solid var(--border-strong)",
                  borderRadius: "2px",
                }}
              />
              {searchQuery && (
                <button
                  className="btn btn-secondary btn-sm"
                  onClick={() => setSearchQuery("")}
                  style={{ padding: "2px 6px", fontSize: "10px" }}
                >
                  Clear
                </button>
              )}
            </div>

            <button
              className="btn btn-secondary btn-sm"
              onClick={loadCases}
              disabled={loading}
              title="Refresh investigation cases"
            >
              <RefreshIcon /> Refresh
            </button>
          </div>

          <button
            className="btn btn-primary"
            onClick={() => setCreateModalOpen(true)}
            style={{ padding: "5px 14px", fontSize: "11px" }}
          >
            <CaseIcon /> New Investigation Case
          </button>
        </div>
      </div>

      {/* Cases List */}
      <div className="panel">
        <div className="panel-body" style={{ padding: 0 }}>
          {loading && (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
              Loading investigation cases from cases.db...
            </div>
          )}

          {error && (
            <div style={{ padding: "24px", color: "var(--badge-alert-text)", textAlign: "center" }}>
              <div style={{ fontWeight: 600 }}>Error Loading Cases</div>
              <div style={{ fontSize: "12px", marginTop: "4px" }}>{error}</div>
              <button
                className="btn btn-secondary btn-sm"
                onClick={loadCases}
                style={{ marginTop: "12px" }}
              >
                Retry
              </button>
            </div>
          )}

          {!loading && !error && filteredCases.length === 0 && (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
              <CaseIcon className="" />
              <p style={{ marginTop: "8px", fontWeight: 500 }}>No investigation cases found.</p>
              <p style={{ fontSize: "11px", marginTop: "4px" }}>
                {searchQuery || statusFilter
                  ? "No cases match the active filter criteria."
                  : "Click 'New Investigation Case' to begin a structured forensic investigation."}
              </p>
            </div>
          )}

          {!loading && !error && filteredCases.length > 0 && (
            <div style={{ overflowX: "auto" }}>
              <table className="data-table" style={{ width: "100%" }}>
                <thead>
                  <tr>
                    <th>Case ID</th>
                    <th>Status</th>
                    <th>Investigation Title</th>
                    <th>Linked Incident</th>
                    <th>Target Scope</th>
                    <th>Owner</th>
                    <th>Last Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCases.map((c) => {
                    const st = typeof c.status === "string" ? c.status.replace("CaseStatus.", "") : "OPEN";
                    const isClosed = st === "CLOSED";
                    const isOpen = st === "OPEN";

                    return (
                      <tr
                        key={c.case_id}
                        style={{ cursor: "pointer" }}
                        onClick={() => onSelectCase(c.case_id, c.incident_id)}
                      >
                        <td style={{ fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: "11px" }}>
                          #{c.case_id}
                        </td>
                        <td>
                          <span
                            className={`badge ${
                              isOpen ? "badge-alert" : isClosed ? "badge-success" : "badge-warn"
                            }`}
                            style={{ fontSize: "10px" }}
                          >
                            {st}
                          </span>
                        </td>
                        <td>
                          <div style={{ fontWeight: 600, color: "var(--text-primary)" }}>{c.title}</div>
                          {c.description && (
                            <div
                              style={{
                                fontSize: "11px",
                                color: "var(--text-muted)",
                                maxWidth: "360px",
                                whiteSpace: "nowrap",
                                overflow: "hidden",
                                textOverflow: "ellipsis",
                              }}
                            >
                              {c.description}
                            </div>
                          )}
                        </td>
                        <td style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                          Incident #{c.incident_id}
                        </td>
                        <td style={{ fontSize: "11px" }}>
                          {c.scope?.target_hosts && c.scope.target_hosts.length > 0 ? (
                            <span style={{ fontFamily: "var(--font-mono)" }}>
                              {c.scope.target_hosts.length} host(s) ({c.scope.target_hosts.slice(0, 2).join(", ")}
                              {c.scope.target_hosts.length > 2 ? "..." : ""})
                            </span>
                          ) : (
                            <span style={{ color: "var(--text-muted)" }}>Fleet Scope</span>
                          )}
                        </td>
                        <td style={{ fontSize: "11px" }}>{c.owner || c.created_by || "SecAnalyst-1"}</td>
                        <td style={{ fontSize: "11px", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                          {c.updated_at ? new Date(c.updated_at).toLocaleString() : "—"}
                        </td>
                        <td>
                          <button
                            className="btn btn-secondary btn-sm"
                            style={{ padding: "3px 8px", fontSize: "10px" }}
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectCase(c.case_id, c.incident_id);
                            }}
                          >
                            Open Workspace &rarr;
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* New Investigation Case Modal */}
      {createModalOpen && (
        <div className="modal-overlay" onClick={() => setCreateModalOpen(false)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()} style={{ maxWidth: "480px" }}>
            <div className="modal-header">
              <span className="modal-title">Open New Investigation Case</span>
              <button className="btn" onClick={() => setCreateModalOpen(false)}>
                &times;
              </button>
            </div>
            <form onSubmit={handleCreateCase}>
              <div className="modal-body" style={{ display: "flex", flexDirection: "column", gap: "12px" }}>
                {createError && (
                  <div style={{ color: "var(--badge-alert-text)", fontSize: "12px", padding: "8px", background: "rgba(239,68,68,0.1)" }}>
                    {createError}
                  </div>
                )}
                <div>
                  <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "4px" }}>
                    Linked Incident ID <span style={{ color: "var(--badge-alert-text)" }}>*</span>
                  </label>
                  <input
                    type="number"
                    min="1"
                    placeholder="e.g. 1, 101, 967431"
                    value={newIncidentId}
                    onChange={(e) => setNewIncidentId(e.target.value)}
                    required
                    style={{ width: "100%", padding: "6px 8px", fontSize: "12px", border: "1px solid var(--border-strong)" }}
                  />
                  <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                    Associates the case with an incident in logintel.db for attack graph and timeline continuity.
                  </span>
                </div>

                <div>
                  <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "4px" }}>
                    Case Title <span style={{ color: "var(--badge-alert-text)" }}>*</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. Lateral Movement & SSH Brute Force Investigation"
                    value={newTitle}
                    onChange={(e) => setNewTitle(e.target.value)}
                    required
                    style={{ width: "100%", padding: "6px 8px", fontSize: "12px", border: "1px solid var(--border-strong)" }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: "11px", fontWeight: 600, display: "block", marginBottom: "4px" }}>
                    Initial Scope & Analyst Notes (Optional)
                  </label>
                  <textarea
                    rows={3}
                    placeholder="Enter preliminary hypotheses, target hosts, or scope bounds..."
                    value={newDescription}
                    onChange={(e) => setNewDescription(e.target.value)}
                    style={{ width: "100%", padding: "6px 8px", fontSize: "12px", border: "1px solid var(--border-strong)" }}
                  />
                </div>
              </div>

              <div className="modal-footer" style={{ display: "flex", justifyContent: "flex-end", gap: "8px", padding: "12px 16px" }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setCreateModalOpen(false)}
                  disabled={creating}
                >
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={creating}>
                  {creating ? "Creating..." : "Create Case"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
