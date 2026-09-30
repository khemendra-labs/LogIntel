import React, { useEffect, useState } from "react";
import { CloseIcon, EyeIcon, RefreshIcon, SearchIcon } from "../components/Icons";
import { RuleCategoryBadge, SeverityBadge } from "../components/StatusBadge";
import { fetchDetectionRuleDetail, fetchDetectionRules } from "../lib/api";
import { DetectionRuleDetailResponse, DetectionRuleSummary, RuleCategory } from "../types/detection";

export function RulesPage() {
  const [rules, setRules] = useState<DetectionRuleSummary[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [search, setSearch] = useState<string>("");

  // Selected rule for detail view / YAML inspection
  const [selectedRuleId, setSelectedRuleId] = useState<string | null>(null);
  const [ruleDetail, setRuleDetail] = useState<DetectionRuleDetailResponse | null>(null);
  const [detailLoading, setDetailLoading] = useState<boolean>(false);
  const [copiedYaml, setCopiedYaml] = useState<boolean>(false);

  const loadRules = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await fetchDetectionRules(categoryFilter || undefined);
      setRules(data.items);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.message || "Failed to load detection rules");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadRules();
  }, [categoryFilter]);

  const loadRuleDetail = async (ruleId: string) => {
    setSelectedRuleId(ruleId);
    setDetailLoading(true);
    setCopiedYaml(false);
    try {
      const data = await fetchDetectionRuleDetail(ruleId);
      setRuleDetail(data);
    } catch (err: any) {
      console.error("Failed to load rule detail:", err);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleCopyYaml = () => {
    if (ruleDetail?.yaml_definition) {
      navigator.clipboard.writeText(ruleDetail.yaml_definition);
      setCopiedYaml(true);
      setTimeout(() => setCopiedYaml(false), 2000);
    }
  };

  const filteredRules = rules.filter((r) => {
    if (!search) return true;
    const term = search.toLowerCase();
    return (
      r.id.toLowerCase().includes(term) ||
      r.name.toLowerCase().includes(term) ||
      r.description.toLowerCase().includes(term)
    );
  });

  return (
    <div>
      {/* Filtering Toolbar */}
      <div className="panel" style={{ marginBottom: "14px" }}>
        <div className="panel-body" style={{ padding: "10px 14px" }}>
          <div className="toolbar-row" style={{ marginBottom: 0, display: "flex", flexWrap: "wrap", gap: "10px", alignItems: "center" }}>
            {/* Category Filter Chips */}
            <div style={{ display: "flex", gap: "4px" }}>
              <button
                className={`btn btn-secondary ${categoryFilter === "" ? "active" : ""}`}
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={() => setCategoryFilter("")}
              >
                All Categories
              </button>
              {(["AUTH", "PRIVILEGE", "PROCESS", "ACCOUNT", "NETWORK"] as RuleCategory[]).map((cat) => (
                <button
                  key={cat}
                  className={`btn btn-secondary ${categoryFilter === cat ? "active" : ""}`}
                  style={{ padding: "4px 8px", fontSize: "11px" }}
                  onClick={() => setCategoryFilter(cat)}
                >
                  {cat}
                </button>
              ))}
            </div>

            <div style={{ height: "16px", width: "1px", background: "var(--border-subtle)", margin: "0 4px" }} />

            {/* Search */}
            <div style={{ display: "flex", alignItems: "center", position: "relative" }}>
              <input
                type="text"
                className="filter-input"
                placeholder="Search rule title or ID..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ fontSize: "11px", padding: "4px 8px", width: "220px" }}
              />
            </div>

            <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                Total: <strong>{filteredRules.length}</strong> rule{filteredRules.length !== 1 ? "s" : ""}
              </span>
              <button
                className="btn btn-secondary"
                style={{ padding: "4px 8px", fontSize: "11px" }}
                onClick={loadRules}
                title="Refresh rules catalog"
              >
                <RefreshIcon />
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Rules Table */}
      <div className="panel">
        <div className="panel-body" style={{ padding: 0 }}>
          {loading ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
              Loading detection rules catalog...
            </div>
          ) : filteredRules.length === 0 ? (
            <div style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)", fontSize: "12px" }}>
              No detection rules match criteria.
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: "90px" }}>Category</th>
                  <th style={{ width: "80px" }}>Severity</th>
                  <th style={{ width: "100px" }}>Type</th>
                  <th>Rule Name & Scope</th>
                  <th>Rule Identifier</th>
                  <th style={{ width: "80px", textAlign: "center" }}>Cooldown</th>
                  <th style={{ width: "80px", textAlign: "center" }}>Status</th>
                  <th style={{ width: "80px", textAlign: "center" }}>YAML</th>
                </tr>
              </thead>
              <tbody>
                {filteredRules.map((rule) => (
                  <tr
                    key={rule.id}
                    onClick={() => loadRuleDetail(rule.id)}
                    style={{ cursor: "pointer" }}
                  >
                    <td>
                      <RuleCategoryBadge category={rule.category} />
                    </td>
                    <td>
                      <SeverityBadge severity={rule.severity} />
                    </td>
                    <td>
                      <span className={`badge ${rule.rule_type === "THRESHOLD" ? "badge-notice" : "badge-neutral"}`} style={{ fontSize: "10px" }}>
                        {rule.rule_type}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontWeight: 600, color: "var(--text-primary)", fontSize: "12px" }}>
                        {rule.name}
                      </div>
                      <div style={{ color: "var(--text-muted)", fontSize: "11px", marginTop: "2px" }}>
                        {rule.description}
                      </div>
                    </td>
                    <td className="mono-cell" style={{ fontSize: "11px", fontWeight: 600 }}>
                      {rule.id}
                    </td>
                    <td style={{ textAlign: "center" }}>
                      <span className="mono-cell" style={{ fontSize: "11px" }}>
                        {rule.cooldown_seconds}s
                      </span>
                    </td>
                    <td style={{ textAlign: "center" }}>
                      <span className={`badge ${rule.enabled ? "badge-success" : "badge-neutral"}`} style={{ fontSize: "10px" }}>
                        {rule.enabled ? "ACTIVE" : "DISABLED"}
                      </span>
                    </td>
                    <td style={{ textAlign: "center" }}>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: "3px 8px", fontSize: "11px" }}
                        onClick={(e) => {
                          e.stopPropagation();
                          loadRuleDetail(rule.id);
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

      {/* Rule Detail & YAML Modal */}
      {selectedRuleId && (
        <div className="modal-backdrop" onClick={() => setSelectedRuleId(null)}>
          <div
            className="modal-dialog"
            onClick={(e) => e.stopPropagation()}
            style={{ maxWidth: "800px", maxHeight: "88vh", display: "flex", flexDirection: "column" }}
          >
            <div className="modal-header">
              <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontWeight: 700, fontSize: "13px", color: "var(--text-muted)" }}>
                  {selectedRuleId}
                </span>
                {ruleDetail && (
                  <>
                    <RuleCategoryBadge category={ruleDetail.rule.category} />
                    <SeverityBadge severity={ruleDetail.rule.severity} />
                  </>
                )}
              </div>
              <button className="icon-button" onClick={() => setSelectedRuleId(null)}>
                <CloseIcon />
              </button>
            </div>

            <div className="modal-body" style={{ overflowY: "auto", padding: "18px 24px" }}>
              {detailLoading || !ruleDetail ? (
                <div style={{ padding: "32px", textAlign: "center", color: "var(--text-muted)" }}>
                  Loading rule definition...
                </div>
              ) : (
                <div>
                  <div style={{ marginBottom: "16px" }}>
                    <h2 style={{ fontSize: "16px", fontWeight: 600, color: "var(--text-primary)", marginBottom: "4px" }}>
                      {ruleDetail.rule.name}
                    </h2>
                    <p style={{ color: "var(--text-secondary)", fontSize: "12px", lineHeight: 1.5 }}>
                      {ruleDetail.rule.description}
                    </p>
                  </div>

                  {/* Summary Properties */}
                  <div className="panel" style={{ marginBottom: "16px" }}>
                    <div className="panel-header" style={{ padding: "8px 12px" }}>
                      <span className="panel-title" style={{ fontSize: "12px" }}>Detection Configuration</span>
                    </div>
                    <div className="panel-body" style={{ padding: "12px" }}>
                      <div className="property-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", rowGap: "10px" }}>
                        <div className="property-item">
                          <span className="property-label">Rule Type</span>
                          <span className="property-value mono-cell">{ruleDetail.rule.rule_type}</span>
                        </div>
                        <div className="property-item">
                          <span className="property-label">Cooldown Window</span>
                          <span className="property-value mono-cell">{ruleDetail.rule.cooldown_seconds} seconds</span>
                        </div>
                        <div className="property-item">
                          <span className="property-label">State</span>
                          <span className="property-value mono-cell">
                            {ruleDetail.rule.enabled ? "ENABLED" : "DISABLED"}
                          </span>
                        </div>

                        {ruleDetail.rule.threshold && (
                          <>
                            <div className="property-item">
                              <span className="property-label">Threshold Count</span>
                              <span className="property-value mono-cell" style={{ fontWeight: 700 }}>
                                {ruleDetail.rule.threshold.count} events
                              </span>
                            </div>
                            <div className="property-item">
                              <span className="property-label">Sliding Window</span>
                              <span className="property-value mono-cell">
                                {ruleDetail.rule.threshold.window_seconds} seconds
                              </span>
                            </div>
                            <div className="property-item">
                              <span className="property-label">Group By Key</span>
                              <span className="property-value mono-cell">
                                {ruleDetail.rule.group_by?.join(", ") || "None"}
                              </span>
                            </div>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* YAML Source */}
                  <div className="panel">
                    <div className="panel-header" style={{ padding: "8px 12px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <span className="panel-title" style={{ fontSize: "12px" }}>Declarative Rule Specification (YAML)</span>
                      <button
                        className="btn btn-secondary"
                        style={{ padding: "3px 8px", fontSize: "11px" }}
                        onClick={handleCopyYaml}
                      >
                        {copiedYaml ? "Copied!" : "Copy YAML"}
                      </button>
                    </div>
                    <div className="panel-body" style={{ padding: "10px" }}>
                      <pre style={{
                        background: "var(--bg-surface-subtle)",
                        border: "1px solid var(--border-subtle)",
                        padding: "12px",
                        borderRadius: "3px",
                        fontSize: "11px",
                        fontFamily: "var(--font-mono)",
                        lineHeight: 1.4,
                        overflowX: "auto",
                        whiteSpace: "pre-wrap",
                      }}>
                        {ruleDetail.yaml_definition}
                      </pre>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
