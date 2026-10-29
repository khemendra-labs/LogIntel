import React, { useEffect, useState } from "react";
import { CaseIcon, MultiHostIcon, RefreshIcon } from "../components/Icons";
import { InvestigationMultiHostWorkbench } from "../features/InvestigationMultiHostWorkbench";
import { fetchCases } from "../lib/api";
import { InvestigationCase } from "../types/investigation";

interface MultiHostPageProps {
  initialCaseId?: number | null;
  refreshTrigger?: number;
}

export function MultiHostPage({ initialCaseId, refreshTrigger = 0 }: MultiHostPageProps) {
  const [cases, setCases] = useState<InvestigationCase[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(initialCaseId || null);
  const [loadingCases, setLoadingCases] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const loadCaseList = async () => {
    setLoadingCases(true);
    setError(null);
    try {
      const data = await fetchCases(undefined, 50);
      setCases(data);
      if (!selectedCaseId && data.length > 0) {
        setSelectedCaseId(data[0].case_id);
      }
    } catch (err: any) {
      console.error("Failed to load cases for multi-host investigation:", err);
      setError(err.message || "Failed to load case list");
    } finally {
      setLoadingCases(false);
    }
  };

  useEffect(() => {
    loadCaseList();
  }, [refreshTrigger]);

  useEffect(() => {
    if (initialCaseId) {
      setSelectedCaseId(initialCaseId);
    }
  }, [initialCaseId]);

  const activeCase = cases.find((c) => c.case_id === selectedCaseId);

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
      {/* Header & Case Selector Bar */}
      <div className="panel" style={{ padding: "12px 16px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", alignItems: "center", gap: "12px" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <MultiHostIcon />
            <div>
              <span style={{ fontWeight: 700, fontSize: "14px" }}>Multi-Host Investigation & Forensic Correlation</span>
              <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "2px" }}>
                Fleet host inventory, lateral movement hops, comparative timelines, and visibility gap auditing
              </div>
            </div>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
            <span style={{ fontSize: "11px", fontWeight: 600, color: "var(--text-secondary)" }}>
              Active Case Context:
            </span>
            <select
              value={selectedCaseId || ""}
              onChange={(e) => setSelectedCaseId(Number(e.target.value))}
              disabled={loadingCases || cases.length === 0}
              style={{
                padding: "4px 10px",
                fontSize: "11px",
                border: "1px solid var(--border-strong)",
                borderRadius: "2px",
                background: "var(--bg-surface)",
                maxWidth: "320px",
              }}
            >
              {cases.length === 0 && <option value="">No cases available in cases.db</option>}
              {cases.map((c) => (
                <option key={c.case_id} value={c.case_id}>
                  #{c.case_id} — {c.title.slice(0, 35)}
                </option>
              ))}
            </select>

            <button
              className="btn btn-secondary btn-sm"
              onClick={loadCaseList}
              disabled={loadingCases}
              title="Refresh case selector"
            >
              <RefreshIcon />
            </button>
          </div>
        </div>

        {activeCase && (
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "16px",
              marginTop: "10px",
              paddingTop: "10px",
              borderTop: "1px solid var(--border-subtle)",
              fontSize: "11px",
            }}
          >
            <div>
              <span style={{ color: "var(--text-muted)" }}>Status: </span>
              <strong style={{ color: "var(--text-primary)" }}>
                {typeof activeCase.status === "string" ? activeCase.status.replace("CaseStatus.", "") : "OPEN"}
              </strong>
            </div>
            <div>
              <span style={{ color: "var(--text-muted)" }}>Target Hosts: </span>
              <strong style={{ fontFamily: "var(--font-mono)" }}>
                {activeCase.scope?.target_hosts?.length ? activeCase.scope.target_hosts.join(", ") : "All Fleet Hosts"}
              </strong>
            </div>
            <div>
              <span style={{ color: "var(--text-muted)" }}>Owner: </span>
              <strong>{activeCase.owner || "SecAnalyst-1"}</strong>
            </div>
          </div>
        )}
      </div>

      {/* Main Multi-Host Workbench Area */}
      {selectedCaseId ? (
        <InvestigationMultiHostWorkbench caseId={selectedCaseId} />
      ) : (
        <div className="panel" style={{ padding: "40px", textAlign: "center", color: "var(--text-muted)" }}>
          {loadingCases ? (
            <div>Loading multi-host case context...</div>
          ) : (
            <div>
              <MultiHostIcon className="" />
              <p style={{ marginTop: "8px", fontWeight: 500 }}>No Investigation Case Selected</p>
              <p style={{ fontSize: "11px", marginTop: "4px" }}>
                Select an existing case above or create a new case in the Investigations tab to begin multi-host correlation.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
