import React, { useState } from "react";
import { SearchIcon, RefreshIcon, AlertIcon, CheckIcon } from "../components/Icons";
import {
  askInvestigationQuestion,
  getInvestigationEvidenceBundle,
  previewInvestigationQuery,
} from "../lib/api";
import {
  AIInvestigationResponse,
  InvestigationEvidenceBundle,
  QueryPreviewResponse,
  QueryProposal,
} from "../types/investigation";

interface InvestigationIntelligencePanelProps {
  incidentId: number;
  onSelectEventId?: (eventId: string) => void;
  onSelectAlertId?: (alertId: number) => void;
  onSelectEntityKey?: (entityKey: string) => void;
}

export function InvestigationIntelligencePanel({
  incidentId,
  onSelectEventId,
  onSelectAlertId,
  onSelectEntityKey,
}: InvestigationIntelligencePanelProps) {
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [response, setResponse] = useState<AIInvestigationResponse | null>(null);
  const [bundle, setBundle] = useState<InvestigationEvidenceBundle | null>(null);
  const [bundleLoading, setBundleLoading] = useState(false);

  // Query preview state
  const [previewProposalId, setPreviewProposalId] = useState<string | null>(null);
  const [previewResult, setPreviewResult] = useState<QueryPreviewResponse | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  const handleAsk = async (customQ?: string) => {
    const q = customQ || question;
    if (!q.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await askInvestigationQuestion(incidentId, q.trim());
      setResponse(res);
      // Also fetch deterministic evidence bundle
      fetchBundle();
    } catch (err: any) {
      setError(err.message || "Failed to obtain AI analysis");
    } finally {
      setLoading(false);
    }
  };

  const fetchBundle = async () => {
    setBundleLoading(true);
    try {
      const b = await getInvestigationEvidenceBundle(incidentId);
      setBundle(b);
    } catch (err) {
      // Non-fatal
    } finally {
      setBundleLoading(false);
    }
  };

  const handlePreviewQuery = async (prop: QueryProposal) => {
    setPreviewProposalId(prop.proposal_id);
    setPreviewLoading(true);
    setPreviewResult(null);
    try {
      const res = await previewInvestigationQuery(incidentId, prop);
      setPreviewResult(res);
    } catch (err: any) {
      setError(`Failed to preview query: ${err.message}`);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleCitationClick = (tag: string) => {
    const match = tag.match(/^\[([a-zA-Z0-9_-]+):([^\]\s]+)\]$/);
    if (!match) return;
    const type = match[1].toLowerCase();
    const id = match[2];
    if (type === "event" && onSelectEventId) {
      onSelectEventId(id);
    } else if (type === "alert" && onSelectAlertId) {
      const num = parseInt(id, 10);
      if (!isNaN(num)) onSelectAlertId(num);
    } else if (type === "entity" && onSelectEntityKey) {
      onSelectEntityKey(id);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "16px", padding: "16px 0" }}>
      {/* Editorial Boundary Notice */}
      <div
        style={{
          padding: "10px 14px",
          background: "var(--bg-subtle, #f5f4ef)",
          borderLeft: "3px solid var(--accent-slate, #4a5568)",
          borderRadius: "3px",
          fontSize: "12px",
          color: "var(--text-secondary, #4a5568)",
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div>
          <strong style={{ color: "var(--text-primary, #1a202c)", letterSpacing: "0.5px" }}>
            EVIDENCE-GROUNDED LOCAL AI ASSISTANT (M5.3)
          </strong>
          <span style={{ marginLeft: "8px" }}>
            Interprets authoritative evidence. Inferences and hypotheses are non-authoritative.
          </span>
        </div>
        <div style={{ fontSize: "11px", fontFamily: "var(--font-mono, monospace)", color: "#718096" }}>
          LOCAL MODEL • ZERO CLOUD
        </div>
      </div>

      {/* Preset Investigation Questions */}
      <div style={{ display: "flex", gap: "8px", flexWrap: "wrap" }}>
        <button
          className="btn btn-secondary"
          style={{ fontSize: "11px", padding: "4px 10px" }}
          onClick={() => {
            setQuestion("Summarize what happened in this incident based on observed evidence.");
            handleAsk("Summarize what happened in this incident based on observed evidence.");
          }}
          disabled={loading}
        >
          📋 Summarize Incident
        </button>
        <button
          className="btn btn-secondary"
          style={{ fontSize: "11px", padding: "4px 10px" }}
          onClick={() => {
            setQuestion("Reconstruct the chronological timeline of observed actions.");
            handleAsk("Reconstruct the chronological timeline of observed actions.");
          }}
          disabled={loading}
        >
          ⏱️ Reconstruct Timeline
        </button>
        <button
          className="btn btn-secondary"
          style={{ fontSize: "11px", padding: "4px 10px" }}
          onClick={() => {
            setQuestion("What working hypotheses explain this incident, and what evidence supports or contradicts them?");
            handleAsk("What working hypotheses explain this incident, and what evidence supports or contradicts them?");
          }}
          disabled={loading}
        >
          💡 Working Hypotheses
        </button>
        <button
          className="btn btn-secondary"
          style={{ fontSize: "11px", padding: "4px 10px" }}
          onClick={() => {
            setQuestion("What telemetry gaps or missing evidence limit our investigation?");
            handleAsk("What telemetry gaps or missing evidence limit our investigation?");
          }}
          disabled={loading}
        >
          🔍 Audit Visibility Gaps
        </button>
      </div>

      {/* Analyst Question Input */}
      <div style={{ display: "flex", gap: "8px" }}>
        <input
          type="text"
          className="input-field"
          style={{
            flex: 1,
            padding: "8px 12px",
            fontSize: "13px",
            fontFamily: "inherit",
            border: "1px solid var(--border-color, #e2e8f0)",
            borderRadius: "4px",
          }}
          placeholder="Ask an investigation question (e.g. Which entities are involved? What changed before and after?)..."
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && !loading) {
              handleAsk();
            }
          }}
          disabled={loading}
        />
        <button
          className="btn btn-primary"
          style={{ padding: "8px 16px", fontSize: "12px", display: "flex", alignItems: "center", gap: "6px" }}
          onClick={() => handleAsk()}
          disabled={loading || !question.trim()}
        >
          {loading ? (
            <>
              <RefreshIcon className="spin" /> Analyzing...
            </>
          ) : (
            <>
              <SearchIcon /> Investigate
            </>
          )}
        </button>
      </div>

      {error && (
        <div
          style={{
            padding: "10px 14px",
            background: "#fff5f5",
            border: "1px solid #feb2b2",
            color: "#c53030",
            borderRadius: "4px",
            fontSize: "12px",
          }}
        >
          <strong>Error:</strong> {error}
        </div>
      )}

      {/* AI Analysis Result */}
      {response && (
        <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
          {/* Answer Overview Card */}
          <div
            style={{
              padding: "16px",
              background: "var(--card-bg, #ffffff)",
              border: "1px solid var(--border-color, #e2e8f0)",
              borderRadius: "4px",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span
                  style={{
                    fontSize: "10px",
                    fontWeight: 700,
                    textTransform: "uppercase",
                    letterSpacing: "0.5px",
                    padding: "2px 6px",
                    borderRadius: "3px",
                    background:
                      response.epistemic_status === "OBSERVED"
                        ? "#e6fffa"
                        : response.epistemic_status === "INFERRED"
                        ? "#feebc8"
                        : "#edf2f7",
                    color:
                      response.epistemic_status === "OBSERVED"
                        ? "#234e52"
                        : response.epistemic_status === "INFERRED"
                        ? "#744210"
                        : "#4a5568",
                  }}
                >
                  Status: {response.epistemic_status}
                </span>
                <span
                  style={{
                    fontSize: "10px",
                    fontWeight: 600,
                    padding: "2px 6px",
                    borderRadius: "3px",
                    background: "#edf2f7",
                    color: "#4a5568",
                  }}
                >
                  Intent: {response.intent}
                </span>
              </div>
              <div style={{ fontSize: "11px", color: "#a0aec0", fontFamily: "var(--font-mono, monospace)" }}>
                {response.model_identifier || "Local AI"} • {response.metadata?.latency_ms ? `${response.metadata.latency_ms}ms` : ""}
              </div>
            </div>

            <div
              style={{
                fontSize: "13px",
                lineHeight: "1.6",
                color: "var(--text-primary, #2d3748)",
                whiteSpace: "pre-wrap",
              }}
            >
              {response.answer_markdown}
            </div>
          </div>

          {/* Validated Claims Table */}
          {response.claims && response.claims.length > 0 && (
            <div
              style={{
                padding: "16px",
                background: "var(--card-bg, #ffffff)",
                border: "1px solid var(--border-color, #e2e8f0)",
                borderRadius: "4px",
              }}
            >
              <h4 style={{ margin: "0 0 12px 0", fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Validated Evidence Claims ({response.claims.length})
              </h4>
              <table className="data-table" style={{ width: "100%", fontSize: "12px" }}>
                <thead>
                  <tr>
                    <th style={{ width: "90px" }}>Epistemic</th>
                    <th>Claim Statement</th>
                    <th style={{ width: "180px" }}>Authoritative Citations</th>
                    <th>Analytical Rationale</th>
                  </tr>
                </thead>
                <tbody>
                  {response.claims.map((claim, idx) => (
                    <tr key={idx}>
                      <td>
                        <span
                          style={{
                            fontSize: "10px",
                            fontWeight: 700,
                            padding: "2px 6px",
                            borderRadius: "3px",
                            background:
                              claim.status === "OBSERVED"
                                ? "#e6fffa"
                                : claim.status === "INFERRED"
                                ? "#feebc8"
                                : "#edf2f7",
                            color:
                              claim.status === "OBSERVED"
                                ? "#234e52"
                                : claim.status === "INFERRED"
                                ? "#744210"
                                : "#4a5568",
                          }}
                        >
                          {claim.status}
                        </span>
                      </td>
                      <td>{claim.claim_text}</td>
                      <td>
                        <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
                          {claim.evidence_refs?.map((ref, rIdx) => (
                            <button
                              key={rIdx}
                              onClick={() => handleCitationClick(ref.citation_tag)}
                              style={{
                                border: "1px solid #cbd5e0",
                                background: "#f7fafc",
                                borderRadius: "3px",
                                fontSize: "10px",
                                fontFamily: "var(--font-mono, monospace)",
                                padding: "2px 5px",
                                cursor: "pointer",
                              }}
                              title={`Inspect ${ref.evidence_type} ${ref.evidence_id}`}
                            >
                              {ref.citation_tag}
                            </button>
                          ))}
                        </div>
                      </td>
                      <td style={{ color: "#718096", fontSize: "11px" }}>{claim.rationale || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Hypotheses Card */}
          {response.hypotheses && response.hypotheses.length > 0 && (
            <div
              style={{
                padding: "16px",
                background: "var(--card-bg, #ffffff)",
                border: "1px solid var(--border-color, #e2e8f0)",
                borderRadius: "4px",
              }}
            >
              <h4 style={{ margin: "0 0 12px 0", fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Working Hypotheses ({response.hypotheses.length})
              </h4>
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {response.hypotheses.map((hyp, hIdx) => (
                  <div
                    key={hIdx}
                    style={{
                      padding: "12px",
                      background: "#fafafa",
                      border: "1px solid #edf2f7",
                      borderRadius: "4px",
                      fontSize: "12px",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
                      <strong style={{ color: "#2d3748" }}>{hyp.statement}</strong>
                      <span
                        style={{
                          fontSize: "10px",
                          fontWeight: 700,
                          padding: "1px 6px",
                          borderRadius: "3px",
                          background: hyp.confidence === "HIGH" ? "#c6f6d5" : hyp.confidence === "MEDIUM" ? "#feebc8" : "#fed7d7",
                          color: hyp.confidence === "HIGH" ? "#22543d" : hyp.confidence === "MEDIUM" ? "#744210" : "#742a2a",
                        }}
                      >
                        Confidence: {hyp.confidence}
                      </span>
                    </div>
                    {hyp.rationale && (
                      <div style={{ color: "#4a5568", marginBottom: "6px", fontSize: "11px" }}>
                        <em>Rationale:</em> {hyp.rationale}
                      </div>
                    )}
                    <div style={{ display: "flex", gap: "16px", fontSize: "11px" }}>
                      {hyp.supporting_evidence?.length > 0 && (
                        <div>
                          <span style={{ color: "#2f855a", fontWeight: 600 }}>Supporting: </span>
                          {hyp.supporting_evidence.map((s, idx) => (
                            <span key={idx} style={{ fontFamily: "monospace", marginRight: "4px" }}>
                              {s.citation_tag}
                            </span>
                          ))}
                        </div>
                      )}
                      {hyp.contradicting_evidence?.length > 0 && (
                        <div>
                          <span style={{ color: "#c53030", fontWeight: 600 }}>Contradicting: </span>
                          {hyp.contradicting_evidence.map((c, idx) => (
                            <span key={idx} style={{ fontFamily: "monospace", marginRight: "4px" }}>
                              {c.citation_tag}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Visibility Gaps & Evidence Conflicts */}
          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
            {/* Gaps */}
            <div
              style={{
                padding: "14px",
                background: "var(--card-bg, #ffffff)",
                border: "1px solid var(--border-color, #e2e8f0)",
                borderRadius: "4px",
              }}
            >
              <h5 style={{ margin: "0 0 10px 0", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Identified Telemetry Gaps ({response.evidence_gaps?.length || 0})
              </h5>
              {response.evidence_gaps && response.evidence_gaps.length > 0 ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  {response.evidence_gaps.map((gap, gIdx) => (
                    <div key={gIdx} style={{ fontSize: "11px", borderLeft: "2px solid #ed8936", paddingLeft: "8px" }}>
                      <strong>{gap.category}:</strong> {gap.description}
                      <div style={{ color: "#718096", fontSize: "10px", marginTop: "2px" }}>
                        Impact: {gap.impact}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: "11px", color: "#a0aec0" }}>No visibility gaps detected.</div>
              )}
            </div>

            {/* Conflicts */}
            <div
              style={{
                padding: "14px",
                background: "var(--card-bg, #ffffff)",
                border: "1px solid var(--border-color, #e2e8f0)",
                borderRadius: "4px",
              }}
            >
              <h5 style={{ margin: "0 0 10px 0", fontSize: "11px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                Detected Evidence Conflicts ({response.conflicts?.length || 0})
              </h5>
              {response.conflicts && response.conflicts.length > 0 ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
                  {response.conflicts.map((conf, cIdx) => (
                    <div key={cIdx} style={{ fontSize: "11px", borderLeft: "2px solid #e53e3e", paddingLeft: "8px" }}>
                      <strong>{conf.conflict_type}:</strong> {conf.explanation}
                      <div style={{ color: "#718096", fontSize: "10px", marginTop: "2px" }}>
                        {conf.evidence_tag_a} vs {conf.evidence_tag_b}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: "11px", color: "#a0aec0" }}>No conflicting evidence detected.</div>
              )}
            </div>
          </div>

          {/* Suggested Next Query Proposals */}
          {response.suggested_query_proposals && response.suggested_query_proposals.length > 0 && (
            <div
              style={{
                padding: "16px",
                background: "var(--card-bg, #ffffff)",
                border: "1px solid var(--border-color, #e2e8f0)",
                borderRadius: "4px",
              }}
            >
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
                <h4 style={{ margin: 0, fontSize: "12px", textTransform: "uppercase", letterSpacing: "0.5px" }}>
                  Suggested Investigation Queries ({response.suggested_query_proposals.length})
                </h4>
                <span style={{ fontSize: "11px", color: "#718096" }}>Preview-Only • Non-Autonomous</span>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {response.suggested_query_proposals.map((prop, pIdx) => (
                  <div
                    key={pIdx}
                    style={{
                      padding: "12px",
                      background: "#f7fafc",
                      border: "1px solid #e2e8f0",
                      borderRadius: "4px",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 600, fontSize: "12px", color: "#2d3748" }}>{prop.intent}</div>
                      <div style={{ fontSize: "11px", color: "#718096", marginTop: "2px" }}>
                        Target: {prop.target_entity || "Any"} • Events: {prop.event_types?.join(", ") || "All"} • Limit: {prop.limit}
                      </div>
                      {prop.rationale && (
                        <div style={{ fontSize: "11px", color: "#4a5568", marginTop: "2px" }}>
                          <em>Rationale:</em> {prop.rationale}
                        </div>
                      )}
                    </div>
                    <button
                      className="btn btn-secondary"
                      style={{ fontSize: "11px", padding: "4px 10px", whiteSpace: "nowrap" }}
                      onClick={() => handlePreviewQuery(prop)}
                      disabled={previewLoading && previewProposalId === prop.proposal_id}
                    >
                      {previewLoading && previewProposalId === prop.proposal_id ? (
                        <>
                          <RefreshIcon className="spin" /> Previewing...
                        </>
                      ) : (
                        "Preview Query"
                      )}
                    </button>
                  </div>
                ))}
              </div>

              {/* Query Preview Results */}
              {previewResult && (
                <div
                  style={{
                    marginTop: "16px",
                    padding: "12px",
                    background: "#edf2f7",
                    borderRadius: "4px",
                    fontSize: "12px",
                  }}
                >
                  <div style={{ fontWeight: 600, marginBottom: "8px" }}>
                    Query Preview Results: {previewResult.matched_count} matching events (Read-Only Preview)
                  </div>
                  {previewResult.events.length > 0 ? (
                    <table className="data-table" style={{ width: "100%", fontSize: "11px" }}>
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Source</th>
                          <th>Action</th>
                          <th>Host</th>
                          <th>User</th>
                          <th>Summary</th>
                        </tr>
                      </thead>
                      <tbody>
                        {previewResult.events.slice(0, 10).map((ev, idx) => (
                          <tr key={idx}>
                            <td style={{ fontFamily: "monospace" }}>{ev.timestamp}</td>
                            <td>{ev.source}</td>
                            <td>{ev.action}</td>
                            <td>{ev.host}</td>
                            <td>{ev.user}</td>
                            <td>{ev.summary}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div style={{ color: "#718096" }}>No matching events found for this filter combination.</div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Evidence Coverage Metadata */}
          {response.evidence_coverage && (
            <div
              style={{
                padding: "10px 14px",
                background: "var(--bg-subtle, #f5f4ef)",
                borderRadius: "4px",
                fontSize: "11px",
                color: "#718096",
                display: "flex",
                justifyContent: "space-between",
              }}
            >
              <div>
                Selected Evidence Items: <strong>{response.evidence_coverage.selected_count}</strong> • Omitted:{" "}
                <strong>{response.evidence_coverage.omitted_count}</strong>
              </div>
              <div>
                Available Types: {response.evidence_coverage.available_evidence_types.join(", ")}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
