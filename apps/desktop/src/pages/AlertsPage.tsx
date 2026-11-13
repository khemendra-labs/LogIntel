import React, { useEffect, useRef, useState } from "react";
import { FilterIcon, RefreshIcon, SearchIcon } from "../components/Icons";
import { AlertStatusBadge, SeverityBadge } from "../components/StatusBadge";
import {
  configureTelegramNotification,
  detectTelegramChatId,
  fetchAlerts,
  fetchNotificationStatus,
  NotificationStatus,
  testTelegramNotification,
} from "../lib/api";
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
  const reqIdRef = useRef(0);

  // Telegram Alert Modal State
  const [telegramModalOpen, setTelegramModalOpen] = useState<boolean>(false);
  const [telegramStatus, setTelegramStatus] = useState<NotificationStatus | null>(null);
  const [botToken, setBotToken] = useState<string>("");
  const [chatId, setChatId] = useState<string>("");
  const [tgLoading, setTgLoading] = useState<boolean>(false);
  const [tgMessage, setTgMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

  const loadAlerts = async () => {
    const currentReqId = ++reqIdRef.current;
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
      if (currentReqId !== reqIdRef.current) return;
      setAlerts(data.items);
      setTotal(data.total);
    } catch (err: any) {
      if (currentReqId === reqIdRef.current) {
        setError(err.message || "Failed to load alerts");
      }
    } finally {
      if (currentReqId === reqIdRef.current) {
        setLoading(false);
      }
    }
  };

  useEffect(() => {
    loadAlerts();
  }, [page, statusFilter, severityFilter, hostFilter, ruleIdFilter, refreshTrigger]);

  const openTelegramModal = async () => {
    setTelegramModalOpen(true);
    setTgMessage(null);
    try {
      const st = await fetchNotificationStatus();
      setTelegramStatus(st);
      if (st.telegram_chat_id_masked && !chatId) {
        setChatId(st.telegram_chat_id_masked);
      }
    } catch (e: any) {
      console.warn("Could not load notification status:", e);
    }
  };

  const handleSaveTelegram = async () => {
    if (!botToken.trim() || !chatId.trim()) {
      setTgMessage({ type: "error", text: "Please provide both Bot Token and Chat ID." });
      return;
    }
    setTgLoading(true);
    setTgMessage(null);
    try {
      const res = await configureTelegramNotification(botToken.trim(), chatId.trim(), true);
      setTgMessage({ type: "success", text: res.message });
      const updated = await fetchNotificationStatus();
      setTelegramStatus(updated);
    } catch (err: any) {
      setTgMessage({ type: "error", text: err.message || "Failed to configure Telegram" });
    } finally {
      setTgLoading(false);
    }
  };

  const handleTestTelegram = async () => {
    setTgLoading(true);
    setTgMessage(null);
    try {
      if (botToken.trim() && chatId.trim()) {
        await configureTelegramNotification(botToken.trim(), chatId.trim(), true);
      }
      const res = await testTelegramNotification();
      setTgMessage({ type: "success", text: res.message || "Test alert delivered to Telegram successfully!" });
    } catch (err: any) {
      setTgMessage({ type: "error", text: err.message || "Test alert failed to deliver. Check token and chat ID." });
    } finally {
      setTgLoading(false);
    }
  };

  const handleDetectChatId = async () => {
    if (!botToken.trim()) {
      setTgMessage({ type: "error", text: "Please enter your Telegram Bot API Token first to detect your Chat ID." });
      return;
    }
    setTgLoading(true);
    setTgMessage(null);
    try {
      const res = await detectTelegramChatId(botToken.trim());
      if (res.found && res.chat_id) {
        setChatId(res.chat_id);
        setTgMessage({ type: "success", text: res.message });
      } else {
        setTgMessage({ type: "error", text: res.message });
      }
    } catch (err: any) {
      setTgMessage({ type: "error", text: err.message || "Failed to auto-detect Chat ID." });
    } finally {
      setTgLoading(false);
    }
  };

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
              <option value="WARNING">Warning</option>
              <option value="NOTICE">Notice</option>
              <option value="INFORMATIONAL">Informational</option>
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
              <button
                className="btn btn-secondary"
                style={{
                  padding: "4px 10px",
                  fontSize: "11px",
                  display: "flex",
                  alignItems: "center",
                  gap: "6px",
                  borderColor: telegramStatus?.telegram_configured ? "var(--accent-color, #2563eb)" : undefined,
                }}
                onClick={openTelegramModal}
                title="Configure Telegram bot notifications for High and Critical security alerts"
              >
                <span>🤖</span>
                <span>Telegram Bot Alerts</span>
                {telegramStatus?.telegram_configured && (
                  <span style={{ fontSize: "9px", background: "var(--badge-success-bg, #ecfdf5)", color: "var(--badge-success-text, #059669)", padding: "1px 5px", borderRadius: "10px", fontWeight: 700 }}>
                    ACTIVE
                  </span>
                )}
              </button>
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
      {/* Telegram Configuration Modal */}
      {telegramModalOpen && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: "rgba(0, 0, 0, 0.5)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
          onClick={() => setTelegramModalOpen(false)}
        >
          <div
            className="panel"
            style={{
              width: "520px",
              maxWidth: "92vw",
              background: "var(--bg-surface, #ffffff)",
              border: "1px solid var(--border-subtle, #e2e8f0)",
              borderRadius: "8px",
              boxShadow: "0 10px 25px rgba(0,0,0,0.2)",
              overflow: "hidden",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div
              style={{
                padding: "14px 18px",
                borderBottom: "1px solid var(--border-subtle)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                background: "var(--bg-secondary, #f8fafc)",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <span style={{ fontSize: "18px" }}>🤖</span>
                <strong style={{ fontSize: "14px", color: "var(--text-primary)" }}>
                  Telegram Bot Security Alert Notifications
                </strong>
              </div>
              <button
                className="btn btn-secondary"
                style={{ padding: "2px 8px", fontSize: "12px", border: "none" }}
                onClick={() => setTelegramModalOpen(false)}
              >
                ✕
              </button>
            </div>

            <div style={{ padding: "18px", display: "flex", flexDirection: "column", gap: "14px" }}>
              <div
                style={{
                  background: "rgba(37, 99, 235, 0.08)",
                  border: "1px solid rgba(37, 99, 235, 0.2)",
                  borderRadius: "6px",
                  padding: "10px 12px",
                  fontSize: "12px",
                  color: "var(--text-secondary)",
                  lineHeight: "1.5",
                }}
              >
                <strong>⚡ Analyst Real-Time Dispatch:</strong> When running in the background, Prahari will immediately dispatch each and every event detail to your personal Telegram Bot whenever a <strong>HIGH</strong> or <strong>CRITICAL</strong> security severity occurs. Lower severities are strictly filtered out.
              </div>

              {telegramStatus?.telegram_configured && (
                <div style={{ fontSize: "11px", color: "var(--badge-success-text, #059669)", background: "var(--badge-success-bg, #ecfdf5)", padding: "6px 10px", borderRadius: "4px" }}>
                  ✓ Telegram bot is actively configured (Target Chat ID: <code>{telegramStatus.telegram_chat_id_masked}</code>).
                </div>
              )}

              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <label style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-primary)" }}>
                  Telegram Bot API Token:
                </label>
                <input
                  type="password"
                  className="filter-input"
                  placeholder="e.g. 123456789:ABCdefGHIjklMNOpqrsTUVwxyz"
                  value={botToken}
                  onChange={(e) => setBotToken(e.target.value)}
                  style={{ width: "100%", padding: "6px 10px", fontSize: "12px" }}
                />
                <span style={{ fontSize: "10px", color: "var(--text-muted)" }}>
                  Created via <code>@BotFather</code> on Telegram.
                </span>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <label style={{ fontSize: "11px", fontWeight: 700, color: "var(--text-primary)" }}>
                    Your Telegram Chat / User ID:
                  </label>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    disabled={tgLoading}
                    onClick={handleDetectChatId}
                    style={{ padding: "2px 8px", fontSize: "11px", display: "flex", alignItems: "center", gap: "4px" }}
                    title="Automatically find your chat ID from messages received by your bot"
                  >
                    🔍 Auto-Detect Chat ID
                  </button>
                </div>
                <input
                  type="text"
                  className="filter-input"
                  placeholder="e.g. 123456789 or -100123456789"
                  value={chatId}
                  onChange={(e) => setChatId(e.target.value)}
                  style={{ width: "100%", padding: "6px 10px", fontSize: "12px" }}
                />
                <span style={{ fontSize: "10px", color: "var(--text-muted)", lineHeight: "1.4" }}>
                  Must be your <strong>numeric Telegram ID</strong> (not a phone number). 
                  First open your bot on Telegram, click <strong>START</strong>, then click <strong>Auto-Detect Chat ID</strong> above.
                </span>
              </div>

              {tgMessage && (
                <div
                  style={{
                    padding: "8px 12px",
                    borderRadius: "4px",
                    fontSize: "12px",
                    background: tgMessage.type === "success" ? "var(--badge-success-bg, #ecfdf5)" : "var(--badge-alert-bg, #fef2f2)",
                    color: tgMessage.type === "success" ? "var(--badge-success-text, #059669)" : "var(--badge-alert-text, #dc2626)",
                    border: `1px solid ${tgMessage.type === "success" ? "var(--badge-success-border, #a7f3d0)" : "var(--badge-alert-border, #fecaca)"}`,
                  }}
                >
                  {tgMessage.text}
                </div>
              )}

              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginTop: "6px" }}>
                <button
                  className="btn btn-secondary"
                  disabled={tgLoading}
                  onClick={handleTestTelegram}
                  style={{ padding: "6px 12px", fontSize: "12px" }}
                >
                  {tgLoading ? "Testing..." : "Send Test Alert"}
                </button>

                <div style={{ display: "flex", gap: "8px" }}>
                  <button
                    className="btn btn-secondary"
                    onClick={() => setTelegramModalOpen(false)}
                    style={{ padding: "6px 12px", fontSize: "12px" }}
                  >
                    Cancel
                  </button>
                  <button
                    className="btn btn-primary"
                    disabled={tgLoading}
                    onClick={handleSaveTelegram}
                    style={{ padding: "6px 14px", fontSize: "12px" }}
                  >
                    {tgLoading ? "Saving..." : "Save & Enable"}
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
