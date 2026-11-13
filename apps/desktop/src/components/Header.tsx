import React from "react";
import { BrandLogo, RefreshIcon } from "./Icons";
import { useTheme } from "../lib/theme";
import { SystemStatus, TelemetryHealthReport } from "../types/events";

interface HeaderProps {
  status: SystemStatus | null;
  health: TelemetryHealthReport | null;
  onRefresh: () => void;
  onOpenHealth: () => void;
  refreshing: boolean;
}

export function Header({
  status,
  health,
  onRefresh,
  onOpenHealth,
  refreshing,
}: HeaderProps) {
  const { preference, setPreference } = useTheme();
  const overall = health?.overall_status?.toLowerCase() || "offline";

  return (
    <header className="app-header">
      <div className="header-brand" style={{ display: "flex", alignItems: "center", gap: "10px" }}>
        <BrandLogo className="brand-symbol" />
        <div style={{ display: "flex", flexDirection: "column", justifyContent: "center" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span className="brand-title" style={{ letterSpacing: "1px", fontWeight: 800 }}>
              प्रहरी <span style={{ fontSize: "13px", fontWeight: 700, color: "var(--accent-cyan, #00d2ff)", opacity: 0.95 }}>PRAHARI</span>
            </span>
            <span className="brand-tag">v{status?.version || "0.1.0"}</span>
            {status?.host && (
              <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
                [{status.host}]
              </span>
            )}
          </div>
          <span style={{ fontSize: "10px", color: "var(--text-muted)", letterSpacing: "0.6px", fontWeight: 500 }}>
            सदा जाग्रत · Autonomous Linux Security Sentinel
          </span>
        </div>
      </div>

      <div className="header-right">
        {/* Theme Segmented Switcher */}
        <div className="theme-segmented" role="radiogroup" aria-label="Theme selection">
          <button
            type="button"
            className={`theme-segmented-btn ${preference === "system" ? "active" : ""}`}
            onClick={() => setPreference("system")}
            title="Follow system/desktop appearance"
          >
            System
          </button>
          <button
            type="button"
            className={`theme-segmented-btn ${preference === "light" ? "active" : ""}`}
            onClick={() => setPreference("light")}
            title="Force light appearance"
          >
            Light
          </button>
          <button
            type="button"
            className={`theme-segmented-btn ${preference === "dark" ? "active" : ""}`}
            onClick={() => setPreference("dark")}
            title="Force dark appearance"
          >
            Dark
          </button>
        </div>

        {health && (
          <div
            className={`health-pill ${overall}`}
            onClick={onOpenHealth}
            title="Click to view telemetry health details"
          >
            <span className="health-indicator-dot" />
            <span>Telemetry: {health.overall_status}</span>
            <span style={{ opacity: 0.7 }}>
              ({health.active_sources_count}/{health.total_sources_count} sources)
            </span>
          </div>
        )}

        <button
          className="btn"
          onClick={onRefresh}
          disabled={refreshing}
          title="Trigger ingestion pass and reload telemetry"
        >
          <RefreshIcon />
          <span>{refreshing ? "Ingesting..." : "Sync Telemetry"}</span>
        </button>
      </div>
    </header>
  );
}
