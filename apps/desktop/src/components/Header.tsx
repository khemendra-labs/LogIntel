import React from "react";
import { BrandLogo, RefreshIcon } from "./Icons";
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
  const overall = health?.overall_status?.toLowerCase() || "offline";

  return (
    <header className="app-header">
      <div className="header-brand">
        <BrandLogo className="brand-symbol" />
        <span className="brand-title">LogIntel</span>
        <span className="brand-tag">v{status?.version || "0.1.0"}</span>
        {status?.host && (
          <span style={{ fontSize: "11px", color: "var(--text-secondary)", fontFamily: "var(--font-mono)" }}>
            [{status.host}]
          </span>
        )}
      </div>

      <div className="header-right">
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
