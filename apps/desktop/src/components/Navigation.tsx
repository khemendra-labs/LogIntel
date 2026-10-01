import React from "react";
import { ActivityIcon, AlertIcon, DatabaseIcon, HuntIcon, IncidentIcon, OverviewIcon, RulesIcon, ServerIcon } from "./Icons";
import { SystemStatus } from "../types/events";

export type NavTab = "overview" | "activity" | "incidents" | "alerts" | "hunting" | "rules";

interface NavigationProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  status: SystemStatus | null;
  openAlertsCount?: number;
  openIncidentsCount?: number;
}

export function Navigation({
  currentTab,
  onTabChange,
  status,
  openAlertsCount = 0,
  openIncidentsCount = 0,
}: NavigationProps) {
  return (
    <aside className="sidebar-nav">
      <div>
        <div className="nav-group-title">Telemetry & Ops</div>
        <button
          className={`nav-item ${currentTab === "overview" ? "active" : ""}`}
          onClick={() => onTabChange("overview")}
        >
          <OverviewIcon />
          <span>Overview</span>
        </button>
        <button
          className={`nav-item ${currentTab === "activity" ? "active" : ""}`}
          onClick={() => onTabChange("activity")}
        >
          <ActivityIcon />
          <span>Activity</span>
        </button>

        <div className="nav-group-title" style={{ marginTop: "16px" }}>Investigation & Hunting</div>
        <button
          className={`nav-item ${currentTab === "incidents" ? "active" : ""}`}
          onClick={() => onTabChange("incidents")}
        >
          <IncidentIcon />
          <span style={{ display: "flex", justifyContent: "space-between", alignItems: "center", width: "100%" }}>
            <span>Incidents</span>
            {openIncidentsCount > 0 && (
              <span className="badge badge-alert" style={{ fontSize: "10px", padding: "1px 5px", marginLeft: "6px" }}>
                {openIncidentsCount}
              </span>
            )}
          </span>
        </button>
        <button
          className={`nav-item ${currentTab === "hunting" ? "active" : ""}`}
          onClick={() => onTabChange("hunting")}
        >
          <HuntIcon />
          <span>Threat Hunting</span>
        </button>
        <button
          className={`nav-item ${currentTab === "alerts" ? "active" : ""}`}
          onClick={() => onTabChange("alerts")}
        >
          <AlertIcon />
          <span style={{ display: "flex", justifyContent: "space-between", alignItems: "center", width: "100%" }}>
            <span>Alerts</span>
            {openAlertsCount > 0 && (
              <span className="badge badge-alert" style={{ fontSize: "10px", padding: "1px 5px", marginLeft: "6px" }}>
                {openAlertsCount}
              </span>
            )}
          </span>
        </button>
        <button
          className={`nav-item ${currentTab === "rules" ? "active" : ""}`}
          onClick={() => onTabChange("rules")}
        >
          <RulesIcon />
          <span>Rules Catalog</span>
        </button>
      </div>

      <div className="sidebar-footer">
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <DatabaseIcon />
          <span>Events in DB: <strong>{status?.total_events.toLocaleString() || 0}</strong></span>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
          <ServerIcon />
          <span>Uptime: <strong>{Math.floor((status?.uptime_seconds || 0) / 60)}m</strong></span>
        </div>
      </div>
    </aside>
  );
}
