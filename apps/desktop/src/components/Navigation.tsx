import React from "react";
import { ActivityIcon, DatabaseIcon, OverviewIcon, ServerIcon } from "./Icons";
import { SystemStatus } from "../types/events";

export type NavTab = "overview" | "activity";

interface NavigationProps {
  currentTab: NavTab;
  onTabChange: (tab: NavTab) => void;
  status: SystemStatus | null;
}

export function Navigation({ currentTab, onTabChange, status }: NavigationProps) {
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
