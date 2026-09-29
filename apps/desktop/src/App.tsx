import React, { useEffect, useState } from "react";
import { Header } from "./components/Header";
import { Navigation, NavTab } from "./components/Navigation";
import { EventDetailModal } from "./features/EventDetailModal";
import { TelemetryHealthModal } from "./features/TelemetryHealthModal";
import {
  fetchEventStatistics,
  fetchSystemStatus,
  fetchTelemetryHealth,
  triggerIngestionCycle,
} from "./lib/api";
import { ActivityPage } from "./pages/ActivityPage";
import { OverviewPage } from "./pages/OverviewPage";
import {
  CanonicalEvent,
  EventStatistics,
  SystemStatus,
  TelemetryHealthReport,
} from "./types/events";

export function App() {
  const [currentTab, setCurrentTab] = useState<NavTab>("overview");
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [health, setHealth] = useState<TelemetryHealthReport | null>(null);
  const [stats, setStats] = useState<EventStatistics | null>(null);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  // Modals
  const [selectedEvent, setSelectedEvent] = useState<CanonicalEvent | null>(null);
  const [healthModalOpen, setHealthModalOpen] = useState<boolean>(false);

  // Activity filter passed from Overview
  const [activityFilter, setActivityFilter] = useState<{ severity?: string; source?: string } | null>(null);

  const loadData = async () => {
    try {
      const [sysStatus, telHealth, evtStats] = await Promise.all([
        fetchSystemStatus(),
        fetchTelemetryHealth(),
        fetchEventStatistics(24),
      ]);
      setStatus(sysStatus);
      setHealth(telHealth);
      setStats(evtStats);
    } catch (err) {
      console.error("Error polling backend engine:", err);
    }
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleSync = async () => {
    setRefreshing(true);
    try {
      await triggerIngestionCycle();
      await loadData();
      setRefreshTrigger((c) => c + 1);
    } catch (err) {
      console.error("Sync error:", err);
    } finally {
      setRefreshing(false);
    }
  };

  const handleNavigateToActivity = (filter?: { severity?: string; source?: string }) => {
    setActivityFilter(filter || null);
    setCurrentTab("activity");
  };

  return (
    <div className="app-container">
      <Header
        status={status}
        health={health}
        onRefresh={handleSync}
        onOpenHealth={() => setHealthModalOpen(true)}
        refreshing={refreshing}
      />

      <div className="app-main-layout">
        <Navigation
          currentTab={currentTab}
          onTabChange={(tab) => {
            if (tab === "activity") setActivityFilter(null);
            setCurrentTab(tab);
          }}
          status={status}
        />

        <main className="content-pane">
          {currentTab === "overview" && (
            <OverviewPage
              stats={stats}
              health={health}
              status={status}
              onSelectEvent={(evt) => setSelectedEvent(evt)}
              onNavigateToActivity={handleNavigateToActivity}
            />
          )}

          {currentTab === "activity" && (
            <ActivityPage
              initialFilter={activityFilter}
              onSelectEvent={(evt) => setSelectedEvent(evt)}
              refreshTrigger={refreshTrigger}
            />
          )}
        </main>
      </div>

      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

      {healthModalOpen && (
        <TelemetryHealthModal
          health={health}
          onClose={() => setHealthModalOpen(false)}
          onRefresh={loadData}
        />
      )}
    </div>
  );
}
