import React, { useEffect, useState } from "react";
import { Header } from "./components/Header";
import { Navigation, NavTab } from "./components/Navigation";
import { AlertDetailModal } from "./features/AlertDetailModal";
import { EventDetailModal } from "./features/EventDetailModal";
import { TelemetryHealthModal } from "./features/TelemetryHealthModal";
import {
  fetchAlerts,
  fetchEventDetail,
  fetchEventStatistics,
  fetchSystemStatus,
  fetchTelemetryHealth,
  triggerIngestionCycle,
} from "./lib/api";
import { ActivityPage } from "./pages/ActivityPage";
import { AlertsPage } from "./pages/AlertsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RulesPage } from "./pages/RulesPage";
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
  const [openAlertsCount, setOpenAlertsCount] = useState<number>(0);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  // Modals
  const [selectedEvent, setSelectedEvent] = useState<CanonicalEvent | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [healthModalOpen, setHealthModalOpen] = useState<boolean>(false);

  // Activity filter passed from Overview
  const [activityFilter, setActivityFilter] = useState<{ severity?: string; source?: string } | null>(null);

  const loadData = async () => {
    try {
      const [sysStatus, telHealth, evtStats, alertsData] = await Promise.all([
        fetchSystemStatus(),
        fetchTelemetryHealth(),
        fetchEventStatistics(24),
        fetchAlerts({ status: "OPEN", limit: 1 }).catch(() => ({ total: 0 })),
      ]);
      setStatus(sysStatus);
      setHealth(telHealth);
      setStats(evtStats);
      if (alertsData && typeof alertsData.total === "number") {
        setOpenAlertsCount(alertsData.total);
      }
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

  const handleNavigateToAlerts = () => {
    setCurrentTab("alerts");
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
          openAlertsCount={openAlertsCount}
        />

        <main className="content-pane">
          {currentTab === "overview" && (
            <OverviewPage
              stats={stats}
              health={health}
              status={status}
              openAlertsCount={openAlertsCount}
              onSelectEvent={(evt) => setSelectedEvent(evt)}
              onNavigateToActivity={handleNavigateToActivity}
              onNavigateToAlerts={handleNavigateToAlerts}
            />
          )}

          {currentTab === "activity" && (
            <ActivityPage
              initialFilter={activityFilter}
              onSelectEvent={(evt) => setSelectedEvent(evt)}
              refreshTrigger={refreshTrigger}
            />
          )}

          {currentTab === "alerts" && (
            <AlertsPage
              onSelectAlert={(id) => setSelectedAlertId(id)}
              refreshTrigger={refreshTrigger}
            />
          )}

          {currentTab === "rules" && (
            <RulesPage />
          )}
        </main>
      </div>

      {selectedEvent && (
        <EventDetailModal
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}

      {selectedAlertId !== null && (
        <AlertDetailModal
          alertId={selectedAlertId}
          onClose={() => setSelectedAlertId(null)}
          onStatusUpdated={() => {
            loadData();
            setRefreshTrigger((c) => c + 1);
          }}
          onSelectEventId={async (eventId) => {
            try {
              const ev = await fetchEventDetail(eventId);
              setSelectedEvent(ev);
            } catch (err) {
              console.error("Failed to load canonical event for evidence:", err);
            }
          }}
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

