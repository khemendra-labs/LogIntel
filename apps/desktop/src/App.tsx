import React, { useEffect, useState } from "react";
import { Header } from "./components/Header";
import { Navigation, NavTab } from "./components/Navigation";
import { AlertDetailModal } from "./features/AlertDetailModal";
import { EntityPivotModal } from "./features/EntityPivotModal";
import { EventDetailModal } from "./features/EventDetailModal";
import { EventForensicsModal } from "./features/EventForensicsModal";
import { IncidentWorkspaceModal } from "./features/IncidentWorkspaceModal";
import { TelemetryHealthModal } from "./features/TelemetryHealthModal";
import {
  fetchAlerts,
  fetchEventDetail,
  fetchEventStatistics,
  fetchIncidents,
  fetchSystemStatus,
  fetchTelemetryHealth,
  triggerIngestionCycle,
} from "./lib/api";
import { ActivityPage } from "./pages/ActivityPage";
import { AlertsPage } from "./pages/AlertsPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { OverviewPage } from "./pages/OverviewPage";
import { RulesPage } from "./pages/RulesPage";
import { ThreatHuntingPage } from "./pages/ThreatHuntingPage";
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
  const [openIncidentsCount, setOpenIncidentsCount] = useState<number>(0);
  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  // Modals
  const [selectedEvent, setSelectedEvent] = useState<CanonicalEvent | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [healthModalOpen, setHealthModalOpen] = useState<boolean>(false);
  const [selectedEntityKey, setSelectedEntityKey] = useState<string | null>(null);
  const [forensicEventId, setForensicEventId] = useState<string | null>(null);

  // Activity filter passed from Overview
  const [activityFilter, setActivityFilter] = useState<{ severity?: string; source?: string } | null>(null);

  const loadData = async () => {
    try {
      const [sysStatus, telHealth, evtStats, alertsData, incidentsData] = await Promise.all([
        fetchSystemStatus(),
        fetchTelemetryHealth(),
        fetchEventStatistics(24),
        fetchAlerts({ status: "OPEN", limit: 1 }).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "OPEN", limit: 1 }).catch(() => ({ total: 0 })),
      ]);
      setStatus(sysStatus);
      setHealth(telHealth);
      setStats(evtStats);
      if (alertsData && typeof alertsData.total === "number") {
        setOpenAlertsCount(alertsData.total);
      }
      if (incidentsData && typeof incidentsData.total === "number") {
        setOpenIncidentsCount(incidentsData.total);
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
          openIncidentsCount={openIncidentsCount}
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

          {currentTab === "incidents" && (
            <IncidentsPage
              onSelectIncident={(id) => setSelectedIncidentId(id)}
              refreshTrigger={refreshTrigger}
            />
          )}

          {currentTab === "hunting" && (
            <ThreatHuntingPage
              onSelectEventForensics={(id) => setForensicEventId(id)}
              onSelectEntityKey={(key) => setSelectedEntityKey(key)}
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

      {selectedIncidentId !== null && (
        <IncidentWorkspaceModal
          incidentId={selectedIncidentId}
          onClose={() => setSelectedIncidentId(null)}
          onStatusUpdated={() => {
            loadData();
            setRefreshTrigger((c) => c + 1);
          }}
          onSelectAlertId={(alertId) => setSelectedAlertId(alertId)}
          onSelectEventId={(eventId) => setForensicEventId(eventId)}
          onSelectEntityKey={(key) => setSelectedEntityKey(key)}
        />
      )}

      {selectedEntityKey !== null && (
        <EntityPivotModal
          entityKey={selectedEntityKey}
          onClose={() => setSelectedEntityKey(null)}
          onSelectEventId={(eventId) => setForensicEventId(eventId)}
          onSelectIncidentId={(incId) => setSelectedIncidentId(incId)}
        />
      )}

      {forensicEventId !== null && (
        <EventForensicsModal
          eventId={forensicEventId}
          onClose={() => setForensicEventId(null)}
          onSelectEntityKey={(key) => setSelectedEntityKey(key)}
          onSelectAlertId={(alId) => setSelectedAlertId(alId)}
          onSelectIncidentId={(incId) => setSelectedIncidentId(incId)}
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

