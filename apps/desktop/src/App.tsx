import React, { useEffect, useRef, useState } from "react";
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
  fetchCases,
  fetchEventDetail,
  fetchEventStatistics,
  fetchIncidents,
  fetchSystemStatus,
  fetchTelemetryHealth,
  triggerIngestionCycle,
} from "./lib/api";
import { ActivityPage } from "./pages/ActivityPage";
import { AlertsPage } from "./pages/AlertsPage";
import { CasesPage } from "./pages/CasesPage";
import { DiagnosticsPage } from "./pages/DiagnosticsPage";
import { IncidentsPage } from "./pages/IncidentsPage";
import { MultiHostPage } from "./pages/MultiHostPage";
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
  const [overviewHours, setOverviewHours] = useState<number>(24);
  const [isLoadingStats, setIsLoadingStats] = useState<boolean>(false);

  // Granular counts for KPI dashboard
  const [openAlertsCount, setOpenAlertsCount] = useState<number>(0);
  const [ackAlertsCount, setAckAlertsCount] = useState<number>(0);
  const [resolvedAlertsCount, setResolvedAlertsCount] = useState<number>(0);
  const [falsePositiveAlertsCount, setFalsePositiveAlertsCount] = useState<number>(0);
  const [openIncidentsCount, setOpenIncidentsCount] = useState<number>(0);
  const [activeIncidentsCount, setActiveIncidentsCount] = useState<number>(0);
  const [casesCount, setCasesCount] = useState<number>(0);

  // Connection & Context state
  const [backendConnected, setBackendConnected] = useState<boolean>(true);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [selectedCaseId, setSelectedCaseId] = useState<number | null>(null);

  const [refreshing, setRefreshing] = useState<boolean>(false);
  const [refreshTrigger, setRefreshTrigger] = useState<number>(0);

  // In-flight request lock to prevent overlapping polling intervals
  const isFetchingRef = useRef<boolean>(false);

  // Modals
  const [selectedEvent, setSelectedEvent] = useState<CanonicalEvent | null>(null);
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [selectedIncidentId, setSelectedIncidentId] = useState<number | null>(null);
  const [healthModalOpen, setHealthModalOpen] = useState<boolean>(false);
  const [selectedEntityKey, setSelectedEntityKey] = useState<string | null>(null);
  const [forensicEventId, setForensicEventId] = useState<string | null>(null);

  // Filters passed across navigation
  const [activityFilter, setActivityFilter] = useState<{ severity?: string; source?: string } | null>(null);

  const loadData = async (hours = overviewHours) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    try {
      const [
        sysStatus,
        telHealth,
        evtStats,
        openAlerts,
        ackAlerts,
        resAlerts,
        fpAlerts,
        openIncidents,
        invIncidents,
        caseList,
      ] = await Promise.all([
        fetchSystemStatus().catch(() => null),
        fetchTelemetryHealth().catch(() => null),
        fetchEventStatistics(hours).catch(() => null),
        fetchAlerts({ status: "OPEN", limit: 1 }).catch(() => ({ total: 0 })),
        fetchAlerts({ status: "ACKNOWLEDGED", limit: 1 }).catch(() => ({ total: 0 })),
        fetchAlerts({ status: "RESOLVED", limit: 1 }).catch(() => ({ total: 0 })),
        fetchAlerts({ status: "FALSE_POSITIVE", limit: 1 }).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "OPEN", limit: 1 }).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "INVESTIGATING", limit: 1 }).catch(() => ({ total: 0 })),
        fetchCases(undefined, 100).catch(() => []),
      ]);

      if (sysStatus) {
        setStatus(sysStatus);
        setBackendConnected(true);
        setBackendError(null);
      } else {
        setBackendConnected(false);
        setBackendError("LogIntel engine is unreachable at 127.0.0.1:41721. Verify that the backend service is running.");
      }

      if (telHealth) setHealth(telHealth);
      if (evtStats) setStats(evtStats);

      if (openAlerts && typeof openAlerts.total === "number") setOpenAlertsCount(openAlerts.total);
      if (ackAlerts && typeof ackAlerts.total === "number") setAckAlertsCount(ackAlerts.total);
      if (resAlerts && typeof resAlerts.total === "number") setResolvedAlertsCount(resAlerts.total);
      if (fpAlerts && typeof fpAlerts.total === "number") setFalsePositiveAlertsCount(fpAlerts.total);

      const openInc = openIncidents?.total || 0;
      const invInc = invIncidents?.total || 0;
      setOpenIncidentsCount(openInc);
      setActiveIncidentsCount(openInc + invInc);

      if (Array.isArray(caseList)) {
        setCasesCount(caseList.length);
        if (caseList.length > 0 && selectedCaseId === null) {
          setSelectedCaseId(caseList[0].case_id);
        }
      }
    } catch (err) {
      console.error("Error polling backend engine:", err);
      setBackendConnected(false);
      setBackendError(err instanceof Error ? err.message : "Error connecting to backend");
    } finally {
      isFetchingRef.current = false;
    }
  };

  useEffect(() => {
    loadData(overviewHours);
    const interval = setInterval(() => {
      loadData(overviewHours);
    }, 8000);
    return () => clearInterval(interval);
  }, [overviewHours]);

  const handleTimeWindowChange = async (hours: number) => {
    setOverviewHours(hours);
    setIsLoadingStats(true);
    try {
      const newStats = await fetchEventStatistics(hours);
      setStats(newStats);
    } catch (err) {
      console.error(`Failed to load event statistics for ${hours}h:`, err);
    } finally {
      setIsLoadingStats(false);
    }
  };

  const handleSync = async () => {
    setRefreshing(true);
    try {
      await triggerIngestionCycle();
      await loadData(overviewHours);
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

  const handleNavigateToAlerts = (filter?: { status?: string }) => {
    setCurrentTab("alerts");
  };

  const handleNavigateToIncidents = (filter?: { status?: string }) => {
    setCurrentTab("incidents");
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
          openIncidentsCount={activeIncidentsCount}
          casesCount={casesCount}
        />

        <main className="content-pane">
          {currentTab === "overview" && (
            <OverviewPage
              stats={stats}
              health={health}
              status={status}
              openAlertsCount={openAlertsCount}
              ackAlertsCount={ackAlertsCount}
              resolvedAlertsCount={resolvedAlertsCount}
              falsePositiveAlertsCount={falsePositiveAlertsCount}
              activeIncidentsCount={activeIncidentsCount}
              onSelectEvent={(evt) => setSelectedEvent(evt)}
              onSelectAlert={(alertId) => setSelectedAlertId(alertId)}
              onSelectIncident={(incId) => setSelectedIncidentId(incId)}
              onOpenHealth={() => setHealthModalOpen(true)}
              onNavigateToActivity={handleNavigateToActivity}
              onNavigateToAlerts={handleNavigateToAlerts}
              onNavigateToIncidents={handleNavigateToIncidents}
              onNavigateToCases={() => setCurrentTab("cases")}
              onNavigateToDiagnostics={() => setCurrentTab("diagnostics")}
              onTimeWindowChange={handleTimeWindowChange}
              currentHours={overviewHours}
              isLoadingStats={isLoadingStats}
              backendConnected={backendConnected}
              backendError={backendError}
              onRetryConnection={() => loadData(overviewHours)}
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

          {currentTab === "rules" && <RulesPage />}

          {currentTab === "cases" && (
            <CasesPage
              onSelectCase={(caseId, incidentId) => {
                setSelectedCaseId(caseId);
                setSelectedIncidentId(incidentId);
              }}
              refreshTrigger={refreshTrigger}
            />
          )}

          {currentTab === "multihost" && (
            <MultiHostPage
              initialCaseId={selectedCaseId}
              refreshTrigger={refreshTrigger}
            />
          )}

          {currentTab === "diagnostics" && (
            <DiagnosticsPage
              status={status}
              health={health}
              onRefresh={async () => {
                await loadData(overviewHours);
              }}
              backendConnected={backendConnected}
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

      {selectedAlertId !== null && (
        <AlertDetailModal
          alertId={selectedAlertId}
          onClose={() => setSelectedAlertId(null)}
          onStatusUpdated={() => {
            loadData(overviewHours);
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
            loadData(overviewHours);
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

      {healthModalOpen && health && (
        <TelemetryHealthModal
          health={health}
          onClose={() => setHealthModalOpen(false)}
          onRefresh={handleSync}
        />
      )}

      {forensicEventId && (
        <EventForensicsModal
          eventId={forensicEventId}
          onClose={() => setForensicEventId(null)}
        />
      )}
    </div>
  );
}
