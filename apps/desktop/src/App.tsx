import React, { lazy, Suspense, useEffect, useRef, useState } from "react";
import { Header } from "./components/Header";
import { Navigation, NavTab } from "./components/Navigation";
import {
  fetchAlerts,
  fetchCases,
  fetchEventDetail,
  fetchEventStatistics,
  fetchHandshake,
  fetchIncidents,
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

// Investigation workbenches are large and are not needed for the initial
// dashboard. Loading them only after the analyst navigates or opens a detail
// panel keeps startup latency and renderer memory predictable on modest hosts.
const AlertsPage = lazy(() => import("./pages/AlertsPage").then(({ AlertsPage }) => ({ default: AlertsPage })));
const CasesPage = lazy(() => import("./pages/CasesPage").then(({ CasesPage }) => ({ default: CasesPage })));
const DiagnosticsPage = lazy(() => import("./pages/DiagnosticsPage").then(({ DiagnosticsPage }) => ({ default: DiagnosticsPage })));
const IncidentsPage = lazy(() => import("./pages/IncidentsPage").then(({ IncidentsPage }) => ({ default: IncidentsPage })));
const MultiHostPage = lazy(() => import("./pages/MultiHostPage").then(({ MultiHostPage }) => ({ default: MultiHostPage })));
const RulesPage = lazy(() => import("./pages/RulesPage").then(({ RulesPage }) => ({ default: RulesPage })));
const ThreatHuntingPage = lazy(() => import("./pages/ThreatHuntingPage").then(({ ThreatHuntingPage }) => ({ default: ThreatHuntingPage })));
const AlertDetailModal = lazy(() => import("./features/AlertDetailModal").then(({ AlertDetailModal }) => ({ default: AlertDetailModal })));
const EntityPivotModal = lazy(() => import("./features/EntityPivotModal").then(({ EntityPivotModal }) => ({ default: EntityPivotModal })));
const EventDetailModal = lazy(() => import("./features/EventDetailModal").then(({ EventDetailModal }) => ({ default: EventDetailModal })));
const EventForensicsModal = lazy(() => import("./features/EventForensicsModal").then(({ EventForensicsModal }) => ({ default: EventForensicsModal })));
const IncidentWorkspaceModal = lazy(() => import("./features/IncidentWorkspaceModal").then(({ IncidentWorkspaceModal }) => ({ default: IncidentWorkspaceModal })));
const TelemetryHealthModal = lazy(() => import("./features/TelemetryHealthModal").then(({ TelemetryHealthModal }) => ({ default: TelemetryHealthModal })));

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

  // In-flight request lock and abort controller to prevent overlapping polling intervals
  const isFetchingRef = useRef<boolean>(false);
  const pollAbortRef = useRef<AbortController | null>(null);

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
    if (typeof document !== "undefined" && document.hidden) return;
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    if (pollAbortRef.current) {
      pollAbortRef.current.abort();
      pollAbortRef.current = null;
    }
    const currentAbort = new AbortController();
    pollAbortRef.current = currentAbort;
    const signal = currentAbort.signal;

    try {
      const isOverview = currentTab === "overview";
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
        fetchSystemStatus(signal).catch(() => null),
        fetchTelemetryHealth(signal).catch(() => null),
        isOverview ? fetchEventStatistics(hours, signal).catch(() => null) : Promise.resolve(null),
        fetchAlerts({ status: "OPEN", limit: 1 }, signal).catch(() => ({ total: 0 })),
        fetchAlerts({ status: "ACKNOWLEDGED", limit: 1 }, signal).catch(() => ({ total: 0 })),
        fetchAlerts({ status: "RESOLVED", limit: 1 }, signal).catch(() => ({ total: 0 })),
        fetchAlerts({ status: "FALSE_POSITIVE", limit: 1 }, signal).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "OPEN", limit: 1 }, signal).catch(() => ({ total: 0 })),
        fetchIncidents({ status: "INVESTIGATING", limit: 1 }, signal).catch(() => ({ total: 0 })),
        fetchCases(undefined, 100, signal).catch(() => []),
      ]);

      if (signal.aborted) return;

      if (sysStatus) {
        setStatus(sysStatus);
        setBackendConnected(true);
        setBackendError(null);
      } else {
        const handshake = await fetchHandshake().catch(() => null);
        if (handshake && handshake.service === "logintel-engine") {
          setBackendConnected(false);
          setBackendError("LogIntel engine is active, but client authentication is synchronizing. Retrying connection...");
        } else {
          setBackendConnected(false);
          setBackendError("LogIntel engine is unreachable at 127.0.0.1:41721. Verify that the backend service is running.");
        }
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
      if (signal.aborted) return;
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
    }, 10000);
    return () => {
      clearInterval(interval);
      if (pollAbortRef.current) {
        pollAbortRef.current.abort();
        pollAbortRef.current = null;
      }
    };
  }, [overviewHours, currentTab]);

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
      <Suspense fallback={<div className="page-loading" role="status">Loading workspace…</div>}>
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
              refreshTrigger={refreshTrigger}
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
      </Suspense>
    </div>
  );
}
