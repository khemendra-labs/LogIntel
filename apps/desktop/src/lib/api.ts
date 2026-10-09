import {
  CanonicalEvent,
  EventsQueryResponse,
  EventStatistics,
  SystemStatus,
  TelemetryHealthReport,
} from "../types/events";
import type {
  Alert,
  AlertDetailResponse,
  AlertQueryParams,
  AlertsQueryResponse,
  AlertStatus,
  DetectionRuleDetailResponse,
  DetectionRulesQueryResponse,
} from "../types/detection";
import type {
  AttackGraphResponse,
  CorrelateIncidentsResponse,
  Incident,
  IncidentAlertsResponse,
  IncidentDetailResponse,
  IncidentQueryParams,
  IncidentsQueryResponse,
  IncidentStatus,
  IncidentTimelineResponse,
} from "../types/incidents";
import type {
  AttackPathReconstruction,
  CreateNoteRequest,
  EntityPivotSummary,
  EventForensics,
  ExportInvestigationResponse,
  InvestigationDossier,
  InvestigationNote,
  InvestigationNoteAudit,
  MitreMapping,
  ThreatHuntFilter,
  ThreatHuntResponse,
  AIInvestigationResponse,
  AIStatusResponse,
  EvidenceCoverage,
  InvestigationEvidenceBundle,
  QueryPreviewResponse,
  QueryProposal,
  InvestigationWorkspace,
  InvestigationScope,
  AnalystHypothesis,
  InvestigationSummary,
  ReportDraft,
  ClaimTrace,
  InvestigationCase,
  CaseStatus,
  CaseHypothesis,
  CaseEvidenceReference,
  CaseQueryRecord,
  CaseReportVersion,
  CaseAuditRecord,
  InvestigationFinding,
  InvestigationCorrelation,
  EvidenceGap,
  GovernedThreatHuntProposal,
  GovernedThreatHuntExecution,
  EntityPivotAnalysis,
  CaseTimelineItem,
  HypothesisEvidenceAnalysis,
  CaseIntelligenceDossier,
  CaseInvestigationDossier,
  InvestigationIntelligenceResponse,
  FindingReviewUpdateRequest,
  EvidenceMatrixEntry,
  EvidenceGapAction,
  RefinedTimelineItem,
  CaseBriefing,
  ProvenanceManifestEntry,
  InvestigationGraph,
  InvestigationGraphNode,
  InvestigationGraphEdge,
  InvestigationPath,
  TemporalChain,
  EntityPivotGraph,
  GraphExplanationRequest,
  GraphExplanationResponse,
  ReportDraftRequest,
  EvidenceCluster,
  BehavioralSequence,
  HypothesisSupportDetail,
  EvidenceGapDetail,
  EntityWorkbenchDossier,
  CorrelationExplanationRequest,
  CorrelationExplanationResponse,
  EpisodeType,
  TransitionType,
  TemporalGapType,
  CampaignCorrelationStatus,
  CampaignRelationReason,
  TransitionReviewState,
  ContinuityType,
  TemporalEpisode,
  TemporalTransition,
  TemporalEvidenceChain,
  TemporalGap,
  MultiHostTrace,
  EntityContinuity,
  IncidentCampaignCorrelation,
  AttackSequenceReconstruction,
  TemporalReconstructionDossier,
  TemporalExplanationResponse,
  CaseAssessment,
  StructuredFinding,
  CompetingHypothesisAssessment,
  InvestigationQuestion,
  PrioritizedEvidenceGap,
  ClosureReadinessAssessment,
  InvestigationBriefing,
  CaseHandoffPackage,
  AssessmentExplanationResponse,
  FindingReviewState,
  InvestigationTimelineItem,
  TimelineFilterParams,
  TimelineReplaySession,
  TimelineContextResponse,
  TimelineQueryResponse,
  EvidenceCollection,
  EvidenceCollectionItem,
  CreateCollectionRequest,
  UpdateCollectionRequest,
  AddCollectionItemRequest,
  UpdateCollectionItemRequest,
  CollectionFilterParams,
  WorkbenchFilterParams,
  EvidenceWorkbenchResponse,
  Finding,
  FindingReviewStatus,
  HypothesisAssessmentView,
  HypothesisComparisonResponse,
  FindingsWorkbenchResponse,
  HuntExecutionResult,
  HuntQueryPreview,
  HuntSequenceProposal,
  HuntSequenceResult,
  HuntExportResponse,
  HuntHistoryRecord,
  GovernedQueryModel,
  HuntIntent,
  StructuredReport,
  ReportVersionSummary,
  ReportComparisonResult,
  EvidencePackage,
  CaseHandoffPacket,
  ReportExportResponse,
  CaseReviewSnapshot,
  ReviewBlocker,
  AcknowledgeBlockerRequest,
  CloseCaseRequest,
  ReopenCaseRequest,
  AIReviewSummaryResponse,
  ReviewExportResponse,
} from "../types/investigation";

const API_BASE = "http://127.0.0.1:41721/api/v1";

let cachedToken: string | null = null;
let tokenProvider: (() => Promise<string | null>) | null = null;

export function setTokenProvider(provider: (() => Promise<string | null>) | null): void {
  tokenProvider = provider;
}

export async function getEngineToken(): Promise<string | null> {
  if (cachedToken) return cachedToken;
  if (tokenProvider) {
    cachedToken = await tokenProvider();
    return cachedToken;
  }
  try {
    if (typeof window !== "undefined" && "__TAURI_INTERNALS__" in window) {
      const { invoke } = await import("@tauri-apps/api/core");
      cachedToken = await invoke<string>("get_engine_token");
      return cachedToken;
    }
  } catch (err) {
    console.debug("Unable to acquire engine token via Tauri invoke:", err);
  }
  return cachedToken;
}

export function setEngineToken(token: string | null): void {
  cachedToken = token;
}

async function apiFetch(path: string, init?: RequestInit): Promise<Response> {
  let token = await getEngineToken();
  const headers = new Headers(init?.headers || {});
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  let res = await fetch(`${API_BASE}${path}`, {
    ...init,
    headers,
  });
  if (res.status === 401 && cachedToken) {
    // Engine may have restarted and rotated its token; invalidate cache and retry once
    cachedToken = null;
    token = await getEngineToken();
    if (token) {
      const retryHeaders = new Headers(init?.headers || {});
      retryHeaders.set("Authorization", `Bearer ${token}`);
      res = await fetch(`${API_BASE}${path}`, {
        ...init,
        headers: retryHeaders,
      });
    }
  }
  return res;
}

export interface HandshakeInfo {
  service: string;
  version: string;
  api_version: string;
  status: string;
}

export async function fetchHandshake(): Promise<HandshakeInfo> {
  const res = await fetch(`${API_BASE}/handshake`);
  if (!res.ok) {
    throw new Error(`Engine handshake failed: ${res.statusText}`);
  }
  return res.json();
}

export interface EventQueryParams {
  limit?: number;
  offset?: number;
  source?: string;
  eventType?: string;
  severity?: string;
  username?: string;
  ip?: string;
  outcome?: string;
  search?: string;
  sortOrder?: "DESC" | "ASC";
}

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const res = await apiFetch("/system/status");
  if (!res.ok) {
    throw new Error(`Failed to fetch system status: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTelemetryHealth(): Promise<TelemetryHealthReport> {
  const res = await apiFetch("/telemetry/health");
  if (!res.ok) {
    throw new Error(`Failed to fetch telemetry health: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvents(params: EventQueryParams = {}): Promise<EventsQueryResponse> {
  const query = new URLSearchParams();
  if (params.limit !== undefined) query.set("limit", params.limit.toString());
  if (params.offset !== undefined) query.set("offset", params.offset.toString());
  if (params.source) query.set("source", params.source);
  if (params.eventType) query.set("event_type", params.eventType);
  if (params.severity) query.set("severity", params.severity);
  if (params.username) query.set("username", params.username);
  if (params.ip) query.set("ip", params.ip);
  if (params.outcome) query.set("outcome", params.outcome);
  if (params.search) query.set("search", params.search);
  if (params.sortOrder) query.set("sort_order", params.sortOrder);

  const res = await apiFetch(`/events?${query.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to query events: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEventDetail(eventId: string): Promise<CanonicalEvent> {
  const res = await apiFetch(`/events/${eventId}`);
  if (!res.ok) {
    throw new Error(`Failed to load event details: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEventStatistics(hours: number = 24): Promise<EventStatistics> {
  const res = await apiFetch(`/events/stats/summary?hours=${hours}`);
  if (!res.ok) {
    throw new Error(`Failed to load event statistics: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerIngestionCycle(): Promise<{ status: string; ingested_records: number }> {
  const res = await apiFetch("/ingestion/trigger", { method: "POST" });
  if (!res.ok) {
    throw new Error(`Failed to trigger ingestion: ${res.statusText}`);
  }
  return res.json();
}

// ============================================================================
// Detection & Alerts API
// ============================================================================


export async function fetchAlerts(params: AlertQueryParams = {}): Promise<AlertsQueryResponse> {
  const query = new URLSearchParams();
  if (params.status) query.set("status", params.status);
  if (params.severity) query.set("severity", params.severity);
  if (params.host) query.set("host", params.host);
  if (params.rule_id) query.set("rule_id", params.rule_id);
  if (params.limit !== undefined) query.set("limit", params.limit.toString());
  if (params.offset !== undefined) query.set("offset", params.offset.toString());

  const res = await apiFetch(`/alerts?${query.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to query alerts: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAlertDetail(alertId: number): Promise<AlertDetailResponse> {
  const res = await apiFetch(`/alerts/${alertId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alert detail for #${alertId}: ${res.statusText}`);
  }
  return res.json();
}

export async function updateAlertStatus(
  alertId: number,
  status: AlertStatus,
  resolutionNote?: string
): Promise<Alert> {
  const res = await apiFetch(`/alerts/${alertId}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, resolution_note: resolutionNote }),
  });
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {}
    throw new Error(`Failed to update alert status: ${errorDetail}`);
  }
  return res.json();
}

export async function fetchDetectionRules(
  category?: string,
  enabled?: boolean
): Promise<DetectionRulesQueryResponse> {
  const query = new URLSearchParams();
  if (category) query.set("category", category);
  if (enabled !== undefined) query.set("enabled", enabled.toString());

  const res = await apiFetch(`/detection/rules?${query.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to query detection rules: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchDetectionRuleDetail(
  ruleId: string
): Promise<DetectionRuleDetailResponse> {
  const res = await apiFetch(`/detection/rules/${ruleId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch detection rule '${ruleId}': ${res.statusText}`);
  }
  return res.json();
}

// ============================================================================
// Incident Management, Correlation & Attack Graph API (Milestone 3)
// ============================================================================

export async function fetchIncidents(
  params: IncidentQueryParams = {}
): Promise<IncidentsQueryResponse> {
  const query = new URLSearchParams();
  if (params.status) query.set("status", params.status);
  if (params.severity) query.set("severity", params.severity);
  if (params.host) query.set("host", params.host);
  if (params.user) query.set("user", params.user);
  if (params.limit !== undefined) query.set("limit", params.limit.toString());
  if (params.offset !== undefined) query.set("offset", params.offset.toString());

  const res = await apiFetch(`/incidents?${query.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to query incidents: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchIncidentDetail(
  incidentId: number
): Promise<IncidentDetailResponse> {
  const res = await apiFetch(`/incidents/${incidentId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch incident detail for #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchIncidentAlerts(
  incidentId: number
): Promise<IncidentAlertsResponse> {
  const res = await apiFetch(`/incidents/${incidentId}/alerts`);
  if (!res.ok) {
    throw new Error(`Failed to fetch alerts for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function updateIncidentStatus(
  incidentId: number,
  status: IncidentStatus,
  resolutionNote?: string
): Promise<Incident> {
  const res = await apiFetch(`/incidents/${incidentId}/status`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ status, resolution_note: resolutionNote }),
  });
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {}
    throw new Error(`Failed to update incident status: ${errorDetail}`);
  }
  return res.json();
}

export async function fetchIncidentAttackGraph(
  incidentId: number
): Promise<AttackGraphResponse> {
  const res = await apiFetch(`/incidents/${incidentId}/graph`);
  if (!res.ok) {
    throw new Error(`Failed to fetch attack graph for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchIncidentTimeline(
  incidentId: number
): Promise<IncidentTimelineResponse> {
  const res = await apiFetch(`/incidents/${incidentId}/timeline`);
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerIncidentCorrelation(): Promise<CorrelateIncidentsResponse> {
  const res = await apiFetch("/incidents/correlate", {
    method: "POST",
  });
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {}
    throw new Error(`Failed to trigger incident correlation: ${errorDetail}`);
  }
  return res.json();
}

// ============================================================================
// Milestone 4 — Investigation Workspace, Threat Hunting & Attack-Path Client
// ============================================================================

export async function fetchInvestigationDossier(
  incidentId: number
): Promise<InvestigationDossier> {
  const res = await apiFetch(`/investigations/${incidentId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation dossier for #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchAttackPath(
  incidentId: number
): Promise<AttackPathReconstruction> {
  const res = await apiFetch(`/investigations/${incidentId}/attack-path`);
  if (!res.ok) {
    throw new Error(`Failed to fetch attack path for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchUnifiedHostGraph(
  incidentId: number
): Promise<any> {
  const res = await apiFetch(`/investigations/${incidentId}/host-graph`);
  if (!res.ok) {
    throw new Error(`Failed to fetch unified host graph for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchHostTelemetryGraph(
  host: string,
  limit: number = 200
): Promise<any> {
  const res = await apiFetch(`/investigations/hosts/${encodeURIComponent(host)}/graph?limit=${limit}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch host telemetry graph for host ${host}: ${res.statusText}`);
  }
  return res.json();
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description?: string;
  reference_url: string;
}

export interface HostThreatStage {
  stage_id: string;
  tactic: string;
  technique?: MitreTechnique;
  timestamp: string;
  summary: string;
  event_ids: string[];
  alert_ids: number[];
  entity_keys: string[];
  epistemic_certainty: string;
  severity: string;
}

export interface HostAttackSequence {
  sequence_id: string;
  host: string;
  scenario_name: string;
  first_seen: string;
  last_seen: string;
  stages: HostThreatStage[];
  threat_score: number;
  escalated_severity: string;
  epistemic_confidence: number;
  participating_users: string[];
  participating_processes: string[];
  external_ips: string[];
}

export interface HostThreatAssessment {
  host: string;
  incident_id?: number;
  assessed_at: string;
  overall_threat_score: number;
  overall_severity: string;
  primary_scenario: string;
  epistemic_confidence: number;
  attack_sequences: HostAttackSequence[];
  mitre_tactics_observed: string[];
  mitre_techniques_observed: MitreTechnique[];
  telemetry_source_diversity: number;
  summary: string;
  node_count: number;
  edge_count: number;
}

export async function fetchHostDetectionRules(): Promise<{ items: any[]; total: number }> {
  const res = await apiFetch("/detection/host-rules");
  if (!res.ok) {
    throw new Error(`Failed to fetch host detection rules: ${res.statusText}`);
  }
  return res.json();
}

export async function evaluateHostThreats(
  host: string,
  limit: number = 200,
  events?: any[],
  alerts?: any[]
): Promise<HostThreatAssessment> {
  const res = await apiFetch("/correlation/host-threats/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ host, limit, events, alerts }),
  });
  if (!res.ok) {
    throw new Error(`Failed to evaluate host threats for ${host}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchHostThreatAssessment(
  incidentId: number
): Promise<HostThreatAssessment> {
  const res = await apiFetch(`/correlation/host-threats/${incidentId}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch host threat assessment for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export interface ScenarioEmulationResult {
  scenario_type: string;
  scenario_name: string;
  host: string;
  events_generated: number;
  detections_triggered: number;
  rule_ids_triggered: string[];
  attack_sequences_detected: number;
  primary_scenario_identified: string;
  mitre_tactics: string[];
  mitre_techniques: string[];
  overall_threat_score: number;
  overall_severity: string;
  epistemic_confidence: number;
  graph_node_count: number;
  graph_edge_count: number;
  elapsed_ms: number;
  passed: boolean;
}

export interface HostValidationReport {
  host: string;
  platform: string;
  kernel_version: string;
  live_sources_available: Record<string, boolean>;
  scenario_results: ScenarioEmulationResult[];
  total_scenarios: number;
  passed_scenarios: number;
  overall_passed: boolean;
  timestamp: string;
  summary: string;
}

export async function fetchHostValidationReport(): Promise<HostValidationReport> {
  const res = await apiFetch("/system/host-validation");
  if (!res.ok) {
    throw new Error(`Failed to fetch host validation report: ${res.statusText}`);
  }
  return res.json();
}

export async function emulateHostScenario(
  scenarioType: string,
  host: string = "prod-linux-01"
): Promise<ScenarioEmulationResult> {
  const res = await apiFetch("/system/host-validation/emulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_type: scenarioType, host }),
  });
  if (!res.ok) {
    throw new Error(`Failed to emulate host scenario ${scenarioType}: ${res.statusText}`);
  }
  return res.json();
}



export async function fetchMitreMappings(
  incidentId: number
): Promise<{ incident_id: number; items: MitreMapping[]; total: number }> {
  const res = await apiFetch(`/investigations/${incidentId}/mitre`);
  if (!res.ok) {
    throw new Error(`Failed to fetch MITRE mappings for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchInvestigationNotes(
  incidentId: number,
  includeDeleted: boolean = false
): Promise<{ incident_id: number; items: InvestigationNote[]; total: number }> {
  const query = includeDeleted ? "?include_deleted=true" : "";
  const res = await apiFetch(`/investigations/${incidentId}/notes${query}`);
  if (!res.ok) {
    throw new Error(`Failed to fetch notes for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchInvestigationNotesAudit(
  incidentId: number
): Promise<{ incident_id: number; items: InvestigationNoteAudit[]; total: number }> {
  const res = await apiFetch(`/investigations/${incidentId}/notes/audit`);
  if (!res.ok) {
    throw new Error(`Failed to fetch notes audit trail for incident #${incidentId}: ${res.statusText}`);
  }
  return res.json();
}

export async function createInvestigationNote(
  incidentId: number,
  req: CreateNoteRequest
): Promise<InvestigationNote> {
  const res = await apiFetch(`/investigations/${incidentId}/notes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {}
    throw new Error(`Failed to add investigation note: ${errorDetail}`);
  }
  return res.json();
}

export async function deleteInvestigationNote(
  noteId: number,
  actor?: string,
  reason?: string
): Promise<{ deleted: boolean; note_id: number; tombstoned?: boolean }> {
  const params = new URLSearchParams();
  if (actor) params.set("actor", actor);
  if (reason) params.set("reason", reason);
  const qs = params.toString() ? `?${params.toString()}` : "";
  const res = await apiFetch(`/investigations/notes/${noteId}${qs}`, {
    method: "DELETE",
  });
  if (!res.ok) {
    throw new Error(`Failed to delete note #${noteId}: ${res.statusText}`);
  }
  return res.json();
}

export async function inspectEventForensics(
  eventId: string
): Promise<EventForensics> {
  const res = await apiFetch(`/investigations/events/${eventId}/inspect`);
  if (!res.ok) {
    throw new Error(`Failed to inspect event forensics for ${eventId}: ${res.statusText}`);
  }
  return res.json();
}

export async function inspectEntityPivot(
  entityKey: string,
  incidentId?: number
): Promise<EntityPivotSummary> {
  const query = incidentId ? `?incident_id=${incidentId}` : "";
  const res = await apiFetch(`/investigations/entities/${encodeURIComponent(entityKey)}/pivot${query}`);
  if (!res.ok) {
    throw new Error(`Failed to inspect entity pivot for ${entityKey}: ${res.statusText}`);
  }
  return res.json();
}

export async function executeThreatHunt(
  filter: ThreatHuntFilter
): Promise<ThreatHuntResponse> {
  const res = await apiFetch("/investigations/hunt", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(filter),
  });
  if (!res.ok) {
    let errorDetail = res.statusText;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {}
    throw new Error(`Threat hunt query failed: ${errorDetail}`);
  }
  return res.json();
}

export async function exportInvestigationReport(
  incidentId: number,
  format: "markdown" | "json" | "csv" = "markdown"
): Promise<ExportInvestigationResponse> {
  const res = await apiFetch(`/investigations/${incidentId}/export?format=${format}`);
  if (!res.ok) {
    throw new Error(`Failed to export investigation report: ${res.statusText}`);
  }
  return res.json();
}

// Aliases for M4 investigation components
export const createIncidentNote = createInvestigationNote;
export const deleteIncidentNote = deleteInvestigationNote;
export const exportInvestigation = exportInvestigationReport;
export const fetchIncidentAttackPath = fetchAttackPath;
export const fetchIncidentMitre = async (id: number): Promise<MitreMapping[]> => {
  const res = await fetchMitreMappings(id);
  return res.items;
};
export const fetchIncidentNotes = async (id: number): Promise<InvestigationNote[]> => {
  const res = await fetchInvestigationNotes(id);
  return res.items;
};
export const huntEvents = executeThreatHunt;

// -------------------------------------------------------------------------
// M5.3 AI Investigation Intelligence API Client
// -------------------------------------------------------------------------

export async function getAIStatus(): Promise<AIStatusResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/status`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch AI subsystem status: ${res.statusText}`);
  }
  return res.json();
}

export async function analyzeInvestigationWithAI(
  incidentId: number,
  task?: string,
  sessionId?: string,
  strictCitations = true,
): Promise<AIInvestigationResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      task: task || null,
      session_id: sessionId || null,
      strict_citations: strictCitations,
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const message = errorData.detail?.message || errorData.detail || res.statusText;
    throw new Error(`AI investigation analysis failed: ${message}`);
  }
  return res.json();
}

export async function askInvestigationQuestion(
  incidentId: number,
  question: string,
  sessionId?: string,
  strictCitations = true,
): Promise<AIInvestigationResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/question`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      question,
      session_id: sessionId || null,
      strict_citations: strictCitations,
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const message = errorData.detail?.message || errorData.detail || res.statusText;
    throw new Error(`AI investigation question failed: ${message}`);
  }
  return res.json();
}

export async function getInvestigationEvidenceBundle(
  incidentId: number,
  targetEntity?: string,
  intent?: string,
): Promise<InvestigationEvidenceBundle> {
  const token = await getEngineToken();
  const params = new URLSearchParams();
  if (targetEntity) params.append("target_entity", targetEntity);
  if (intent) params.append("intent", intent);

  const url = `${API_BASE}/ai/investigations/${incidentId}/evidence${params.toString() ? `?${params.toString()}` : ""}`;
  const res = await fetch(url, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence bundle: ${res.statusText}`);
  }
  return res.json();
}

export async function getInvestigationEvidenceCoverage(
  incidentId: number,
): Promise<EvidenceCoverage> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/coverage`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence coverage: ${res.statusText}`);
  }
  return res.json();
}

export async function previewInvestigationQuery(
  incidentId: number,
  proposal: Partial<QueryProposal>,
): Promise<QueryPreviewResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/query/preview`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(proposal),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const message = errorData.detail?.message || errorData.detail || res.statusText;
    throw new Error(`Query preview failed: ${message}`);
  }
  return res.json();
}

export async function getInvestigationWorkspace(
  incidentId: number
): Promise<InvestigationWorkspace> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/workspace`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation workspace: ${res.statusText}`);
  }
  return res.json();
}

export async function updateInvestigationState(
  incidentId: number,
  state: string,
  actor: string = "SecAnalyst-1",
  reason?: string
): Promise<InvestigationWorkspace> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/state`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ state, actor, reason }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    const msg = errorData.detail || res.statusText;
    throw new Error(`Failed to update investigation state: ${msg}`);
  }
  return res.json();
}

export async function updateInvestigationScope(
  incidentId: number,
  scope: InvestigationScope
): Promise<InvestigationWorkspace> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/scope`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(scope),
  });
  if (!res.ok) {
    throw new Error(`Failed to update investigation scope: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchInvestigationHypotheses(
  incidentId: number
): Promise<{ investigation_id: number; items: AnalystHypothesis[]; total: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/hypotheses`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch hypotheses: ${res.statusText}`);
  }
  return res.json();
}

export async function createInvestigationHypothesis(
  incidentId: number,
  req: {
    statement: string;
    status?: string;
    supporting_tags?: string[];
    contradicting_tags?: string[];
    gaps?: string[];
    assessment?: string;
    author?: string;
  }
): Promise<AnalystHypothesis> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/hypotheses`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(`Failed to create hypothesis: ${errorData.detail || res.statusText}`);
  }
  return res.json();
}

export async function updateInvestigationHypothesis(
  incidentId: number,
  hypothesisId: string,
  req: {
    status?: string;
    assessment?: string;
    supporting_tags?: string[];
    contradicting_tags?: string[];
    gaps?: string[];
  }
): Promise<AnalystHypothesis> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/hypotheses/${hypothesisId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(`Failed to update hypothesis: ${errorData.detail || res.statusText}`);
  }
  return res.json();
}

export async function executeApprovedInvestigationQuery(
  incidentId: number,
  proposal: Partial<QueryProposal>
): Promise<any> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/query/execute`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(proposal),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(`Query execution failed: ${errorData.detail || res.statusText}`);
  }
  return res.json();
}

export async function fetchInvestigationSummary(
  incidentId: number
): Promise<InvestigationSummary> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/summary`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation summary: ${res.statusText}`);
  }
  return res.json();
}

export async function generateInvestigationReportDraft(
  incidentId: number
): Promise<ReportDraft> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/report/draft`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to generate report draft: ${res.statusText}`);
  }
  return res.json();
}

export async function traceClaimExplainability(
  incidentId: number,
  claimText: string,
  citationTags: string[]
): Promise<{ incident_id: number; claim_text: string; traces: ClaimTrace[] }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/ai/investigations/${incidentId}/explainability`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ claim_text: claimText, citation_tags: citationTags }),
  });
  if (!res.ok) {
    throw new Error(`Failed to trace claim explainability: ${res.statusText}`);
  }
  return res.json();
}

// -------------------------------------------------------------
// M5.5 Investigation Case Continuity & Handoff API Client
// -------------------------------------------------------------

export async function fetchCases(
  status?: string,
  limit: number = 50
): Promise<InvestigationCase[]> {
  const token = await getEngineToken();
  const params = new URLSearchParams();
  if (status) params.append("status", status);
  if (limit) params.append("limit", limit.toString());

  const res = await fetch(`${API_BASE}/cases?${params.toString()}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation cases: ${res.statusText}`);
  }
  return res.json();
}

export async function createOrOpenCase(
  incidentId: number,
  title?: string,
  description?: string
): Promise<InvestigationCase> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      incident_id: incidentId,
      title,
      description,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to open/create investigation case: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCase(caseId: number): Promise<InvestigationCase> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case ${caseId}: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCaseStatus(
  caseId: number,
  targetStatus: CaseStatus,
  reason?: string
): Promise<InvestigationCase> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/state`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      target_status: targetStatus,
      reason,
    }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(`Failed to update case state: ${errorData.detail || res.statusText}`);
  }
  return res.json();
}

export async function updateCaseScope(
  caseId: number,
  scope: InvestigationScope
): Promise<InvestigationCase> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/scope`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(scope),
  });
  if (!res.ok) {
    throw new Error(`Failed to update case scope: ${res.statusText}`);
  }
  return res.json();
}

export async function handoffCase(
  caseId: number,
  newOwner: string,
  handoffNotes?: string
): Promise<InvestigationCase> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/handoff`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      new_owner: newOwner,
      handoff_notes: handoffNotes,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to handoff case: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseHypotheses(caseId: number): Promise<CaseHypothesis[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch hypotheses: ${res.statusText}`);
  }
  return res.json();
}

export async function createCaseHypothesis(
  caseId: number,
  statement: string,
  tags?: string[]
): Promise<CaseHypothesis> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      statement,
      supporting_evidence_tags: tags || [],
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to create hypothesis: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCaseHypothesis(
  caseId: number,
  hypothesisId: string,
  updates: Partial<CaseHypothesis>
): Promise<CaseHypothesis> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/${hypothesisId}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(updates),
  });
  if (!res.ok) {
    throw new Error(`Failed to update hypothesis: ${res.statusText}`);
  }
  return res.json();
}

export async function addCaseEvidenceReference(
  caseId: number,
  ref: {
    source_type: string;
    source_id: string;
    role?: string;
    epistemic_status?: string;
    citation_tag: string;
    analyst_annotation?: string;
  }
): Promise<CaseEvidenceReference> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(ref),
  });
  if (!res.ok) {
    throw new Error(`Failed to add evidence reference: ${res.statusText}`);
  }
  return res.json();
}

export async function removeCaseEvidenceReference(
  caseId: number,
  referenceId: string
): Promise<{ status: string; reference_id: string }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/${referenceId}`, {
    method: "DELETE",
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to remove evidence reference: ${res.statusText}`);
  }
  return res.json();
}

export async function executeCaseApprovedQuery(
  caseId: number,
  proposal: QueryProposal
): Promise<any> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/queries/execute`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(proposal),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(`Case query execution failed: ${errorData.detail || res.statusText}`);
  }
  return res.json();
}

export async function generateCaseReportDraft(
  caseId: number,
  title?: string
): Promise<CaseReportVersion> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ title }),
  });
  if (!res.ok) {
    throw new Error(`Failed to generate case report draft: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseReports(caseId: number): Promise<CaseReportVersion[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case reports: ${res.statusText}`);
  }
  return res.json();
}

export async function compareCaseReportVersions(
  caseId: number,
  v1: number,
  v2: number
): Promise<{
  case_id: number;
  version_a: number;
  version_b: number;
  summary_diff: string[];
  facts_added: string[];
  facts_removed: string[];
  recommendations_diff: string[];
}> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/compare?v1=${v1}&v2=${v2}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to compare report versions: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseAuditLog(caseId: number): Promise<CaseAuditRecord[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/audit`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case audit log: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseAIContext(caseId: number): Promise<any> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/ai-context`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch reconstructed AI context: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseFindings(caseId: number): Promise<{ case_id: number; findings: InvestigationFinding[]; correlations: InvestigationCorrelation[] }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case findings: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseCorrelations(caseId: number): Promise<InvestigationCorrelation[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlations`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case correlations: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseTimeline(caseId: number): Promise<CaseTimelineItem[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case timeline: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseEvidenceGaps(caseId: number): Promise<EvidenceGap[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence-gaps`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence gaps: ${res.statusText}`);
  }
  return res.json();
}

export async function resolveEntityPivot(
  caseId: number,
  entityType: string,
  entityValue: string
): Promise<EntityPivotAnalysis> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/pivots/${encodeURIComponent(entityType)}/${encodeURIComponent(entityValue)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to resolve entity pivot: ${res.statusText}`);
  }
  return res.json();
}

export async function createThreatHuntProposal(
  caseId: number,
  templateId: string,
  parameters: Record<string, any>,
  rationale: string,
  actor: string = "SecAnalyst-1"
): Promise<GovernedThreatHuntProposal> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunt/proposals`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      template_id: templateId,
      parameters,
      rationale,
      actor,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to create threat hunt proposal: ${res.statusText}`);
  }
  return res.json();
}

export async function executeCaseThreatHunt(
  caseId: number,
  proposal: GovernedThreatHuntProposal,
  approvedBy: string = "SecAnalyst-1"
): Promise<GovernedThreatHuntExecution> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunt/execute`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      proposal,
      approved_by: approvedBy,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to execute threat hunt: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchHypothesisAnalysis(
  caseId: number,
  hypothesisId: string
): Promise<HypothesisEvidenceAnalysis> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/${encodeURIComponent(hypothesisId)}/analysis`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch hypothesis analysis: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseIntelligenceDossier(caseId: number): Promise<CaseIntelligenceDossier> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/intelligence`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case intelligence dossier: ${res.statusText}`);
  }
  return res.json();
}

export async function generateCaseIntelligenceSynthesis(
  caseId: number,
  actor: string = "SecAnalyst-1"
): Promise<InvestigationIntelligenceResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/intelligence/synthesis`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ actor }),
  });
  if (!res.ok) {
    throw new Error(`Failed to generate case intelligence synthesis: ${res.statusText}`);
  }
  return res.json();
}

// ==========================================
// M5.7 — Investigation Dossier & Operations
// ==========================================

export async function getInvestigationDossier(
  caseId: number
): Promise<CaseInvestigationDossier> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/dossier`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation dossier: ${res.statusText}`);
  }
  return res.json();
}

export async function updateFindingReview(
  caseId: number,
  findingId: string,
  req: FindingReviewUpdateRequest
): Promise<Record<string, any>> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings/${encodeURIComponent(findingId)}/review`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    throw new Error(`Failed to update finding review: ${res.statusText}`);
  }
  return res.json();
}

export async function getEvidenceMatrix(
  caseId: number
): Promise<EvidenceMatrixEntry[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence-matrix`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence matrix: ${res.statusText}`);
  }
  return res.json();
}

export async function getEvidenceGapActions(
  caseId: number
): Promise<EvidenceGapAction[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence-gaps/actions`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence gap actions: ${res.statusText}`);
  }
  return res.json();
}

export async function getRefinedTimeline(
  caseId: number
): Promise<RefinedTimelineItem[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/intelligence`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch refined timeline: ${res.statusText}`);
  }
  return res.json();
}

export async function getCaseBriefing(
  caseId: number
): Promise<CaseBriefing> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/briefing`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case briefing: ${res.statusText}`);
  }
  return res.json();
}

export async function getProvenanceManifest(
  caseId: number
): Promise<ProvenanceManifestEntry[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/provenance`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch provenance manifest: ${res.statusText}`);
  }
  return res.json();
}

export async function getGovernedThreatHuntResults(
  caseId: number
): Promise<Array<Record<string, any>>> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunt-results`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch threat hunt results: ${res.statusText}`);
  }
  return res.json();
}

export async function draftReportFromDossier(
  caseId: number,
  req?: ReportDraftRequest
): Promise<CaseReportVersion> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/report/draft`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req || {}),
  });
  if (!res.ok) {
    throw new Error(`Failed to draft report from dossier: ${res.statusText}`);
  }
  return res.json();
}

// -------------------------------------------------------------------------
// Milestone 5.8: Investigation Graph & Evidence Relationship Intelligence
// -------------------------------------------------------------------------

export async function fetchCaseInvestigationGraph(
  caseId: number,
  params?: {
    max_nodes?: number;
    max_edges?: number;
    entity_type?: string;
    relationship_type?: string;
    epistemic_status?: string;
    start_time?: string;
    end_time?: string;
  }
): Promise<InvestigationGraph> {
  const token = await getEngineToken();
  const query = new URLSearchParams();
  if (params?.max_nodes !== undefined) query.set("max_nodes", String(params.max_nodes));
  if (params?.max_edges !== undefined) query.set("max_edges", String(params.max_edges));
  if (params?.entity_type) query.set("entity_type", params.entity_type);
  if (params?.relationship_type) query.set("relationship_type", params.relationship_type);
  if (params?.epistemic_status) query.set("epistemic_status", params.epistemic_status);
  if (params?.start_time) query.set("start_time", params.start_time);
  if (params?.end_time) query.set("end_time", params.end_time);

  const qs = query.toString() ? `?${query.toString()}` : "";
  const res = await fetch(`${API_BASE}/cases/${caseId}/graph${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation graph: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseGraphNodeDetail(
  caseId: number,
  nodeId: string
): Promise<{ node: InvestigationGraphNode; connected_edges: InvestigationGraphEdge[]; total_connected_edges: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/graph/nodes/${encodeURIComponent(nodeId)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch graph node detail: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseGraphEdgeEvidence(
  caseId: number,
  edgeId: string
): Promise<{
  edge: InvestigationGraphEdge;
  evidence_references: Array<Record<string, any>>;
  evidence_event_ids: string[];
  corroboration_status: string;
  epistemic_status: string;
  is_authoritative: boolean;
}> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/graph/edges/${encodeURIComponent(edgeId)}/evidence`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch graph edge evidence: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseEntityPivotGraph(
  caseId: number,
  entityType: string,
  entityValue: string
): Promise<EntityPivotGraph> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/graph/pivots/${encodeURIComponent(entityType)}/${encodeURIComponent(entityValue)}`,
    {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch entity pivot graph: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseInvestigationPath(
  caseId: number,
  source: string,
  target: string,
  maxDepth = 5
): Promise<InvestigationPath> {
  const token = await getEngineToken();
  const query = new URLSearchParams({
    source,
    target,
    max_depth: String(maxDepth),
  });
  const res = await fetch(`${API_BASE}/cases/${caseId}/graph/paths?${query.toString()}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch investigation path: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseGraphTemporalChain(caseId: number): Promise<TemporalChain> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/graph/temporal-chain`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch temporal chain: ${res.statusText}`);
  }
  return res.json();
}

export async function explainCaseGraphRelationship(
  caseId: number,
  req?: GraphExplanationRequest
): Promise<GraphExplanationResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/graph/explain`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req || {}),
  });
  if (!res.ok) {
    throw new Error(`Failed to explain graph relationship: ${res.statusText}`);
  }
  return res.json();
}

export async function exportCaseInvestigationGraph(
  caseId: number,
  format = "json"
): Promise<{ case_id: number; format: string; content: string }> {
  const token = await getEngineToken();
  const query = new URLSearchParams({ format });
  const res = await fetch(`${API_BASE}/cases/${caseId}/graph/export?${query.toString()}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to export investigation graph: ${res.statusText}`);
  }
  return res.json();
}

// ---------------------------------------------------------------------------
// M5.9 Evidence Correlation & Investigation Intelligence API Functions
// ---------------------------------------------------------------------------

export async function fetchEvidenceClusters(
  caseId: number,
  clusterType?: string
): Promise<{ case_id: number; clusters: EvidenceCluster[]; total_clusters: number }> {
  const token = await getEngineToken();
  const query = new URLSearchParams();
  if (clusterType) query.set("cluster_type", clusterType);
  const qs = query.toString() ? `?${query.toString()}` : "";
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/clusters${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence clusters: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvidenceClusterDetail(
  caseId: number,
  clusterId: string
): Promise<{ cluster: EvidenceCluster; related_findings: any[]; related_entities: any[] }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/clusters/${encodeURIComponent(clusterId)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch cluster detail: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchBehavioralSequences(
  caseId: number
): Promise<{ case_id: number; sequences: BehavioralSequence[]; total_sequences: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/sequences`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch behavioral sequences: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchHypothesisCorrelationSupport(
  caseId: number,
  hypothesisId: string
): Promise<HypothesisSupportDetail> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/hypotheses/${encodeURIComponent(hypothesisId)}/support`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch hypothesis correlation support: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCorrelationEvidenceGaps(
  caseId: number
): Promise<{ case_id: number; gaps: EvidenceGapDetail[]; total_gaps: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/gaps`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch correlation evidence gaps: ${res.statusText}`);
  }
  return res.json();
}

export async function generateFindingsFromClusters(
  caseId: number,
  clusterIds?: string[]
): Promise<{ case_id: number; generated_count: number; findings: any[] }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/findings/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(clusterIds ? { cluster_ids: clusterIds } : {}),
  });
  if (!res.ok) {
    throw new Error(`Failed to generate findings from clusters: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEntityWorkbenchDossier(
  caseId: number,
  entityType: string,
  entityValue: string
): Promise<EntityWorkbenchDossier> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/correlation/workbench/${encodeURIComponent(entityType)}/${encodeURIComponent(entityValue)}`,
    {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to fetch entity workbench dossier: ${res.statusText}`);
  }
  return res.json();
}

export async function explainCorrelationCluster(
  caseId: number,
  req: CorrelationExplanationRequest
): Promise<CorrelationExplanationResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/correlation/explain`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    throw new Error(`Failed to explain correlation cluster: ${res.statusText}`);
  }
  return res.json();
}

// ============================================================================
// Milestone 5.10: Temporal Investigation Reconstruction & Campaign Correlation
// ============================================================================

export async function fetchTemporalReconstruction(
  caseId: number,
  params?: {
    max_events?: number;
    max_episodes?: number;
    max_transitions?: number;
  }
): Promise<TemporalReconstructionDossier> {
  const token = await getEngineToken();
  const query = new URLSearchParams();
  if (params?.max_events !== undefined) query.set("max_events", String(params.max_events));
  if (params?.max_episodes !== undefined) query.set("max_episodes", String(params.max_episodes));
  if (params?.max_transitions !== undefined) query.set("max_transitions", String(params.max_transitions));
  const qs = query.toString() ? `?${query.toString()}` : "";
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/reconstruction${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch temporal reconstruction: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTemporalEpisodes(
  caseId: number,
  episodeType?: string
): Promise<{ case_id: number; episodes: TemporalEpisode[]; total_episodes: number }> {
  const token = await getEngineToken();
  const query = new URLSearchParams();
  if (episodeType) query.set("episode_type", episodeType);
  const qs = query.toString() ? `?${query.toString()}` : "";
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/episodes${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch temporal episodes: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTemporalTransitions(
  caseId: number,
  params?: {
    transition_type?: string;
    epistemic_status?: string;
  }
): Promise<{ case_id: number; transitions: TemporalTransition[]; total_transitions: number }> {
  const token = await getEngineToken();
  const query = new URLSearchParams();
  if (params?.transition_type) query.set("transition_type", params.transition_type);
  if (params?.epistemic_status) query.set("epistemic_status", params.epistemic_status);
  const qs = query.toString() ? `?${query.toString()}` : "";
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/transitions${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch temporal transitions: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTemporalGaps(
  caseId: number
): Promise<{ case_id: number; gaps: TemporalGap[]; total_gaps: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/gaps`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch temporal gaps: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTemporalSequences(
  caseId: number
): Promise<{ case_id: number; sequences: AttackSequenceReconstruction[]; total_sequences: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/sequences`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch temporal attack sequences: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCampaignCorrelations(
  caseId: number
): Promise<{ case_id: number; correlations: IncidentCampaignCorrelation[]; total_correlations: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/incidents`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch campaign correlations: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchIncidentCampaignRelation(
  caseId: number,
  incidentId: number
): Promise<IncidentCampaignCorrelation> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/incidents/${incidentId}/relations`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch incident campaign relation: ${res.statusText}`);
  }
  return res.json();
}

export async function reviewTemporalTransition(
  caseId: number,
  transitionId: string,
  reviewState: TransitionReviewState,
  reviewer: string,
  notes?: string
): Promise<{ case_id: number; transition_id: string; review_state: string; epistemic_status_preserved: boolean }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/transitions/${encodeURIComponent(transitionId)}/review`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      review_state: reviewState,
      reviewer,
      notes: notes || null,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to review temporal transition: ${res.statusText}`);
  }
  return res.json();
}

export async function explainTemporalReconstruction(
  caseId: number,
  targetId: string,
  question?: string
): Promise<TemporalExplanationResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/explain`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      target_id: targetId,
      question: question || null,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to explain temporal reconstruction: ${res.statusText}`);
  }
  return res.json();
}

export async function exportTemporalReconstruction(
  caseId: number,
  format: "json" | "csv" | "graphml" = "json"
): Promise<{ case_id: number; format: string; content: string }> {
  const token = await getEngineToken();
  const query = new URLSearchParams({ format });
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/export?${query.toString()}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to export temporal reconstruction: ${res.statusText}`);
  }
  return res.json();
}

// -----------------------------------------------------------------------------
// M5.11 Case Assessment & Investigation Closure Client Methods
// -----------------------------------------------------------------------------

export async function getCaseAssessment(caseId: number, refresh: boolean = false): Promise<CaseAssessment> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment?refresh=${refresh}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch case assessment: ${res.statusText}`);
  }
  return res.json();
}

export async function getCaseFindings(caseId: number): Promise<{ case_id: number; findings: StructuredFinding[]; total_findings: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/findings`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch findings: ${res.statusText}`);
  }
  return res.json();
}

export async function reviewCaseFinding(
  caseId: number,
  findingId: string,
  reviewState: FindingReviewState,
  notes: string = "",
  reviewer: string = "SecAnalyst-1"
): Promise<{ review_id: string; case_id: number; finding_id: string; review_state: string; epistemic_status_preserved: boolean }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/findings/${encodeURIComponent(findingId)}/review`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      review_state: reviewState,
      analyst_notes: notes,
      reviewed_by: reviewer,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to review finding: ${res.statusText}`);
  }
  return res.json();
}

export async function getCaseHypotheses(caseId: number): Promise<{ case_id: number; hypotheses: CompetingHypothesisAssessment[]; total_hypotheses: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/hypotheses`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch hypotheses: ${res.statusText}`);
  }
  return res.json();
}

export async function getCaseQuestions(caseId: number): Promise<{ case_id: number; questions: InvestigationQuestion[]; total_questions: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/questions`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch questions: ${res.statusText}`);
  }
  return res.json();
}

export async function createCaseQuestion(
  caseId: number,
  question: string,
  category: string = "AUTHENTICATION",
  relatedEvidence: string[] = [],
  relatedEntities: string[] = [],
  recommendedQuery?: string,
  createdBy: string = "SecAnalyst-1"
): Promise<InvestigationQuestion> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/questions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      question,
      category,
      related_evidence: relatedEvidence,
      related_entities: relatedEntities,
      recommended_query: recommendedQuery || null,
      created_by: createdBy,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to create question: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCaseQuestionStatus(
  caseId: number,
  questionId: string,
  status: string,
  resolutionNotes?: string,
  actor: string = "SecAnalyst-1"
): Promise<InvestigationQuestion> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/questions/${encodeURIComponent(questionId)}/status`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      status,
      resolution_notes: resolutionNotes || null,
      actor,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to update question status: ${res.statusText}`);
  }
  return res.json();
}

export async function getCaseGaps(caseId: number): Promise<{ case_id: number; evidence_gaps: PrioritizedEvidenceGap[]; total_gaps: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/gaps`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence gaps: ${res.statusText}`);
  }
  return res.json();
}

export async function getClosureReadiness(caseId: number): Promise<ClosureReadinessAssessment> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/readiness`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch closure readiness: ${res.statusText}`);
  }
  return res.json();
}

export async function recordAnalystAssessment(
  caseId: number,
  analystAssessment: string,
  actor: string = "SecAnalyst-1"
): Promise<CaseAssessment> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/analyst-assessment`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      analyst_assessment: analystAssessment,
      actor,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to record analyst assessment: ${res.statusText}`);
  }
  return res.json();
}

export async function getInvestigationBriefing(caseId: number): Promise<InvestigationBriefing> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/briefing`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch briefing: ${res.statusText}`);
  }
  return res.json();
}

export async function getCaseHandoff(caseId: number, actor: string = "SecAnalyst-1"): Promise<CaseHandoffPackage> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/handoff?actor=${encodeURIComponent(actor)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch handoff package: ${res.statusText}`);
  }
  return res.json();
}

export async function explainCaseAssessment(
  caseId: number,
  targetId?: string,
  query?: string
): Promise<AssessmentExplanationResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/assessment/explain`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      target_id: targetId || null,
      query: query || null,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to explain assessment: ${res.statusText}`);
  }
  return res.json();
}

// ----------------------------------------------------------------------------
// M7.2 Unified Investigation Timeline & Interactive Evidence Replay
// ----------------------------------------------------------------------------

function buildTimelineQueryString(params?: TimelineFilterParams): string {
  if (!params) return "";
  const query = new URLSearchParams();
  if (params.start_time) query.set("start_time", params.start_time);
  if (params.end_time) query.set("end_time", params.end_time);
  if (params.host) query.set("host", params.host);
  if (params.event_type) query.set("event_type", params.event_type);
  if (params.source_layer) query.set("source_layer", params.source_layer);
  if (params.entity) query.set("entity", params.entity);
  if (params.epistemic_status) query.set("epistemic_status", params.epistemic_status);
  if (params.collection_status) query.set("collection_status", params.collection_status);
  if (params.search_text) query.set("search_text", params.search_text);
  if (params.limit !== undefined) query.set("limit", String(params.limit));
  if (params.offset !== undefined) query.set("offset", String(params.offset));
  const qs = query.toString();
  return qs ? `?${qs}` : "";
}

export async function fetchUnifiedTimeline(
  caseId: number,
  params?: TimelineFilterParams
): Promise<TimelineQueryResponse> {
  const token = await getEngineToken();
  const qs = buildTimelineQueryString(params);
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/unified${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch unified timeline: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTimelineReplay(
  caseId: number,
  params?: TimelineFilterParams
): Promise<TimelineReplaySession> {
  const token = await getEngineToken();
  const qs = buildTimelineQueryString(params);
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/replay${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline replay session: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTimelineContext(
  caseId: number,
  timelineId: string
): Promise<TimelineContextResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/context/${encodeURIComponent(timelineId)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch timeline context: ${res.statusText}`);
  }
  return res.json();
}

export async function bookmarkTimelineItem(
  caseId: number,
  timelineId: string,
  annotation?: string
): Promise<{ success: boolean; bookmark_ref_id: string }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/${encodeURIComponent(timelineId)}/bookmark`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ annotation: annotation || "Bookmarked from timeline" }),
  });
  if (!res.ok) {
    throw new Error(`Failed to bookmark timeline item: ${res.statusText}`);
  }
  return res.json();
}

export async function removeTimelineBookmark(
  caseId: number,
  timelineId: string
): Promise<{ success: boolean }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/${encodeURIComponent(timelineId)}/bookmark`, {
    method: "DELETE",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to remove timeline bookmark: ${res.statusText}`);
  }
  return res.json();
}

export async function exportUnifiedTimeline(
  caseId: number,
  format: "json" | "csv" = "json",
  params?: TimelineFilterParams
): Promise<string> {
  const token = await getEngineToken();
  const baseParams = params ? { ...params } : {};
  const qsObj = new URLSearchParams();
  qsObj.set("format", format);
  if (baseParams.start_time) qsObj.set("start_time", baseParams.start_time);
  if (baseParams.end_time) qsObj.set("end_time", baseParams.end_time);
  if (baseParams.host) qsObj.set("host", baseParams.host);
  if (baseParams.event_type) qsObj.set("event_type", baseParams.event_type);
  if (baseParams.source_layer) qsObj.set("source_layer", baseParams.source_layer);
  if (baseParams.entity) qsObj.set("entity", baseParams.entity);
  if (baseParams.epistemic_status) qsObj.set("epistemic_status", baseParams.epistemic_status);
  if (baseParams.collection_status) qsObj.set("collection_status", baseParams.collection_status);
  if (baseParams.search_text) qsObj.set("search_text", baseParams.search_text);
  if (baseParams.limit !== undefined) qsObj.set("limit", String(baseParams.limit));

  const res = await fetch(`${API_BASE}/cases/${caseId}/timeline/unified/export?${qsObj.toString()}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to export timeline: ${res.statusText}`);
  }
  return res.text();
}

// ----------------------------------------------------------------------------
// M7.3 Logical Evidence Collections & Evidence Workbench API Methods
// ----------------------------------------------------------------------------

export async function fetchCaseCollections(
  caseId: number,
  params?: CollectionFilterParams
): Promise<EvidenceCollection[]> {
  const token = await getEngineToken();
  const query = new URLSearchParams();
  if (params?.status) query.set("status", params.status);
  if (params?.search_text) query.set("search_text", params.search_text);
  if (params?.limit !== undefined) query.set("limit", String(params.limit));
  if (params?.offset !== undefined) query.set("offset", String(params.offset));
  const qs = query.toString() ? `?${query.toString()}` : "";

  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/collections${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch collections: ${res.statusText}`);
  }
  return res.json();
}

export async function createCaseCollection(
  caseId: number,
  req: CreateCollectionRequest
): Promise<EvidenceCollection> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/collections`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    throw new Error(`Failed to create collection: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseCollection(
  caseId: number,
  collectionId: string
): Promise<EvidenceCollection> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/collections/${encodeURIComponent(collectionId)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch collection: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCaseCollection(
  caseId: number,
  collectionId: string,
  req: UpdateCollectionRequest
): Promise<EvidenceCollection> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/collections/${encodeURIComponent(collectionId)}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    throw new Error(`Failed to update collection: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteCaseCollection(
  caseId: number,
  collectionId: string
): Promise<{ success: boolean; deleted_collection_id: string }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/collections/${encodeURIComponent(collectionId)}`, {
    method: "DELETE",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to delete collection: ${res.statusText}`);
  }
  return res.json();
}

export async function addCaseCollectionItem(
  caseId: number,
  collectionId: string,
  req: AddCollectionItemRequest
): Promise<EvidenceCollectionItem> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/evidence/collections/${encodeURIComponent(collectionId)}/items`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(req),
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to add collection item: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCaseCollectionItem(
  caseId: number,
  collectionId: string,
  itemId: string,
  req: UpdateCollectionItemRequest
): Promise<EvidenceCollectionItem> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/evidence/collections/${encodeURIComponent(collectionId)}/items/${encodeURIComponent(itemId)}`,
    {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(req),
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to update collection item: ${res.statusText}`);
  }
  return res.json();
}

export async function removeCaseCollectionItem(
  caseId: number,
  collectionId: string,
  itemId: string
): Promise<{ success: boolean; removed_item_id: string }> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/evidence/collections/${encodeURIComponent(collectionId)}/items/${encodeURIComponent(itemId)}`,
    {
      method: "DELETE",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to remove collection item: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEvidenceWorkbench(
  caseId: number,
  params?: WorkbenchFilterParams
): Promise<EvidenceWorkbenchResponse> {
  const token = await getEngineToken();
  const query = new URLSearchParams();
  if (params?.collection_id) query.set("collection_id", params.collection_id);
  if (params?.source_type) query.set("source_type", params.source_type);
  if (params?.epistemic_status) query.set("epistemic_status", params.epistemic_status);
  if (params?.host) query.set("host", params.host);
  if (params?.search_text) query.set("search_text", params.search_text);
  if (params?.limit !== undefined) query.set("limit", String(params.limit));
  if (params?.offset !== undefined) query.set("offset", String(params.offset));
  const qs = query.toString() ? `?${query.toString()}` : "";

  const res = await fetch(`${API_BASE}/cases/${caseId}/evidence/workbench${qs}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch evidence workbench: ${res.statusText}`);
  }
  return res.json();
}

export async function exportCaseCollection(
  caseId: number,
  collectionId: string,
  format: "json" | "csv" = "json"
): Promise<string> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/evidence/collections/${encodeURIComponent(collectionId)}/export?format=${format}`,
    {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to export collection: ${res.statusText}`);
  }
  return res.text();
}

// -----------------------------------------------------------------------------
// M7.4 Findings & Hypothesis Workbench API Methods
// -----------------------------------------------------------------------------

export async function fetchFindingsWorkbench(caseId: number): Promise<FindingsWorkbenchResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings/workbench`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch findings workbench: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseFindingsM74(caseId: number): Promise<{ case_id: number; findings: Finding[]; total_findings: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch findings: ${res.statusText}`);
  }
  return res.json();
}

export async function createCaseFindingM74(caseId: number, data: Partial<Finding>): Promise<Finding> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    throw new Error(`Failed to create finding: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCaseFindingM74(caseId: number, findingId: string, data: Partial<Finding>): Promise<Finding> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings/${encodeURIComponent(findingId)}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    throw new Error(`Failed to update finding: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteCaseFindingM74(caseId: number, findingId: string): Promise<{ status: string; finding_id: string; evidence_preserved: boolean }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings/${encodeURIComponent(findingId)}`, {
    method: "DELETE",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to delete finding: ${res.statusText}`);
  }
  return res.json();
}

export async function reviewCaseFindingM74(
  caseId: number,
  findingId: string,
  reviewStatus: FindingReviewStatus,
  analystNotes: string = "",
  reviewedBy: string = "SecAnalyst-1"
): Promise<Finding> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings/${encodeURIComponent(findingId)}/review`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({
      review_status: reviewStatus,
      analyst_notes: analystNotes,
      reviewed_by: reviewedBy,
    }),
  });
  if (!res.ok) {
    throw new Error(`Failed to review finding: ${res.statusText}`);
  }
  return res.json();
}

export async function addFindingEvidenceM74(
  caseId: number,
  findingId: string,
  evidenceData: Record<string, any>
): Promise<Finding> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings/${encodeURIComponent(findingId)}/evidence`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(evidenceData),
  });
  if (!res.ok) {
    throw new Error(`Failed to add finding evidence: ${res.statusText}`);
  }
  return res.json();
}

export async function removeFindingEvidenceM74(
  caseId: number,
  findingId: string,
  sourceId: string
): Promise<Finding> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/findings/${encodeURIComponent(findingId)}/evidence/${encodeURIComponent(sourceId)}`,
    {
      method: "DELETE",
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    }
  );
  if (!res.ok) {
    throw new Error(`Failed to remove finding evidence: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchHypothesesWorkbenchM74(caseId: number): Promise<{ case_id: number; hypotheses: HypothesisAssessmentView[]; total_hypotheses: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/workbench`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to fetch hypotheses: ${res.statusText}`);
  }
  return res.json();
}

export async function compareHypothesesM74(caseId: number): Promise<HypothesisComparisonResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/compare`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to compare hypotheses: ${res.statusText}`);
  }
  return res.json();
}

export async function createHypothesisM74(caseId: number, data: Record<string, any>): Promise<HypothesisAssessmentView> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/m74`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    throw new Error(`Failed to create hypothesis: ${res.statusText}`);
  }
  return res.json();
}

export async function updateHypothesisM74(caseId: number, hypothesisId: string, data: Record<string, any>): Promise<HypothesisAssessmentView> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/m74/${encodeURIComponent(hypothesisId)}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    throw new Error(`Failed to update hypothesis: ${res.statusText}`);
  }
  return res.json();
}

export async function deleteHypothesisM74(caseId: number, hypothesisId: string): Promise<{ status: string; hypothesis_id: string; evidence_preserved: boolean }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/m74/${encodeURIComponent(hypothesisId)}`, {
    method: "DELETE",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to delete hypothesis: ${res.statusText}`);
  }
  return res.json();
}

export async function addHypothesisGapM74(caseId: number, hypothesisId: string, data: Record<string, any>): Promise<HypothesisAssessmentView> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hypotheses/${encodeURIComponent(hypothesisId)}/gaps`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    throw new Error(`Failed to add hypothesis gap: ${res.statusText}`);
  }
  return res.json();
}

export async function exportFindingsWorkbenchM74(caseId: number, format: "json" | "csv" = "json"): Promise<string> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/findings/export?format=${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    throw new Error(`Failed to export findings workbench: ${res.statusText}`);
  }
  return res.text();
}

// ============================================================================
// M7.5 Threat Hunting & Governed Analyst Query API Client
// ============================================================================

export async function previewThreatHuntM75(caseId: number, proposal: Record<string, any>): Promise<HuntQueryPreview> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/preview`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(proposal),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Preview failed: ${res.statusText}`);
  }
  return res.json();
}

export async function createThreatHuntProposalM75(caseId: number, proposal: Record<string, any>): Promise<{ hunt_id: string; approval_state: string }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(proposal),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Hunt creation failed: ${res.statusText}`);
  }
  return res.json();
}

export async function approveThreatHuntM75(caseId: number, huntId: string, rationale?: string): Promise<{ hunt_id: string; approval_state: string }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/${encodeURIComponent(huntId)}/approve`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ approved_by: "SecAnalyst-1", rationale: rationale || "Analyst approval for bounded execution" }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Approval failed: ${res.statusText}`);
  }
  return res.json();
}

export async function executeThreatHuntM75(caseId: number, huntId: string): Promise<HuntExecutionResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/${encodeURIComponent(huntId)}/execute`, {
    method: "POST",
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Hunt execution failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchHuntDetailM75(caseId: number, huntId: string): Promise<HuntExecutionResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/${encodeURIComponent(huntId)}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch hunt failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseHuntsM75(caseId: number): Promise<HuntHistoryRecord[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch hunt history failed: ${res.statusText}`);
  }
  return res.json();
}

export async function pivotThreatHuntEntityM75(caseId: number, entityType: string, entityValue: string): Promise<HuntExecutionResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/pivot/entity`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ entity_type: entityType, entity_value: entityValue }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Entity pivot failed: ${res.statusText}`);
  }
  return res.json();
}

export async function pivotThreatHuntTemporalM75(caseId: number, anchorTimestamp: string, windowMinutes: number = 15, direction: string = "around"): Promise<HuntExecutionResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/pivot/temporal`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ anchor_timestamp: anchorTimestamp, window_minutes: windowMinutes, direction }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Temporal pivot failed: ${res.statusText}`);
  }
  return res.json();
}

export async function executeSequenceThreatHuntM75(caseId: number, proposal: HuntSequenceProposal): Promise<HuntSequenceResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/sequence`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(proposal),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Sequence hunt failed: ${res.statusText}`);
  }
  return res.json();
}

export async function executeIocThreatHuntM75(caseId: number, iocValue: string, iocType?: string): Promise<HuntExecutionResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/ioc`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ ioc_value: iocValue, ioc_type: iocType }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `IOC hunt failed: ${res.statusText}`);
  }
  return res.json();
}

export async function exportThreatHuntM75(caseId: number, huntId: string, format: "json" | "csv" = "json"): Promise<HuntExportResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/${encodeURIComponent(huntId)}/export?format=${format}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Export hunt failed: ${res.statusText}`);
  }
  return res.json();
}

export async function aiAssistThreatHuntM75(caseId: number, question: string): Promise<GovernedQueryModel> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/ai-assist`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ natural_language_question: question }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `AI proposal failed: ${res.statusText}`);
  }
  return res.json();
}

export async function convertHuntToFindingM75(caseId: number, req: Record<string, any>): Promise<Finding> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/convert/finding`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Convert to finding failed: ${res.statusText}`);
  }
  return res.json();
}

export async function convertHuntToHypothesisM75(caseId: number, req: Record<string, any>): Promise<any> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/convert/hypothesis`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Convert to hypothesis failed: ${res.statusText}`);
  }
  return res.json();
}

export async function convertHuntToCollectionM75(caseId: number, req: Record<string, any>): Promise<any> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/hunts/convert/collection`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Convert to collection failed: ${res.statusText}`);
  }
  return res.json();
}

// =============================================================================
// M7.6 Investigation Reporting, Evidence Package & Case Handoff API Functions
// =============================================================================

export async function createCaseReportM76(
  caseId: number,
  req: {
    title: string;
    objective?: string;
    selected_evidence_ids?: string[];
    selected_collection_ids?: string[];
    selected_finding_ids?: string[];
    selected_hypothesis_ids?: string[];
    selected_hunt_ids?: string[];
    analyst_notes?: string;
  },
  actor: string = "SecAnalyst-1"
): Promise<StructuredReport> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Create report draft failed: ${res.statusText}`);
  }
  return res.json();
}

export async function listCaseReportsM76(
  caseId: number
): Promise<{ case_id: number; versions: ReportVersionSummary[]; total_versions: number }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `List case reports failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getCurrentCaseReportM76(caseId: number): Promise<StructuredReport> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/current`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Get current report failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getCaseReportVersionM76(caseId: number, version: number): Promise<StructuredReport> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/versions/${version}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Get report version failed: ${res.statusText}`);
  }
  return res.json();
}

export async function updateCaseReportDraftM76(
  caseId: number,
  reportId: string,
  req: {
    title?: string;
    executive_summary?: string;
    analyst_interpretation?: string;
    conclusion?: string;
    handoff_instructions?: string;
    recommended_next_actions?: string[];
    limitations?: string[];
  },
  actor: string = "SecAnalyst-1"
): Promise<StructuredReport> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/${reportId}/draft?actor=${encodeURIComponent(actor)}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Update report draft failed: ${res.statusText}`);
  }
  return res.json();
}

export async function submitCaseReportReviewM76(
  caseId: number,
  reportId: string,
  req: { review_notes?: string },
  actor: string = "SecAnalyst-1"
): Promise<StructuredReport> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/${reportId}/submit-review?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Submit report review failed: ${res.statusText}`);
  }
  return res.json();
}

export async function finalizeCaseReportM76(
  caseId: number,
  reportId: string,
  req: { reviewed_by: string; finalization_notes?: string },
  actor: string = "SecAnalyst-1"
): Promise<StructuredReport> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/${reportId}/finalize?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Finalize report failed: ${res.statusText}`);
  }
  return res.json();
}

export async function compareCaseReportsM76(
  caseId: number,
  versionOlder: number,
  versionNewer: number,
  reportId?: string
): Promise<ReportComparisonResult> {
  const token = await getEngineToken();
  const params = new URLSearchParams({
    version_older: String(versionOlder),
    version_newer: String(versionNewer),
  });
  if (reportId) params.append("report_id", reportId);

  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/compare?${params.toString()}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Compare reports failed: ${res.statusText}`);
  }
  return res.json();
}

export async function exportCaseReportM76(
  caseId: number,
  version?: number,
  format: string = "json"
): Promise<ReportExportResponse> {
  const token = await getEngineToken();
  const params = new URLSearchParams({ format });
  if (version !== undefined) params.append("version", String(version));

  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/export?${params.toString()}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Export report failed: ${res.statusText}`);
  }
  return res.json();
}

export async function requestAIReportDraftM76(
  caseId: number,
  req: { section_to_draft: string; custom_guidance?: string },
  actor: string = "SecAnalyst-1"
): Promise<any> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/reports/ai-draft?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `AI draft failed: ${res.statusText}`);
  }
  return res.json();
}

export async function createEvidencePackageM76(
  caseId: number,
  req: { report_version?: number; package_notes?: string } = {},
  actor: string = "SecAnalyst-1"
): Promise<EvidencePackage> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/packages?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Create evidence package failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getEvidencePackageM76(caseId: number, packageId: string): Promise<EvidencePackage> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/packages/${packageId}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Get evidence package failed: ${res.statusText}`);
  }
  return res.json();
}

export async function prepareCaseHandoffM76(
  caseId: number,
  req: {
    target_operator: string;
    report_version?: number;
    operational_notes?: string;
    recommended_next_actions?: string[];
  },
  actor: string = "SecAnalyst-1"
): Promise<CaseHandoffPacket> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/handoff/prepare?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Prepare case handoff failed: ${res.statusText}`);
  }
  return res.json();
}

export async function acknowledgeCaseHandoffM76(
  caseId: number,
  handoffId: string,
  req: { acknowledgement_notes?: string } = {},
  actor: string = "SecAnalyst-2"
): Promise<CaseHandoffPacket> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/handoff/${handoffId}/acknowledge?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Acknowledge case handoff failed: ${res.statusText}`);
  }
  return res.json();
}

export async function returnCaseHandoffM76(
  caseId: number,
  handoffId: string,
  req: { return_reason: string },
  actor: string = "SecAnalyst-2"
): Promise<CaseHandoffPacket> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/handoff/${handoffId}/return?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Return case handoff failed: ${res.statusText}`);
  }
  return res.json();
}

export async function getCurrentCaseHandoffM76(caseId: number): Promise<CaseHandoffPacket> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/handoff/current`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Get current case handoff failed: ${res.statusText}`);
  }
  return res.json();
}

// ----------------------------------------------------------------------------
// M7.7 Case Comparison & Campaign Correlation API Client Methods
// ----------------------------------------------------------------------------

import type {
  CampaignCorrelationCandidate,
  CaseComparisonResult,
  ComparisonAISummaryResponse,
  CreateCaseComparisonRequest,
  ReviewCorrelationRequest,
  SharedEntity,
  TemporalOverlapResult,
} from "../types/investigation";

export async function createCaseComparison(
  caseId: number,
  req: CreateCaseComparisonRequest,
  actor: string = "SecAnalyst-1"
): Promise<CaseComparisonResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/comparison?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Create case comparison failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseComparison(
  caseId: number,
  comparisonId: string,
  actor: string = "SecAnalyst-1"
): Promise<CaseComparisonResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/comparison/${comparisonId}?actor=${encodeURIComponent(actor)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch case comparison failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchComparisonEntities(
  caseId: number,
  comparisonId: string,
  actor: string = "SecAnalyst-1"
): Promise<SharedEntity[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/comparison/${comparisonId}/entities?actor=${encodeURIComponent(actor)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch comparison entities failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchComparisonTimeline(
  caseId: number,
  comparisonId: string,
  actor: string = "SecAnalyst-1"
): Promise<TemporalOverlapResult> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/comparison/${comparisonId}/timeline?actor=${encodeURIComponent(actor)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch comparison timeline failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchComparisonCorrelations(
  caseId: number,
  comparisonId: string,
  actor: string = "SecAnalyst-1"
): Promise<CampaignCorrelationCandidate[]> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/comparison/${comparisonId}/correlations?actor=${encodeURIComponent(actor)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch comparison correlations failed: ${res.statusText}`);
  }
  return res.json();
}

export async function reviewCorrelationCandidate(
  caseId: number,
  comparisonId: string,
  candidateId: string,
  req: ReviewCorrelationRequest,
  actor: string = "SecAnalyst-1"
): Promise<CampaignCorrelationCandidate> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/comparison/${comparisonId}/correlations/${candidateId}/review?actor=${encodeURIComponent(actor)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(req),
    }
  );
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Review correlation candidate failed: ${res.statusText}`);
  }
  return res.json();
}

export async function generateComparisonAISummary(
  caseId: number,
  comparisonId: string,
  req: { prompt_instruction?: string } = {},
  actor: string = "SecAnalyst-1"
): Promise<ComparisonAISummaryResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/comparison/${comparisonId}/ai-summary?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Generate comparison AI summary failed: ${res.statusText}`);
  }
  return res.json();
}

export async function exportCaseComparison(
  caseId: number,
  comparisonId: string,
  format: "json" | "csv" | "markdown" = "json",
  actor: string = "SecAnalyst-1"
): Promise<string> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/comparison/${comparisonId}/export?format=${encodeURIComponent(format)}&actor=${encodeURIComponent(actor)}`,
    {
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }
  );
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Export case comparison failed: ${res.statusText}`);
  }
  return res.text();
}

// ----------------------------------------------------------------------------
// M7.8 Investigation Quality, Closure & Forensic Review API Client
// ----------------------------------------------------------------------------

export async function fetchCaseReview(
  caseId: number,
  actor: string = "SecAnalyst-1"
): Promise<CaseReviewSnapshot> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/review?actor=${encodeURIComponent(actor)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch case review failed: ${res.statusText}`);
  }
  return res.json();
}

export async function runCaseReview(
  caseId: number,
  notes?: string,
  actor: string = "SecAnalyst-1"
): Promise<CaseReviewSnapshot> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/review/run?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify({ notes }),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Run case review failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseReviewBlockers(
  caseId: number,
  severity?: string,
  unresolvedOnly?: boolean,
  actor: string = "SecAnalyst-1"
): Promise<{ case_id: number; total_blockers: number; blockers: ReviewBlocker[] }> {
  const token = await getEngineToken();
  const params = new URLSearchParams();
  if (severity) params.set("severity", severity);
  if (unresolvedOnly) params.set("unresolved_only", "true");
  params.set("actor", actor);

  const res = await fetch(`${API_BASE}/cases/${caseId}/review/blockers?${params.toString()}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch review blockers failed: ${res.statusText}`);
  }
  return res.json();
}

export async function acknowledgeCaseReviewBlocker(
  caseId: number,
  blockerId: string,
  req: AcknowledgeBlockerRequest,
  actor: string = "SecAnalyst-1"
): Promise<CaseReviewSnapshot> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/review/blockers/${encodeURIComponent(blockerId)}/acknowledge?actor=${encodeURIComponent(actor)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(req),
    }
  );
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Acknowledge review blocker failed: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchCaseReviewHistory(
  caseId: number,
  actor: string = "SecAnalyst-1"
): Promise<{ case_id: number; total_records: number; records: any[] }> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/review/history?actor=${encodeURIComponent(actor)}`, {
    headers: {
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Fetch review history failed: ${res.statusText}`);
  }
  return res.json();
}

export async function closeCaseWithReview(
  caseId: number,
  req: CloseCaseRequest,
  actor: string = "SecAnalyst-1"
): Promise<CaseReviewSnapshot> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/review/close?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Close case failed: ${res.statusText}`);
  }
  return res.json();
}

export async function reopenCaseWithReview(
  caseId: number,
  req: ReopenCaseRequest,
  actor: string = "SecAnalyst-1"
): Promise<CaseReviewSnapshot> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/review/reopen?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Reopen case failed: ${res.statusText}`);
  }
  return res.json();
}

export async function generateCaseReviewAISummary(
  caseId: number,
  req: { instructions?: string } = {},
  actor: string = "SecAnalyst-1"
): Promise<AIReviewSummaryResponse> {
  const token = await getEngineToken();
  const res = await fetch(`${API_BASE}/cases/${caseId}/review/ai-summary?actor=${encodeURIComponent(actor)}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Generate review AI summary failed: ${res.statusText}`);
  }
  return res.json();
}

export async function exportCaseReview(
  caseId: number,
  format: "json" | "csv" | "markdown" = "json",
  actor: string = "SecAnalyst-1"
): Promise<string> {
  const token = await getEngineToken();
  const res = await fetch(
    `${API_BASE}/cases/${caseId}/review/export?format=${encodeURIComponent(format)}&actor=${encodeURIComponent(actor)}`,
    {
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }
  );
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Export case review failed: ${res.statusText}`);
  }
  return res.text();
}








