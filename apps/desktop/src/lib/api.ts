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


