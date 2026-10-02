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





