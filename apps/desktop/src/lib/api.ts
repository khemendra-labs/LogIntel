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

