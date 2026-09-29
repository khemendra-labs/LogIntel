import {
  CanonicalEvent,
  EventsQueryResponse,
  EventStatistics,
  SystemStatus,
  TelemetryHealthReport,
} from "../types/events";

const API_BASE = "http://127.0.0.1:41721/api/v1";

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
  const res = await fetch(`${API_BASE}/system/status`);
  if (!res.ok) {
    throw new Error(`Failed to fetch system status: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchTelemetryHealth(): Promise<TelemetryHealthReport> {
  const res = await fetch(`${API_BASE}/telemetry/health`);
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

  const res = await fetch(`${API_BASE}/events?${query.toString()}`);
  if (!res.ok) {
    throw new Error(`Failed to query events: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEventDetail(eventId: string): Promise<CanonicalEvent> {
  const res = await fetch(`${API_BASE}/events/${eventId}`);
  if (!res.ok) {
    throw new Error(`Failed to load event details: ${res.statusText}`);
  }
  return res.json();
}

export async function fetchEventStatistics(hours: number = 24): Promise<EventStatistics> {
  const res = await fetch(`${API_BASE}/events/stats/summary?hours=${hours}`);
  if (!res.ok) {
    throw new Error(`Failed to load event statistics: ${res.statusText}`);
  }
  return res.json();
}

export async function triggerIngestionCycle(): Promise<{ status: string; ingested_records: number }> {
  const res = await fetch(`${API_BASE}/ingestion/trigger`, { method: "POST" });
  if (!res.ok) {
    throw new Error(`Failed to trigger ingestion: ${res.statusText}`);
  }
  return res.json();
}
