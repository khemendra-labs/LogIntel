export type Severity =
  | "DEBUG"
  | "INFORMATIONAL"
  | "NOTICE"
  | "WARNING"
  | "ALERT"
  | "CRITICAL";

export type Outcome = "SUCCESS" | "FAILURE" | "ATTEMPT" | "UNKNOWN";

export type EventType =
  | "AUTH_LOGIN_SUCCESS"
  | "AUTH_LOGIN_FAILURE"
  | "AUTH_LOGOUT"
  | "SESSION_OPEN"
  | "SESSION_CLOSE"
  | "PRIVILEGE_ELEVATION_ATTEMPT"
  | "PRIVILEGE_ELEVATION_SUCCESS"
  | "PRIVILEGE_ELEVATION_FAILURE"
  | "SUDO_COMMAND"
  | "USER_CREATE"
  | "USER_DELETE"
  | "USER_MODIFY"
  | "GROUP_MODIFY"
  | "SYSTEM_BOOT"
  | "SYSTEM_SHUTDOWN"
  | "KERNEL_MESSAGE"
  | "KERNEL_DEVICE_CHANGE"
  | "SYSTEM_SERVICE_STATE"
  | "SECURITY_ACCESS_DENIED"
  | "SYSTEM_GENERIC"
  | "UNKNOWN";

export interface Actor {
  username?: string | null;
  uid?: number | null;
  session_id?: string | null;
  terminal?: string | null;
}

export interface Process {
  name?: string | null;
  pid?: number | null;
  ppid?: number | null;
  executable?: string | null;
  command_line?: string | null;
}

export interface Network {
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  protocol?: string | null;
}

export interface CanonicalEvent {
  id: string;
  timestamp: string;
  ingested_at: string;
  host: string;
  source: string;
  event_type: EventType;
  severity: Severity;
  actor: Actor;
  process: Process;
  network: Network;
  action?: string | null;
  outcome: Outcome;
  summary: string;
  raw_message: string;
  iocs: string[];
  parser: string;
  source_file?: string | null;
  source_offset?: string | null;
  metadata: Record<string, any>;
}

export interface EventsQueryResponse {
  items: CanonicalEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface SourceHealth {
  name: string;
  source_type: string;
  available: boolean;
  error_reason?: string | null;
  total_records: number;
  last_collected_at?: string | null;
  file_path?: string | null;
  file_size_bytes?: number | null;
  file_permissions?: string | null;
  action_hint?: string | null;
}

export interface TelemetryHealthReport {
  timestamp: string;
  overall_status: "HEALTHY" | "DEGRADED" | "OFFLINE";
  sources: SourceHealth[];
  total_events_in_db: number;
  database_size_bytes: number;
  active_sources_count: number;
  total_sources_count: number;
}

export interface EventStatistics {
  total_events: number;
  window_hours: number;
  window_events: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  by_source: Record<string, number>;
  timeline: Array<{ bucket: string; count: number }>;
  recent_alerts: CanonicalEvent[];
}

export interface SystemStatus {
  app_name: string;
  version: string;
  host: string;
  uptime_seconds: number;
  ingestion_running: boolean;
  database_path: string;
  total_events: number;
}
