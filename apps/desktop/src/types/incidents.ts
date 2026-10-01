import { Severity } from "./events";
import type { Alert } from "./detection";

export type IncidentStatus =
  | "OPEN"
  | "INVESTIGATING"
  | "CONTAINED"
  | "RESOLVED"
  | "FALSE_POSITIVE"
  | "CLOSED";

export const ALLOWED_INCIDENT_STATUS_TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  OPEN: ["INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"],
  INVESTIGATING: ["CONTAINED", "RESOLVED", "FALSE_POSITIVE", "OPEN"],
  CONTAINED: ["RESOLVED", "FALSE_POSITIVE", "INVESTIGATING", "OPEN"],
  RESOLVED: ["CLOSED", "OPEN"],
  FALSE_POSITIVE: ["CLOSED", "OPEN"],
  CLOSED: ["OPEN"],
};

export type EntityType =
  | "HOST"
  | "USER"
  | "IP"
  | "PROCESS"
  | "COMMAND"
  | "FILE"
  | "SESSION";

export type ConfidenceLevel =
  | "DIRECT"
  | "STRONG"
  | "CORRELATED"
  | "INFERRED"
  | "WEAK";

export type RelationshipType =
  | "AUTHENTICATED_TO"
  | "ATTEMPTED_LOGIN"
  | "LOGGED_INTO"
  | "DROPPED_BY_FIREWALL"
  | "PROBED_PORT"
  | "CONNECTED_TO"
  | "MATCHED_THREAT_IOC"
  | "EXECUTED"
  | "SPAWNED"
  | "ELEVATED_PRIVILEGE"
  | "ATTEMPTED_PRIVILEGE"
  | "VIOLATED_MAC_POLICY"
  | "CRASHED_PROCESS"
  | "CREATED_ACCOUNT"
  | "DELETED_ACCOUNT"
  | "MODIFIED_ACCOUNT"
  | "ATTRIBUTED_TO"
  | "FLAGGED_ENTITY"
  | "LATERAL_MOVEMENT"
  | "ACCESSED_FILE"
  | "CO_OCCURRED"
  | string;

export type TimelineItemType = "MILESTONE" | "ALERT" | "EVENT";

export interface Incident {
  id: number;
  incident_key: string;
  title: string;
  summary: string;
  severity: Severity;
  status: IncidentStatus;
  primary_host: string;
  primary_user?: string | null;
  first_seen: string;
  last_seen: string;
  alert_count: number;
  event_count: number;
  created_at: string;
  updated_at: string;
  resolved_at?: string | null;
  resolution_note?: string | null;
}

export interface IncidentEntity {
  id?: number | null;
  incident_id: number;
  entity_key: string;
  entity_type: EntityType;
  display_name: string;
  metadata: Record<string, any>;
}

export interface IncidentRelationship {
  id?: number | null;
  incident_id: number;
  source_entity_key: string;
  target_entity_key: string;
  relationship_type: RelationshipType;
  confidence: ConfidenceLevel;
  evidence_event_ids: string[];
  matched_at?: string | null;
}

export interface AttackGraphNode {
  id: string;
  entity_type: EntityType;
  label: string;
  metadata: Record<string, any>;
}

export interface AttackGraphEdge {
  id: string;
  source: string;
  target: string;
  relationship_type: string;
  confidence: ConfidenceLevel;
  evidence_event_ids: string[];
  matched_at?: string | null;
}

export interface AttackGraphResponse {
  incident_id: number;
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
}

export interface TimelineItem {
  id: string;
  timestamp: string;
  item_type: TimelineItemType;
  title: string;
  summary: string;
  severity?: Severity | null;
  entity_keys: string[];
  ref_id?: string | null;
  details: Record<string, any>;
}

export interface IncidentTimelineResponse {
  incident_id: number;
  items: TimelineItem[];
  total: number;
}

export interface IncidentQueryParams {
  status?: IncidentStatus;
  severity?: Severity;
  host?: string;
  user?: string;
  limit?: number;
  offset?: number;
}

export interface IncidentsQueryResponse {
  items: Incident[];
  total: number;
  limit: number;
  offset: number;
}

export interface IncidentDetailResponse {
  incident: Incident;
  alerts: Alert[];
  graph: AttackGraphResponse;
  timeline: TimelineItem[];
}

export interface IncidentAlertsResponse {
  incident_id: number;
  items: Alert[];
  total: number;
}

export interface UpdateIncidentStatusPayload {
  status: IncidentStatus;
  resolution_note?: string;
}

export interface CorrelateIncidentsResponse {
  correlated_incidents_count: number;
  incident_ids: number[];
}
