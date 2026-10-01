export type NoteTargetType = "incident" | "event" | "entity" | "alert" | "INCIDENT" | "EVENT" | "ENTITY" | "ALERT";

export interface InvestigationNote {
  id: number;
  incident_id: number;
  author: string;
  content: string;
  created_at: string;
  target_type: NoteTargetType;
  target_id?: string | null;
  is_deleted?: boolean;
  deleted_at?: string | null;
  deleted_by?: string | null;
  deletion_reason?: string | null;
}

export interface InvestigationNoteAudit {
  id: number;
  note_id: number;
  incident_id: number;
  action: "CREATED" | "UPDATED" | "DELETED" | string;
  actor: string;
  content: string;
  target_type: NoteTargetType;
  target_id?: string | null;
  created_at: string;
  action_timestamp: string;
  reason?: string | null;
}

export interface CreateNoteRequest {
  author: string;
  content: string;
  target_type?: NoteTargetType | string;
  target_id?: string | null;
}

export interface EntityPivotSummary {
  entity_key: string;
  entity_type: string;
  display_name?: string;
  label?: string;
  first_seen?: string | null;
  last_seen?: string | null;
  total_events: number;
  total_alerts: number;
  total_incidents: number;
  alert_count?: number;
  incident_count?: number;
  associated_hosts: string[];
  associated_users: string[];
  associated_ips: string[];
  associated_processes: string[];
  associated_commands?: string[];
  related_relationships: Array<Record<string, any>>;
  recent_events: Array<Record<string, any>>;
  alerts: Array<Record<string, any>>;
  incidents?: Array<Record<string, any>>;
  metadata?: Record<string, any>;
}

export type AttackPathStepNature = "OBSERVED" | "INFERRED" | "UNAVAILABLE";

export interface AttackPathNodeInfo {
  id: string;
  label: string;
  entity_type: string;
}

export interface AttackPathStep {
  step_number: number;
  source_node: AttackPathNodeInfo | string;
  target_node: AttackPathNodeInfo | string;
  relationship_type: string;
  stage?: string;
  confidence: string;
  nature: AttackPathStepNature;
  supporting_event_ids?: string[];
  evidence_event_ids?: string[];
  description?: string;
  inference_reason?: string | null;
  derivation_source?: string | null;
  timestamp?: string | null;
}

export interface AttackPathReconstruction {
  incident_id: number;
  steps: AttackPathStep[];
  root_causes?: string[];
  terminal_targets?: string[];
  is_multi_host?: boolean;
  total_steps?: number;
}

export interface MitreMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  rule_id: string;
  rule_name?: string;
  supporting_alert_ids: number[];
  supporting_event_ids?: string[];
  evidence_event_count?: number;
  confidence?: string;
}

export interface EventForensicsNode {
  id: string;
  label: string;
  entity_type: string;
}

export interface EventForensics {
  event_id: string;
  event: Record<string, any>;
  provenance?: {
    source_file?: string | null;
    source_offset?: string | null;
    parser?: string | null;
    event_fingerprint?: string | null;
    raw_message?: string | null;
    timestamp?: string;
    ingested_at?: string;
  };
  detections: Array<Record<string, any>>;
  alerts: Array<Record<string, any>>;
  incidents: Array<Record<string, any>>;
  entities: Array<EventForensicsNode | string>;
  relationships?: Array<Record<string, any>>;
}

export interface ThreatHuntFilter {
  search_text?: string;
  query?: string;
  start_time?: string;
  end_time?: string;
  host?: string;
  username?: string;
  src_ip?: string;
  dst_ip?: string;
  ip?: string;
  process_name?: string;
  process?: string;
  command?: string;
  event_type?: string;
  source?: string;
  severity?: string;
  outcome?: string;
  action?: string;
  rule_id?: string;
  detection_rule?: string;
  alert_id?: number;
  ioc?: string;
  limit?: number;
  offset?: number;
}

export interface ThreatHuntResponse {
  items: Array<Record<string, any>>;
  total?: number;
  total_matches?: number;
  limit?: number;
  offset?: number;
  query_summary?: string;
}

export interface InvestigationDossier {
  incident: Record<string, any>;
  alerts: Array<Record<string, any>>;
  entities: Array<Record<string, any>>;
  relationships: Array<Record<string, any>>;
  timeline: Array<Record<string, any>>;
  attack_path: AttackPathReconstruction;
  mitre_mappings: MitreMapping[];
  notes: InvestigationNote[];
  timeline_total: number;
}

export interface ExportInvestigationResponse {
  incident_id: number;
  format: string;
  content: string;
  filename: string;
}
