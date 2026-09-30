import { CanonicalEvent, Severity } from "./events";

export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED" | "FALSE_POSITIVE";

export type RuleCategory = "AUTH" | "PRIVILEGE" | "PROCESS" | "ACCOUNT" | "NETWORK";

export type RuleType = "ATOMIC" | "THRESHOLD";

export type EvidenceRole = "TRIGGER" | "AGGREGATE" | "CONTEXT";

export interface Alert {
  id: number;
  rule_id: string;
  dedup_key: string;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  host: string;
  first_seen: string;
  last_seen: string;
  occurrence_count: number;
  acknowledged_at?: string | null;
  resolved_at?: string | null;
  resolution_note?: string | null;
}

export interface DetectionEvidenceItem {
  id: number;
  detection_id: number;
  event_id: string;
  role: EvidenceRole;
  matched_at: string;
  event?: CanonicalEvent | null;
}

export interface DetectionRecordItem {
  id: number;
  alert_id: number;
  rule_id: string;
  matched_at: string;
  summary: string;
  details?: Record<string, any>;
  evidence: DetectionEvidenceItem[];
}

export interface AlertDetailResponse {
  alert: Alert;
  detections: DetectionRecordItem[];
}

export interface AlertsQueryResponse {
  items: Alert[];
  total: number;
  limit: number;
  offset: number;
}

export interface DetectionRuleSummary {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: RuleCategory;
  rule_type: RuleType;
  enabled: boolean;
  cooldown_seconds: number;
  conditions_count: number;
}

export interface DetectionRulesQueryResponse {
  items: DetectionRuleSummary[];
  total: number;
}

export interface DetectionRuleDetailResponse {
  rule: {
    id: string;
    name: string;
    description: string;
    severity: Severity;
    category: RuleCategory;
    rule_type: RuleType;
    enabled: boolean;
    conditions: Record<string, any>;
    threshold?: {
      count: number;
      window_seconds: number;
    } | null;
    group_by?: string[] | null;
    cooldown_seconds: number;
    references?: string[];
  };
  yaml_definition: string;
}

export interface AlertQueryParams {
  status?: AlertStatus;
  severity?: Severity;
  host?: string;
  rule_id?: string;
  limit?: number;
  offset?: number;
}

export interface UpdateAlertStatusPayload {
  status: AlertStatus;
  resolution_note?: string;
}
