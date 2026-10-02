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

// -------------------------------------------------------------------------
// M5.3 AI Investigation Intelligence Types
// -------------------------------------------------------------------------

export type EpistemicStatus = "OBSERVED" | "INFERRED" | "UNKNOWN";
export type EvidenceType = "event" | "alert" | "detection" | "entity" | "relationship" | "mitre_mapping" | "incident" | "timeline_step";
export type EvidenceRole = "PRIMARY" | "SUPPORTING" | "CONTEXTUAL" | "CORROBORATING" | "CONTRADICTING" | "TEMPORAL" | "ENTITY_LINK";
export type InvestigationIntent = "SUMMARY" | "TIMELINE" | "ENTITY_ANALYSIS" | "ALERT_EXPLANATION" | "DETECTION_EXPLANATION" | "ATTACK_PATH_EXPLANATION" | "MITRE_EXPLANATION" | "HYPOTHESIS" | "EVIDENCE_GAP" | "NEXT_QUERY";

export interface CitationRef {
  evidence_type: EvidenceType;
  evidence_id: string;
  citation_tag: string;
}

export interface Claim {
  claim_text: string;
  status: EpistemicStatus;
  evidence_refs: CitationRef[];
  rationale?: string | null;
}

export interface Hypothesis {
  statement: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
  supporting_evidence: CitationRef[];
  contradicting_evidence: CitationRef[];
  rationale?: string | null;
  unknowns: string[];
}

export interface EvidenceConflict {
  conflict_id: string;
  evidence_tag_a: string;
  evidence_tag_b: string;
  conflict_type: string;
  explanation: string;
}

export interface EvidenceGap {
  gap_id: string;
  category: string;
  description: string;
  impact: string;
  suggested_data_source?: string | null;
}

export interface EvidenceCoverage {
  required_evidence_types: string[];
  available_evidence_types: string[];
  missing_evidence_types: string[];
  selected_count: number;
  omitted_count: number;
  truncation_reasons: string[];
}

export interface QueryProposal {
  proposal_id: string;
  title?: string | null;
  intent: string;
  target_entity?: string | null;
  time_range?: string | null;
  event_types: string[];
  source?: string | null;
  filters: Record<string, any>;
  limit: number;
  rationale?: string | null;
  is_executed: boolean;
}

export interface EvidenceItem {
  evidence_id: string;
  evidence_type: EvidenceType;
  source_id: string;
  source_table: string;
  timestamp: string;
  relevance_score: number;
  role: EvidenceRole;
  citation_tag: string;
  summary: string;
  metadata: Record<string, any>;
}

export interface InvestigationEvidenceBundle {
  investigation_id: number;
  generated_at: string;
  items: EvidenceItem[];
  conflicts: EvidenceConflict[];
  gaps: EvidenceGap[];
  coverage: EvidenceCoverage;
  metadata: Record<string, any>;
}

export interface AIInvestigationResponse {
  answer_markdown: string;
  epistemic_status: EpistemicStatus;
  intent: InvestigationIntent;
  claims: Claim[];
  citations: CitationRef[];
  timeline_summary: string[];
  evidence_summary: string[];
  hypotheses: Hypothesis[];
  evidence_gaps: EvidenceGap[];
  conflicts: EvidenceConflict[];
  suggested_query_proposals: QueryProposal[];
  evidence_coverage?: EvidenceCoverage | null;
  suggested_queries: string[];
  identified_unknowns: string[];
  unverified_citations: string[];
  has_unverified_claims: boolean;
  model_identifier?: string | null;
  metadata: Record<string, any>;
}

export interface AIStatusResponse {
  enabled: boolean;
  provider_id: string;
  runtime_healthy: boolean;
  runtime_version?: string | null;
  configured_model: string;
  active_model?: string | null;
  active_model_available: boolean;
  installed_models: string[];
  latency_ms: number;
  error?: string | null;
}

export interface QueryPreviewResponse {
  proposal_id: string;
  intent: string;
  rationale?: string | null;
  executed: boolean;
  is_preview_only: boolean;
  matched_count: number;
  events: Array<Record<string, any>>;
}

export type InvestigationState = "OPEN" | "ACTIVE" | "PAUSED" | "READY_FOR_REVIEW" | "CLOSED";

export interface InvestigationScope {
  investigation_id: number;
  time_start?: string | null;
  time_end?: string | null;
  subject_type: string;
  subject_id: string;
  selected_entity_ids: string[];
  selected_alert_ids: number[];
  selected_detection_ids: number[];
  selected_event_ids: string[];
}

export type HypothesisStatus = "OPEN" | "SUPPORTED" | "WEAKENED" | "UNRESOLVED" | "REJECTED";

export interface AnalystHypothesis {
  hypothesis_id: string;
  investigation_id: number;
  statement: string;
  status: HypothesisStatus;
  supporting_evidence_tags: string[];
  contradicting_evidence_tags: string[];
  evidence_gaps: string[];
  analyst_assessment?: string | null;
  created_at: string;
  updated_at: string;
  created_by: string;
}

export interface InvestigationWorkspace {
  investigation_id: number;
  incident_id: number;
  state: InvestigationState;
  scope: InvestigationScope;
  hypotheses: AnalystHypothesis[];
  evidence_candidates: EvidenceItem[];
  notes: Array<Record<string, any>>;
  state_history: Array<{
    timestamp: string;
    actor: string;
    previous_state: string;
    new_state: string;
    reason?: string | null;
  }>;
  created_at: string;
  updated_at: string;
}

export interface InvestigationSummary {
  investigation_id: number;
  scope: Record<string, any>;
  subject: Record<string, any>;
  key_observations: string[];
  timeline: Array<Record<string, any>>;
  entities: Array<Record<string, any>>;
  detections: Array<Record<string, any>>;
  alerts: Array<Record<string, any>>;
  attack_path: Record<string, any>;
  hypotheses: Array<Record<string, any>>;
  evidence_supporting: Array<Record<string, any>>;
  evidence_contradicting: Array<Record<string, any>>;
  evidence_gaps: Array<Record<string, any>>;
  mitre_context: Array<Record<string, any>>;
  analyst_notes: Array<Record<string, any>>;
  ai_assisted_analysis: Record<string, any>;
  open_questions: string[];
}

export interface ReportDraft {
  report_id: string;
  investigation_id: number;
  generated_at: string;
  title: string;
  executive_summary: string;
  facts: Array<Record<string, any>>;
  inferences: Array<Record<string, any>>;
  hypotheses: Array<Record<string, any>>;
  unknowns: string[];
  recommendations: string[];
  is_draft: boolean;
}

export interface ClaimTrace {
  claim_text: string;
  epistemic_status: string;
  citation_tag: string;
  evidence_type: string;
  evidence_id: string;
  source_table: string;
  source_id: string;
  timestamp?: string | null;
  summary?: string | null;
  raw_evidence?: Record<string, any> | null;
}

// -------------------------------------------------------------
// M5.5 Persistent Case & Investigation Continuity Types
// -------------------------------------------------------------

export type CaseStatus =
  | "OPEN"
  | "ACTIVE"
  | "PAUSED"
  | "READY_FOR_REVIEW"
  | "CLOSED"
  | "ARCHIVED";

export type ResolutionStatus = "AVAILABLE" | "MISSING" | "UNRESOLVED";

export type ContentOrigin = "ANALYST_AUTHORED" | "AI_GENERATED" | "SYSTEM_GENERATED";

export interface CaseEvidenceReference {
  reference_id: string;
  case_id: number;
  source_type: string;
  source_id: string;
  role: string;
  epistemic_status: string;
  citation_tag: string;
  analyst_annotation?: string | null;
  created_at: string;
  resolution_status: ResolutionStatus;
  resolved_record?: Record<string, any> | null;
}

export interface CaseHypothesis {
  hypothesis_id: string;
  case_id: number;
  statement: string;
  status: HypothesisStatus;
  supporting_evidence_tags: string[];
  contradicting_evidence_tags: string[];
  evidence_gaps: string[];
  analyst_assessment?: string | null;
  created_at: string;
  updated_at: string;
  created_by: string;
  version: number;
}

export interface CaseQueryRecord {
  query_id: string;
  case_id: number;
  proposal_id?: string | null;
  query_template_id: string;
  parameters: Record<string, any>;
  rationale?: string | null;
  executed_by: string;
  executed_at: string;
  result_count: number;
  execution_status: string;
  evidence_candidates_count: number;
}

export interface CaseReportVersion {
  report_id: string;
  case_id: number;
  version: number;
  title: string;
  origin: ContentOrigin;
  generated_by: string;
  model_name?: string | null;
  model_digest?: string | null;
  executive_summary: string;
  facts: Array<Record<string, any>>;
  inferences: Array<Record<string, any>>;
  hypotheses: Array<Record<string, any>>;
  unknowns: string[];
  recommendations: string[];
  citation_manifest: Array<Record<string, any>>;
  is_final: boolean;
  created_at: string;
  created_by: string;
}

export interface CaseAuditRecord {
  audit_id?: number;
  case_id: number;
  timestamp: string;
  actor: string;
  action: string;
  previous_value?: string | null;
  new_value?: string | null;
  reason?: string | null;
}

export interface InvestigationCase {
  case_id: number;
  incident_id: number;
  title: string;
  description?: string | null;
  created_at: string;
  updated_at: string;
  created_by: string;
  owner: string;
  status: CaseStatus;
  version: number;
  scope: InvestigationScope;
  hypotheses: CaseHypothesis[];
  evidence_references: CaseEvidenceReference[];
  query_history: CaseQueryRecord[];
  report_versions: CaseReportVersion[];
  audit_history: CaseAuditRecord[];
}

// --- Milestone 5.6: Investigation Intelligence, Threat Hunting & Evidence Correlation ---

export type QueryResultStatus = "NO_MATCH" | "MATCHED" | "PARTIAL" | "UNAVAILABLE" | "INVALID" | "FAILED";
export type TimelineSourceType = "OBSERVED_EVENT" | "ALERT" | "DETECTION" | "ANALYST_ANNOTATION" | "DERIVED_CORRELATION" | "AI_INTERPRETATION";
export type HypothesisSupportStatus = "SUPPORTED_BY_CURRENT_EVIDENCE" | "WEAKLY_SUPPORTED" | "CONTRADICTED" | "INSUFFICIENT_EVIDENCE" | "UNRESOLVED";

export interface InvestigationFinding {
  finding_id: string;
  case_id: number;
  finding_type: string;
  title: string;
  description: string;
  epistemic_status: EpistemicStatus;
  confidence_basis: string;
  source_references: string[];
  related_entities: string[];
  related_alerts: string[];
  related_detections: string[];
  related_events: string[];
  created_at: string;
  generated_by: string;
}

export interface InvestigationCorrelation {
  correlation_id: string;
  case_id: number;
  source_item: string;
  target_item: string;
  reasons: string[];
  confidence_score: number;
  temporal_distance_seconds?: number | null;
  shared_entities: string[];
}

export interface TemporalWindowAnalysis {
  anchor_id: string;
  anchor_type: string;
  anchor_timestamp: string;
  window_seconds: number;
  before_items: Array<Record<string, any>>;
  during_items: Array<Record<string, any>>;
  after_items: Array<Record<string, any>>;
  temporal_anomalies: string[];
  state_contradictions: string[];
}

export interface EvidenceGap {
  gap_id: string;
  case_id: number;
  gap_type: string;
  description: string;
  affected_scope: string[];
  supporting_context: string;
  recommended_query?: Record<string, any> | null;
  status: string;
}

export interface GovernedThreatHuntProposal {
  proposal_id: string;
  case_id: number;
  template_id: string;
  parameters: Record<string, any>;
  rationale: string;
  validation_status: "VALID" | "INVALID";
  validation_errors: string[];
  preview_query_description: string;
  suggested_by: string;
  created_at: string;
}

export interface GovernedThreatHuntExecution {
  case_id: number;
  proposal_id: string;
  template_id: string;
  parameters: Record<string, any>;
  executed_by: string;
  approved_by: string;
  executed_at: string;
  result_status: QueryResultStatus;
  result_count: number;
  matched_items: Array<Record<string, any>>;
  candidate_findings: InvestigationFinding[];
}

export interface EntityPivotAnalysis {
  entity_type: string;
  entity_value: string;
  case_id: number;
  related_events: Array<Record<string, any>>;
  related_alerts: Array<Record<string, any>>;
  related_detections: Array<Record<string, any>>;
  related_incidents: number[];
  related_cases: number[];
  related_entities: Array<Record<string, any>>;
  temporal_activity: Array<Record<string, any>>;
  evidence_references: string[];
}

export interface CaseTimelineItem {
  item_id: string;
  case_id: number;
  timestamp: string;
  source_type: TimelineSourceType;
  title: string;
  summary: string;
  provenance: string;
  citation_tag?: string | null;
  is_authoritative: boolean;
  metadata?: Record<string, any>;
}

export interface HypothesisEvidenceAnalysis {
  hypothesis_id: string;
  case_id: number;
  statement: string;
  support_status: HypothesisSupportStatus;
  supporting_evidence: Array<Record<string, any>>;
  contradicting_evidence: Array<Record<string, any>>;
  evidence_gaps: string[];
  temporal_consistency: boolean;
  entity_consistency: boolean;
  analysis_summary: string;
}

export interface AttackPathStepAnalysis {
  step_number: number;
  stage: string;
  description: string;
  epistemic_status: EpistemicStatus;
  supporting_evidence: string[];
  mitre_technique_id?: string | null;
  mitre_technique_name?: string | null;
}

export interface CaseIntelligenceDossier {
  case_id: number;
  incident_id: number;
  case_title: string;
  status: string;
  owner: string;
  findings: InvestigationFinding[];
  correlations: InvestigationCorrelation[];
  evidence_gaps: EvidenceGap[];
  timeline: CaseTimelineItem[];
  hypotheses_analysis: HypothesisEvidenceAnalysis[];
  attack_path: AttackPathStepAnalysis[];
  mitre_mappings: Array<Record<string, any>>;
  generated_at: string;
}

export interface InvestigationIntelligenceResponse {
  case_id: number;
  summary: string;
  observed_claims: string[];
  inferred_claims: string[];
  unknowns: string[];
  evidence_gaps: string[];
  correlations: string[];
  citations: string[];
  suggested_queries: Array<Record<string, any>>;
  hypothesis_assessment: Record<string, any>;
  provenance: Record<string, any>;
}


