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

export type FindingReviewState =
  | "UNREVIEWED"
  | "UNDER_REVIEW"
  | "ACCEPTED"
  | "REJECTED"
  | "DISPUTED"
  | "NEEDS_MORE_EVIDENCE";

export type EvidenceMatrixStatus =
  | "SUPPORTED"
  | "WEAKLY_SUPPORTED"
  | "CONTRADICTED"
  | "INSUFFICIENT"
  | "UNRESOLVED";

export type EvidenceItemResolution =
  | "RESOLVED"
  | "MISSING"
  | "UNRESOLVED"
  | "UNAVAILABLE";

export interface EvidenceMatrixItem {
  citation_tag: string;
  source_type: string;
  source_id: string;
  resolution_status: EvidenceItemResolution;
  summary?: string;
  epistemic_status: string;
}

export interface EvidenceMatrixEntry {
  hypothesis_id: string;
  statement: string;
  status: EvidenceMatrixStatus;
  supporting_evidence: EvidenceMatrixItem[];
  contradicting_evidence: EvidenceMatrixItem[];
  evidence_gaps: string[];
  resolved_support_count: number;
  unresolved_support_count: number;
  assessment_rationale: string;
}

export interface EvidenceGapAction {
  gap_id: string;
  case_id: number;
  gap_type: string;
  description: string;
  suggested_action: string;
  reason: string;
  evidence_requirement: string;
  execution_nature: "ANALYST_CONTROLLED";
  target_entity?: string | null;
  target_time_window?: string | null;
  suggested_query_template_id?: string | null;
  suggested_parameters?: Record<string, any>;
  governance_notice: string;
}

export type RefinedTimelineSourceType =
  | "OBSERVED_EVENT"
  | "DETECTION"
  | "ALERT"
  | "INCIDENT"
  | "CORRELATION"
  | "FINDING"
  | "ANALYST_NOTE"
  | "HYPOTHESIS"
  | "THREAT_HUNT_RESULT"
  | "AI_INTERPRETATION";

export interface RefinedTimelineItem {
  item_id: string;
  case_id: number;
  timestamp: string;
  source_type: RefinedTimelineSourceType;
  source_id: string;
  title: string;
  summary: string;
  epistemic_status: EpistemicStatus | string;
  is_authoritative: boolean;
  citation_tag?: string | null;
  provenance: string;
  metadata?: Record<string, any>;
}

export interface CaseBriefing {
  case_id: number;
  incident_id: number;
  case_title: string;
  scope_summary: Record<string, any>;
  observed_metrics: Record<string, number>;
  key_findings_summary: Array<Record<string, any>>;
  correlations_narrative: string;
  evidence_gaps_summary: Array<Record<string, any>>;
  hypotheses_evidence_states: Array<Record<string, any>>;
  recommended_next_actions: EvidenceGapAction[];
  generated_at: string;
  generated_by: string;
  governance_classification: string;
}

export interface ProvenanceManifestEntry {
  entry_id: string;
  section: string;
  source_type: string;
  source_id: string;
  source_hash_or_reference: string;
  epistemic_status: string;
  is_authoritative: boolean;
  generated_by: string;
  generated_at: string;
  case_id: number;
}

export interface CaseInvestigationDossier {
  case_id: number;
  incident_id: number;
  case_title: string;
  status: string;
  owner: string;
  created_at: string;
  scope: Record<string, any>;
  findings: Array<Record<string, any>>;
  evidence_summary: Record<string, any>;
  timeline: RefinedTimelineItem[];
  entities: Array<Record<string, any>>;
  correlations: Array<Record<string, any>>;
  evidence_gaps: EvidenceGapAction[];
  hypotheses: Array<Record<string, any>>;
  evidence_matrix: EvidenceMatrixEntry[];
  threat_hunting_results: Array<Record<string, any>>;
  attack_path: Array<Record<string, any>>;
  mitre_techniques: Array<Record<string, any>>;
  analyst_notes: Array<Record<string, any>>;
  ai_interpretation?: Record<string, any> | null;
  review_state_summary: Record<string, number>;
  provenance_manifest: ProvenanceManifestEntry[];
  generated_at: string;
}

export interface FindingReviewUpdateRequest {
  review_state: FindingReviewState;
  analyst_notes?: string;
  reviewer?: string;
}

export interface ReportDraftRequest {
  title?: string;
  analyst_notes?: string;
  is_final?: boolean;
  actor?: string;
}

// ============================================================================
// Milestone 5.8: Investigation Graph & Evidence Relationship Intelligence
// ============================================================================

export type GraphNodeType =
  | "HOST"
  | "USER"
  | "IP"
  | "PROCESS"
  | "COMMAND"
  | "FILE"
  | "SESSION"
  | "DOMAIN"
  | "CONTAINER"
  | "EVENT"
  | "DETECTION"
  | "ALERT"
  | "INCIDENT"
  | "FINDING";

export type RelationshipEpistemicStatus = "OBSERVED" | "INFERRED" | "UNKNOWN";

export type CorroborationStatus =
  | "DIRECT_EVIDENCE"
  | "CORROBORATED"
  | "SINGLE_SOURCE"
  | "TEMPORALLY_ALIGNED"
  | "CONTRADICTED"
  | "INSUFFICIENT_EVIDENCE"
  | "UNRESOLVED";

export type TemporalRelation =
  | "BEFORE"
  | "DURING"
  | "AFTER"
  | "OVERLAPS"
  | "CO_OCCURRED"
  | "SEQUENCE";

export type PathNature = "OBSERVED" | "INFERRED" | "MIXED";

export interface GraphEvidenceItem {
  reference_id: string;
  source_type: string;
  source_id: string;
  source_hash: string;
  citation_tag: string;
  timestamp?: string | null;
  summary: string;
  epistemic_status: EpistemicStatus;
  is_authoritative: boolean;
  role: string;
}

export interface InvestigationGraphNode {
  node_id: string;
  node_type: GraphNodeType;
  display_label: string;
  entity_key?: string | null;
  is_authoritative: boolean;
  epistemic_status: EpistemicStatus;
  source_reference?: string | null;
  metadata?: Record<string, any>;
  first_seen?: string | null;
  last_seen?: string | null;
  degree: number;
}

export interface InvestigationGraphEdge {
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  epistemic_status: RelationshipEpistemicStatus;
  is_authoritative: boolean;
  corroboration_status: CorroborationStatus;
  evidence_references: GraphEvidenceItem[];
  evidence_event_ids: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  duration_seconds?: number | null;
  temporal_relation?: TemporalRelation | null;
  mitre_technique_id?: string | null;
  mitre_tactic?: string | null;
  description: string;
  provenance: string;
}

export interface InvestigationGraph {
  case_id: number;
  incident_id: number;
  nodes: InvestigationGraphNode[];
  edges: InvestigationGraphEdge[];
  total_nodes: number;
  total_edges: number;
  observed_edges_count: number;
  inferred_edges_count: number;
  corroborated_edges_count: number;
  contradicted_edges_count: number;
  generated_at: string;
}

export interface InvestigationPath {
  path_id: string;
  case_id: number;
  source_node_id: string;
  target_node_id: string;
  nodes: InvestigationGraphNode[];
  edges: InvestigationGraphEdge[];
  total_steps: number;
  path_nature: PathNature;
  evidence_references_count: number;
  total_duration_seconds?: number | null;
  summary: string;
}

export interface TemporalChainStep {
  step_index: number;
  timestamp: string;
  edge_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  delta_seconds_from_previous?: number | null;
  evidence_citation: string;
  epistemic_status: RelationshipEpistemicStatus;
}

export interface TemporalChain {
  case_id: number;
  steps: TemporalChainStep[];
  total_steps: number;
  start_time?: string | null;
  end_time?: string | null;
  total_span_seconds?: number | null;
}

export interface EntityPivotGraph {
  entity_key: string;
  entity_type: string;
  case_id: number;
  connected_nodes: InvestigationGraphNode[];
  connected_edges: InvestigationGraphEdge[];
  related_alerts_count: number;
  related_events_count: number;
  related_findings_count: number;
  timeline_occurrences_count: number;
}

export interface GraphExplanationRequest {
  edge_id?: string | null;
  path_nodes?: string[] | null;
  question?: string | null;
  include_evidence_citations?: boolean;
}

export interface GraphExplanationResponse {
  explanation_id: string;
  case_id: number;
  target_ref: string;
  summary: string;
  evidence_citations: string[];
  epistemic_status: EpistemicStatus;
  is_authoritative: boolean;
  generated_by: string;
  generated_at: string;
}

// =============================================================================
// Milestone 5.9: Evidence Correlation Intelligence & Decision Support Types
// =============================================================================

export type CorrelationReason =
  | "SHARED_ENTITY"
  | "SHARED_SESSION"
  | "SHARED_PROCESS"
  | "SHARED_SOURCE_IP"
  | "SHARED_DESTINATION_IP"
  | "SHARED_INCIDENT"
  | "SHARED_DETECTION"
  | "TEMPORAL_PROXIMITY"
  | "EXPLICIT_RELATIONSHIP"
  | "DIRECT_EVIDENCE_LINK"
  | "BEHAVIORAL_SEQUENCE";

export interface CorrelationReasonItem {
  reason_type: CorrelationReason;
  description: string;
  dimension_value?: string | null;
  correlation_basis: string;
}

export interface EvidenceCluster {
  cluster_id: string;
  case_id: number;
  title: string;
  summary: string;
  cluster_type: string;
  correlation_reasons: CorrelationReasonItem[];
  temporal_bounds: {
    start_time?: string | null;
    end_time?: string | null;
    duration_seconds?: string | null;
  };
  participating_entities: string[];
  evidence_references: GraphEvidenceItem[];
  evidence_event_ids: string[];
  epistemic_status: EpistemicStatus;
  corroboration_status: CorroborationStatus;
  contradictions: string[];
  gaps: string[];
  created_at: string;
}

export interface BehavioralSequenceStep {
  step_index: number;
  timestamp: string;
  stage_name: string;
  action_summary: string;
  actor_entity: string;
  target_entity: string;
  evidence_citation: string;
  epistemic_status: EpistemicStatus;
}

export interface BehavioralSequence {
  sequence_id: string;
  case_id: number;
  pattern_name: string;
  description: string;
  steps: BehavioralSequenceStep[];
  total_steps: number;
  epistemic_status: EpistemicStatus;
  supporting_evidence_count: number;
  start_time?: string | null;
  end_time?: string | null;
  duration_seconds?: number | null;
}

export interface HypothesisSupportDetail {
  hypothesis_id: string;
  case_id: number;
  statement: string;
  support_status: string;
  supporting_evidence: GraphEvidenceItem[];
  contradicting_evidence: GraphEvidenceItem[];
  contextual_evidence: GraphEvidenceItem[];
  missing_evidence_descriptions: string[];
  unresolved_questions: string[];
  recommended_governed_queries: QueryProposal[];
}

export interface EvidenceGapDetail {
  gap_id: string;
  case_id: number;
  gap_type: string;
  title: string;
  description: string;
  affected_entities: string[];
  affected_hypotheses: string[];
  resolution_remedy: string;
  recommended_governed_query?: QueryProposal | null;
  status: string;
}

export interface EntityWorkbenchDossier {
  case_id: number;
  entity_key: string;
  entity_type: string;
  display_name: string;
  related_clusters: EvidenceCluster[];
  related_findings: Array<Record<string, any>>;
  related_sequences: BehavioralSequence[];
  adjacent_graph_entities: string[];
  evidence_references: GraphEvidenceItem[];
  identified_gaps: EvidenceGapDetail[];
  mitre_techniques: Array<Record<string, any>>;
}

export interface CorrelationExplanationRequest {
  cluster_id?: string | null;
  sequence_id?: string | null;
  question?: string | null;
}

export interface CorrelationExplanationResponse {
  explanation_id: string;
  case_id: number;
  target_cluster_id?: string | null;
  summary: string;
  reasoning_explanation: string;
  supporting_citations: string[];
  identified_unknowns: string[];
  epistemic_status: EpistemicStatus;
  is_authoritative: boolean;
  generated_by: string;
  generated_at: string;
}

// =============================================================================
// Milestone 5.10: Temporal Investigation Reconstruction & Campaign Correlation
// =============================================================================

export type EpisodeType =
  | "AUTHENTICATION_BURST"
  | "PROCESS_EXECUTION_EPISODE"
  | "PRIVILEGE_CHANGE_EPISODE"
  | "LATERAL_MOVEMENT_EPISODE"
  | "NETWORK_ACTIVITY_EPISODE"
  | "PERSISTENCE_EPISODE"
  | "GENERIC_EPISODE";

export type TransitionType =
  | "USER_TO_HOST"
  | "HOST_TO_HOST"
  | "USER_TO_PROCESS"
  | "PROCESS_TO_NETWORK_DESTINATION"
  | "PROCESS_TO_FILE"
  | "ALERT_TO_INCIDENT"
  | "INCIDENT_TO_ENTITY"
  | "STAGE_PROGRESSION"
  | "SESSION_HANDOFF";

export type TemporalGapType =
  | "NO_TELEMETRY"
  | "MISSING_HOST_VISIBILITY"
  | "MISSING_PROCESS_TELEMETRY"
  | "MISSING_NETWORK_TELEMETRY"
  | "TIMESTAMP_GAP"
  | "UNRESOLVED_TRANSITION"
  | "INSUFFICIENT_EVIDENCE";

export type CampaignCorrelationStatus =
  | "POTENTIALLY_RELATED"
  | "CORRELATED"
  | "INSUFFICIENT_EVIDENCE"
  | "UNRELATED";

export type CampaignRelationReason =
  | "SHARED_ENTITY"
  | "SHARED_ACCOUNT"
  | "SHARED_SOURCE"
  | "SHARED_DESTINATION"
  | "TEMPORAL_PROXIMITY"
  | "COMMON_SEQUENCE"
  | "COMMON_EVIDENCE"
  | "COMMON_TECHNIQUE";

export type TransitionReviewState = "UNREVIEWED" | "ACCEPTED" | "REJECTED" | "DISPUTED";

export type ContinuityType =
  | "SAME_ACCOUNT_ACROSS_HOSTS"
  | "SAME_PROCESS_LINEAGE"
  | "SAME_SOURCE_IP"
  | "SAME_DESTINATION"
  | "SAME_ENTITY_MULTIPLE_INCIDENTS";

export interface TemporalEpisode {
  episode_id: string;
  case_id: number;
  episode_type: EpisodeType;
  title: string;
  summary: string;
  start_time: string;
  end_time: string;
  duration_seconds: number;
  entities: string[];
  evidence_references: GraphEvidenceItem[];
  evidence_event_ids: string[];
  epistemic_status: EpistemicStatus;
  corroboration_status: string;
}

export interface TemporalTransition {
  transition_id: string;
  case_id: number;
  transition_type: TransitionType;
  from_entity: string;
  to_entity: string;
  from_episode_id?: string | null;
  to_episode_id?: string | null;
  timestamp: string;
  reason: string;
  correlation_basis: string;
  evidence_references: GraphEvidenceItem[];
  epistemic_status: EpistemicStatus;
  review_state: TransitionReviewState;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  review_notes?: string | null;
}

export interface EvidenceChainStep {
  step_index: number;
  source_record_type: string;
  source_record_id: string;
  citation_tag: string;
  timestamp: string;
  entity_key: string;
  action_or_relation: string;
  epistemic_status: EpistemicStatus;
}

export interface TemporalEvidenceChain {
  chain_id: string;
  case_id: number;
  name: string;
  description: string;
  steps: EvidenceChainStep[];
  total_steps: number;
  start_time: string;
  end_time: string;
  epistemic_status: EpistemicStatus;
}

export interface TemporalGap {
  gap_id: string;
  case_id: number;
  gap_type: TemporalGapType;
  title: string;
  description: string;
  affected_entities: string[];
  start_time?: string | null;
  end_time?: string | null;
  duration_seconds?: number | null;
  remedy: string;
  governed_hunt_proposal?: QueryProposal | null;
}

export interface MultiHostTrace {
  trace_id: string;
  case_id: number;
  source_host: string;
  target_host: string;
  actor: string;
  hop_count: number;
  transitions: TemporalTransition[];
  evidence_references: GraphEvidenceItem[];
  start_time: string;
  end_time: string;
  epistemic_status: EpistemicStatus;
}

export interface EntityContinuity {
  continuity_id: string;
  case_id: number;
  continuity_type: ContinuityType;
  entity_key: string;
  occurrences_count: number;
  participating_hosts: string[];
  evidence_references: GraphEvidenceItem[];
  description: string;
}

export interface IncidentCampaignCorrelation {
  correlation_id: string;
  primary_incident_id: number;
  related_incident_id: number;
  related_incident_title: string;
  relationship_reason: CampaignRelationReason;
  correlation_status: CampaignCorrelationStatus;
  shared_entities: string[];
  shared_evidence_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
  epistemic_status: EpistemicStatus;
  summary: string;
}

export interface AttackSequenceStep {
  step_number: number;
  timestamp: string;
  stage_name: string;
  entity: string;
  evidence_citation: string;
  reason: string;
  epistemic_status: EpistemicStatus;
  mitre_technique_id?: string | null;
  mitre_technique_name?: string | null;
  rule_id?: string | null;
}

export interface AttackSequenceReconstruction {
  sequence_id: string;
  case_id: number;
  name: string;
  description: string;
  steps: AttackSequenceStep[];
  total_steps: number;
  start_time: string;
  end_time: string;
  duration_seconds: number;
  epistemic_status: EpistemicStatus;
}

export interface TemporalReconstructionDossier {
  reconstruction_id: string;
  case_id: number;
  incident_id: number;
  generated_at: string;
  start_time?: string | null;
  end_time?: string | null;
  duration_seconds: number;
  episodes: TemporalEpisode[];
  transitions: TemporalTransition[];
  evidence_chains: TemporalEvidenceChain[];
  gaps: TemporalGap[];
  multi_host_traces: MultiHostTrace[];
  continuities: EntityContinuity[];
  campaign_correlations: IncidentCampaignCorrelation[];
  attack_sequences: AttackSequenceReconstruction[];
  mitre_summary: Array<Record<string, any>>;
  provenance_hash: string;
}

export interface TemporalExplanationResponse {
  explanation_id: string;
  case_id: number;
  target_id: string;
  explanation_text: string;
  is_authoritative: boolean;
  generated_by: string;
  referenced_citations: string[];
  epistemic_status: EpistemicStatus;
  generated_at: string;
}

// -------------------------------------------------------------
// M5.11 Analyst Decision Intelligence & Case Assessment Types
// -------------------------------------------------------------

export type EvidenceSufficiencyState =
  | "SUFFICIENT"
  | "PARTIALLY_SUFFICIENT"
  | "INSUFFICIENT"
  | "UNKNOWN";

export type ClosureReadinessState =
  | "READY"
  | "NOT_READY"
  | "READY_WITH_LIMITATIONS"
  | "UNKNOWN";

export type AssessmentState = "DRAFT" | "REVIEWED" | "FINAL";

export type QuestionStatus =
  | "OPEN"
  | "INVESTIGATING"
  | "ANSWERED"
  | "UNRESOLVED"
  | "NOT_APPLICABLE";

export type QuestionCategory =
  | "AUTHENTICATION"
  | "EXECUTION"
  | "LATERAL_MOVEMENT"
  | "PERSISTENCE"
  | "DATA_EXFILTRATION"
  | "TEMPORAL_GAP"
  | "IDENTITY_CONTINUITY"
  | "HOST_ATTRIBUTION"
  | "AUTHORIZATION";

export type GapPriority = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

export interface StructuredFinding {
  finding_id: string;
  case_id: number;
  title: string;
  description: string;
  epistemic_status: EpistemicStatus;
  severity: string;
  evidence_references: string[];
  supporting_references: string[];
  contradicting_references: string[];
  related_entities: string[];
  related_events: string[];
  related_incidents: number[];
  related_sequences: string[];
  mitre_references: string[];
  review_state: FindingReviewState;
  provenance: Record<string, any>;
}

export interface CompetingHypothesisAssessment {
  hypothesis_id: string;
  statement: string;
  status: string;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  evidence_gaps: string[];
  determination: "SUPPORTING" | "CONTRADICTING" | "UNRESOLVED";
  analyst_assessment?: string | null;
  epistemic_status: EpistemicStatus;
}

export interface InvestigationQuestion {
  question_id: string;
  case_id: number;
  question: string;
  category: QuestionCategory;
  status: QuestionStatus;
  related_evidence: string[];
  related_entities: string[];
  recommended_query?: string | null;
  created_at: string;
  resolved_at?: string | null;
  resolution_notes?: string | null;
}

export interface PrioritizedEvidenceGap {
  gap_id: string;
  title: string;
  gap_type: string;
  affected_area: string;
  priority: GapPriority;
  explanation: string;
  remedy: string;
  related_entities: string[];
}

export interface CaseConclusion {
  statement: string;
  epistemic_status: EpistemicStatus;
  supporting_evidence: string[];
  contradicting_evidence: string[];
  limitations: string[];
  unknowns: string[];
}

export interface EvidenceSufficiencyAssessment {
  status: EvidenceSufficiencyState;
  rationale: string;
  existing_evidence: string[];
  missing_evidence: string[];
  contradicting_evidence: string[];
  next_useful_evidence: string[];
}

export interface ClosureReadinessAssessment {
  status: ClosureReadinessState;
  summary: string;
  blocking_factors: string[];
  warnings: string[];
  recommendations: string[];
}

export interface CaseAssessment {
  case_id: number;
  assessment_id: string;
  assessment_version: number;
  created_at: string;
  updated_at: string;
  case_state: string;
  evidence_state: EvidenceSufficiencyState;
  assessment_state: AssessmentState;
  epistemic_summary: Record<string, number>;
  key_findings: StructuredFinding[];
  supporting_evidence: string[];
  contradicting_evidence: string[];
  evidence_gaps: PrioritizedEvidenceGap[];
  hypotheses: CompetingHypothesisAssessment[];
  questions: InvestigationQuestion[];
  evidence_sufficiency: EvidenceSufficiencyAssessment;
  attack_sequence_summary: string[];
  affected_entities: string[];
  affected_hosts: string[];
  mitre_summary: Array<Record<string, any>>;
  analyst_assessment: string;
  closure_readiness: ClosureReadinessAssessment;
  conclusion: CaseConclusion;
  provenance: Record<string, any>;
}

export interface InvestigationBriefing {
  briefing_id: string;
  case_id: number;
  assessment_id: string;
  sections: Record<string, string>;
  briefing_text: string;
  closure_readiness: ClosureReadinessState;
  evidence_sufficiency: EvidenceSufficiencyState;
  generated_at: string;
  provenance_hash: string;
}

export interface CaseHandoffPackage {
  handoff_id: string;
  case_id: number;
  created_at: string;
  operator: string;
  case_summary: string;
  current_state: string;
  key_findings: string[];
  open_questions: string[];
  evidence_gaps: string[];
  hypotheses: string[];
  affected_entities: string[];
  analyst_assessment: string;
  required_next_actions: string[];
  report_versions: number[];
  provenance_manifest: Record<string, any>;
}

export interface AssessmentExplanationResponse {
  explanation_id: string;
  case_id: number;
  target_id: string;
  explanation_text: string;
  is_authoritative: boolean;
  generated_by: string;
  referenced_citations: string[];
  epistemic_status: EpistemicStatus;
  generated_at: string;
}

// ----------------------------------------------------------------------------
// M7.2 Unified Investigation Timeline & Interactive Evidence Replay
// ----------------------------------------------------------------------------

export type TimestampPrecision = "SECOND" | "MILLISECOND" | "UNKNOWN";

export type CollectionStatus =
  | "SOURCE_AVAILABLE"
  | "SOURCE_UNAVAILABLE"
  | "RULE_NOT_CONFIGURED"
  | "NO_EVENT_OBSERVED"
  | "TELEMETRY_DROPPED"
  | "UNKNOWN";

export type TimelineSourceLayer =
  | "EVENT"
  | "ALERT"
  | "EVIDENCE"
  | "HOST_TELEMETRY"
  | "INCIDENT"
  | "AUDIT";

export interface InvestigationTimelineItem {
  timeline_id: string;
  case_id: number;
  timestamp: string;
  timestamp_precision: TimestampPrecision;
  host_id: string;
  event_type: string;
  source_layer: TimelineSourceLayer;
  source_id: string;
  entity_refs: string[];
  relationship_refs: string[];
  detection_refs: string[];
  incident_refs: number[];
  evidence_refs: string[];
  epistemic_status: EpistemicStatus;
  collection_status: CollectionStatus;
  display_summary: string;
  provenance: Record<string, any>;
  is_bookmarked?: boolean;
}

export interface TimelineFilterParams {
  start_time?: string;
  end_time?: string;
  host?: string;
  event_type?: string;
  source_layer?: TimelineSourceLayer;
  entity?: string;
  epistemic_status?: EpistemicStatus;
  collection_status?: CollectionStatus;
  search_text?: string;
  limit?: number;
  offset?: number;
}

export interface TimelineReplayFrame {
  frame_index: number;
  timestamp: string;
  item: InvestigationTimelineItem;
  active_entities: string[];
  active_hosts: string[];
  epistemic_status: EpistemicStatus;
}

export interface TimelineReplaySession {
  case_id: number;
  total_frames: number;
  frames: TimelineReplayFrame[];
  session_fingerprint: string;
  deterministic_order: string[];
}

export interface TimelineContextResponse {
  timeline_id: string;
  case_id: number;
  item: InvestigationTimelineItem;
  linked_entities: Array<Record<string, any>>;
  linked_evidence: Array<Record<string, any>>;
  linked_alerts: Array<Record<string, any>>;
  traceable_path: Array<{
    level: string;
    id: string;
    type: string;
    epistemic_status: string;
    details?: string;
  }>;
}

export interface TimelineQueryResponse {
  total: number;
  items: InvestigationTimelineItem[];
  filter_applied: Record<string, any>;
  deterministic_hash: string;
}

// ----------------------------------------------------------------------------
// M7.3 Logical Evidence Collections & Evidence Workbench
// ----------------------------------------------------------------------------

export type EvidenceCollectionStatus = "ACTIVE" | "ARCHIVED";

export interface EvidenceCollectionItem {
  item_id: string;
  collection_id: string;
  case_id: number;
  source_type: string;
  source_id: string;
  role: string;
  epistemic_status: EpistemicStatus;
  collection_status: CollectionStatus;
  citation_tag: string;
  analyst_annotation?: string | null;
  order_index: number;
  added_at: string;
  added_by: string;
  host_id?: string | null;
  event_type?: string | null;
  timestamp?: string | null;
  display_summary?: string | null;
  provenance: Record<string, any>;
}

export interface EvidenceCollection {
  collection_id: string;
  case_id: number;
  name: string;
  description?: string | null;
  status: EvidenceCollectionStatus;
  tags: string[];
  created_at: string;
  updated_at: string;
  created_by: string;
  items_count: number;
  items: EvidenceCollectionItem[];
}

export interface CreateCollectionRequest {
  name: string;
  description?: string;
  tags?: string[];
}

export interface UpdateCollectionRequest {
  name?: string;
  description?: string;
  status?: EvidenceCollectionStatus;
  tags?: string[];
}

export interface AddCollectionItemRequest {
  source_type: string;
  source_id: string;
  role?: string;
  epistemic_status?: EpistemicStatus;
  citation_tag?: string;
  analyst_annotation?: string;
}

export interface UpdateCollectionItemRequest {
  role?: string;
  analyst_annotation?: string;
  order_index?: number;
}

export interface CollectionFilterParams {
  status?: EvidenceCollectionStatus;
  search_text?: string;
  limit?: number;
  offset?: number;
}

export interface WorkbenchFilterParams {
  collection_id?: string;
  source_type?: string;
  epistemic_status?: EpistemicStatus;
  host?: string;
  search_text?: string;
  limit?: number;
  offset?: number;
}

export interface EvidenceWorkbenchResponse {
  case_id: number;
  total_evidence_count: number;
  collections: EvidenceCollection[];
  items: EvidenceCollectionItem[];
  filter_applied: Record<string, any>;
  deterministic_hash: string;
}

// -----------------------------------------------------------------------------
// M7.4 Findings & Hypothesis Workbench Types
// -----------------------------------------------------------------------------

export type FindingReviewStatus = "UNREVIEWED" | "ACCEPTED" | "REJECTED" | "DISPUTED";
export type FindingLifecycleStatus = "DRAFT" | "ACTIVE" | "ARCHIVED";
export type HypothesisLifecycleStatus = "OPEN" | "SUPPORTED" | "WEAKENED" | "DISPUTED" | "INCONCLUSIVE" | "REJECTED";
export type EvidenceGapType = "AUDIT_RULE_NOT_CONFIGURED" | "SOURCE_UNAVAILABLE" | "NO_EVENT_OBSERVED" | "TELEMETRY_DROPPED" | "UNKNOWN";
export type FindingEvidenceRole = "SUPPORTING" | "CONTRADICTING" | "CONTEXTUAL" | "TEMPORAL" | "CORROBORATING";

export interface FindingEvidenceReference {
  reference_id: string;
  source_type: string;
  source_id: string;
  citation_tag: string;
  role: FindingEvidenceRole;
  epistemic_status: EpistemicStatus;
  collection_id?: string | null;
  analyst_note?: string | null;
  host?: string | null;
  timestamp?: string | null;
  added_at: string;
  provenance_hash?: string | null;
}

export interface FindingVersion {
  version: number;
  title: string;
  statement: string;
  epistemic_status: EpistemicStatus;
  updated_at: string;
  updated_by: string;
  change_summary: string;
}

export interface Finding {
  finding_id: string;
  case_id: number;
  title: string;
  statement: string;
  epistemic_status: EpistemicStatus;
  review_status: FindingReviewStatus;
  lifecycle_status: FindingLifecycleStatus;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  supporting_evidence: FindingEvidenceReference[];
  contradicting_evidence: FindingEvidenceReference[];
  supporting_collections: string[];
  related_hypotheses: string[];
  contradicting_hypotheses: string[];
  analyst_notes?: string | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  version: number;
  version_history: FindingVersion[];
  created_at: string;
  updated_at: string;
  created_by: string;
  provenance: Record<string, any>;
}

export interface EvidenceGapM74 {
  gap_id: string;
  gap_type: EvidenceGapType;
  description: string;
  expected_source: string;
  affected_hypotheses: string[];
  detected_at?: string | null;
}

export interface HypothesisAssessmentView {
  hypothesis_id: string;
  case_id: number;
  title: string;
  statement: string;
  status: HypothesisLifecycleStatus;
  version: number;
  supporting_evidence: FindingEvidenceReference[];
  contradicting_evidence: FindingEvidenceReference[];
  evidence_gaps: EvidenceGapM74[];
  relevant_collections: string[];
  supporting_findings: string[];
  contradicting_findings: string[];
  analyst_assessment?: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface HypothesisComparisonItem {
  hypothesis_id: string;
  title: string;
  statement: string;
  status: HypothesisLifecycleStatus;
  supporting_count: number;
  contradicting_count: number;
  gaps_count: number;
  supporting_evidence_ids: string[];
  contradicting_evidence_ids: string[];
  gap_descriptions: string[];
  analyst_assessment?: string | null;
}

export interface HypothesisComparisonResponse {
  case_id: number;
  hypotheses: HypothesisComparisonItem[];
  total_hypotheses: number;
  generated_at: string;
}

export interface FindingsWorkbenchResponse {
  case_id: number;
  findings: Finding[];
  hypotheses: HypothesisAssessmentView[];
  evidence_gaps: EvidenceGapM74[];
  total_findings: number;
  total_hypotheses: number;
  total_gaps: number;
}

// ============================================================================
// M7.5 Advanced Threat Hunting & Governed Analyst Queries Types
// ============================================================================

export type HuntIntent =
  | "PROCESS_EXECUTION"
  | "AUTHENTICATION_ACTIVITY"
  | "PRIVILEGE_ESCALATION"
  | "NETWORK_CONNECTION"
  | "FILE_ACTIVITY"
  | "PERSISTENCE"
  | "SYSTEMD_SERVICE_ACTIVITY"
  | "CONTAINER_ACTIVITY"
  | "USER_SESSION"
  | "CROSS_HOST_ACTIVITY"
  | "IOC_LOOKUP"
  | "ENTITY_ACTIVITY"
  | "TEMPORAL_SEQUENCE"
  | "CORRELATION";

export type QueryOperator =
  | "equals"
  | "not_equals"
  | "contains"
  | "prefix"
  | "suffix"
  | "in"
  | "not_in"
  | "exists"
  | "range"
  | "before"
  | "after"
  | "between";

export type HuntApprovalState =
  | "DRAFT"
  | "VALIDATED"
  | "READY"
  | "APPROVED"
  | "EXECUTING"
  | "COMPLETED"
  | "REJECTED";

export type HuntExecutionStatus =
  | "PENDING"
  | "RUNNING"
  | "MATCHED"
  | "NO_MATCH"
  | "RESOURCE_LIMIT_EXCEEDED"
  | "INVALID_QUERY"
  | "UNAUTHORIZED"
  | "SOURCE_UNAVAILABLE"
  | "RULE_NOT_CONFIGURED"
  | "TELEMETRY_DROPPED"
  | "EXECUTION_FAILED";

export type EpistemicStatusM75 = "OBSERVED" | "INFERRED" | "UNKNOWN";

export interface FieldFilter {
  field: string;
  operator: QueryOperator;
  value: any;
}

export interface EntityFilter {
  entity_type: string;
  entity_value: string;
}

export interface TemporalWindow {
  anchor_timestamp: string;
  relative_window_minutes?: number;
  direction?: "before" | "after" | "around";
}

export interface HuntResourceBounds {
  max_result_count: number;
  max_time_window_days: number;
  max_query_complexity: number;
  max_pagination_offset: number;
  max_evidence_size_bytes: number;
  max_execution_duration_sec: number;
}

export interface GovernedQueryModel {
  hunt_id?: string | null;
  case_id: number;
  intent: HuntIntent;
  question: string;
  scope?: Record<string, any>;
  temporal_window?: TemporalWindow | null;
  source_types: string[];
  entity_filters: EntityFilter[];
  field_filters: FieldFilter[];
  ordering_field?: string;
  ordering_direction?: "ASC" | "DESC";
  limit: number;
  offset: number;
  requested_pivots: string[];
}

export interface HuntQueryPreview {
  case_id: number;
  intent: HuntIntent;
  question: string;
  validation_status: "VALID" | "INVALID";
  filter_count: number;
  source_layers: string[];
  preview_sql_summary: string;
  resource_limits: HuntResourceBounds;
  estimated_complexity: number;
  requires_approval: boolean;
  notes: string[];
}

export interface HuntResultItem {
  result_id: string;
  source_type: string;
  source_id: string;
  citation_tag: string;
  host: string;
  timestamp: string;
  summary: string;
  action: string;
  outcome: string;
  username?: string | null;
  src_ip?: string | null;
  dst_ip?: string | null;
  process_name?: string | null;
  epistemic_status: EpistemicStatusM75;
  raw_preview: string;
  provenance_hash: string;
}

export interface HuntExecutionResult {
  hunt_id: string;
  case_id: number;
  intent: HuntIntent;
  question: string;
  status: HuntExecutionStatus;
  approval_state: HuntApprovalState;
  approved_by?: string | null;
  executed_by?: string | null;
  executed_at: string;
  duration_ms: number;
  result_count: number;
  total_matches: number;
  is_truncated: boolean;
  resource_limit_exceeded: boolean;
  results: HuntResultItem[];
  query_fingerprint: string;
  provenance_manifest: Record<string, any>;
}

export interface HuntSequenceStep {
  step_number: number;
  name: string;
  action_type: string;
  field_filters: FieldFilter[];
  max_time_delta_seconds?: number;
}

export interface HuntSequenceProposal {
  case_id: number;
  sequence_name: string;
  description: string;
  steps: HuntSequenceStep[];
}

export interface HuntSequenceStepEvaluation {
  step_number: number;
  name: string;
  action_type: string;
  status: "MATCHED" | "MISSING_TELEMETRY" | "UNOBSERVED";
  matched_event_id?: string | null;
  timestamp?: string | null;
  host?: string | null;
  evidence_summary?: string | null;
}

export interface HuntSequenceResult {
  case_id: number;
  sequence_name: string;
  total_steps: number;
  matched_steps: number;
  missing_steps: number;
  epistemic_classification: EpistemicStatusM75;
  step_evaluations: HuntSequenceStepEvaluation[];
  evaluated_at: string;
}

export interface HuntExportResponse {
  case_id: number;
  hunt_id: string;
  format: string;
  export_content: string;
  exported_at: string;
  fingerprint: string;
  result_count: number;
}

export interface HuntHistoryRecord {
  query_id: string;
  case_id: number;
  query_template_id: string;
  rationale: string;
  executed_by: string;
  executed_at: string;
  result_count: number;
  execution_status: string;
}

// =============================================================================
// M7.6 Investigation Reporting, Evidence Package & Case Handoff Interfaces
// =============================================================================

export type ReportLifecycleStatus =
  | "DRAFT"
  | "REVIEW_READY"
  | "UNDER_REVIEW"
  | "FINALIZED"
  | "SUPERSEDED";

export type ReportContentOrigin =
  | "AUTHORITATIVE_REFERENCE"
  | "ANALYST_AUTHORED"
  | "SYSTEM_GENERATED"
  | "AI_GENERATED_DRAFT"
  | "DERIVED_SUMMARY";

export type HandoffStatus =
  | "NOT_READY"
  | "READY_FOR_HANDOFF"
  | "HANDED_OFF"
  | "ACKNOWLEDGED"
  | "RETURNED_FOR_FOLLOWUP";

export type PackageLifecycleStatus = "CREATING" | "COMPLETED" | "FAILED";

export interface ProvenanceManifestEntry {
  source_type: string;
  source_id: string;
  citation_tag: string;
  epistemic_status: string;
  cryptographic_source_hash: string;
  selection_reason?: string | null;
}

export interface DeterministicProvenanceManifest {
  case_id: number;
  report_id: string;
  report_version: number;
  generated_at: string;
  total_references: number;
  entries: ProvenanceManifestEntry[];
  manifest_blake2b_digest: string;
}

export interface StructuredReport {
  report_id: string;
  case_id: number;
  version: number;
  lifecycle_status: ReportLifecycleStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
  reviewed_by?: string | null;
  reviewed_at?: string | null;

  case_identification: {
    case_id: number;
    title: string;
    incident_id: number;
    owner: string;
    status: string;
    case_version: number;
    created_at: string;
    updated_at: string;
  };
  investigation_scope: {
    hosts: string[];
    users: string[];
    ip_subnets: string[];
    time_window_start?: string | null;
    time_window_end?: string | null;
    boundary_notes?: string | null;
  };
  executive_summary: {
    summary_text: string;
    content_origin: ReportContentOrigin;
    generated_by_model?: string | null;
  };
  investigation_objective: {
    primary_objective: string;
    triggering_indicators: string[];
  };
  evidence_sources: {
    sources_inspected: string[];
    total_telemetry_events_considered: number;
  };
  evidence_collections: {
    collections: Array<Record<string, any>>;
  };
  unified_timeline_summary: {
    milestones: Array<Record<string, any>>;
    earliest_observed_event?: string | null;
    latest_observed_event?: string | null;
  };
  key_findings: {
    findings: Array<Record<string, any>>;
  };
  hypotheses: {
    hypotheses: Array<Record<string, any>>;
  };
  threat_hunting_activity: {
    hunts_executed: Array<Record<string, any>>;
  };
  evidence_correlation: {
    correlated_clusters: Array<Record<string, any>>;
    multi_host_traces: Array<Record<string, any>>;
  };
  case_assessment: {
    assessment_state?: string | null;
    closure_readiness?: string | null;
    analyst_assessment_text?: string | null;
  };
  evidence_gaps: {
    gaps: Array<Record<string, any>>;
  };
  outstanding_questions: {
    questions: Array<Record<string, any>>;
  };
  analyst_interpretation: {
    interpretation_notes: string;
    author: string;
  };
  conclusion: {
    current_conclusion: string;
    requires_further_monitoring: boolean;
  };
  limitations: {
    limitations: string[];
  };
  handoff_notes: {
    handoff_instructions: string;
    recommended_next_actions: string[];
  };
  provenance_manifest: DeterministicProvenanceManifest;
  metadata: {
    report_id: string;
    case_id: number;
    version: number;
    lifecycle_status: ReportLifecycleStatus;
    created_by: string;
    created_at: string;
    updated_at: string;
    reviewed_by?: string | null;
    reviewed_at?: string | null;
    blake2b_fingerprint: string;
  };
}

export interface ReportVersionSummary {
  report_id: string;
  case_id: number;
  version: number;
  title: string;
  lifecycle_status: ReportLifecycleStatus;
  created_by: string;
  created_at: string;
  updated_at: string;
  is_final: boolean;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  blake2b_fingerprint: string;
  references_count: number;
}

export interface ReportComparisonSectionDiff {
  section_name: string;
  status: "IDENTICAL" | "MODIFIED" | "ADDED" | "REMOVED";
  details?: Record<string, any>;
}

export interface ReportComparisonResult {
  case_id: number;
  report_id: string;
  version_older: number;
  version_newer: number;
  compared_at: string;
  differences_count: number;
  section_diffs: ReportComparisonSectionDiff[];
  older_fingerprint: string;
  newer_fingerprint: string;
}

export interface EvidencePackageManifest {
  package_id: string;
  case_id: number;
  report_id: string;
  report_version: number;
  created_by: string;
  created_at: string;
  status: PackageLifecycleStatus;
  schema_version: string;
  generator_version: string;
  included_artifacts: string[];
  source_reference_count: number;
  package_blake2b_digest: string;
}

export interface EvidencePackage {
  manifest: EvidencePackageManifest;
  report_snapshot: StructuredReport;
  artifacts_json: Record<string, any>;
}

export interface CaseHandoffPacket {
  handoff_id: string;
  case_id: number;
  report_id: string;
  report_version: number;
  status: HandoffStatus;
  prepared_by: string;
  prepared_at: string;
  handed_off_to?: string | null;
  handed_off_at?: string | null;
  acknowledged_by?: string | null;
  acknowledged_at?: string | null;
  return_reason?: string | null;
  investigated_scope_summary: string;
  observed_facts_count: number;
  active_hypotheses_count: number;
  evidence_gaps_count: number;
  outstanding_questions: string[];
  recommended_next_actions: string[];
  operational_notes?: string | null;
}

export interface ReportExportResponse {
  case_id: number;
  report_id: string;
  version: number;
  format: string;
  content: string;
  fingerprint: string;
  exported_at: string;
}


