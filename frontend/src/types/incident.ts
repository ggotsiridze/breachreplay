// Mirrors backend/app/models/domain.py

export type AssetType = 'INTERNET' | 'SERVER' | 'WORKSTATION' | 'DATABASE' | 'IDENTITY' | 'INFRASTRUCTURE' | 'UNKNOWN';
export type AssetState = 'NORMAL' | 'SUSPICIOUS' | 'AFFECTED' | 'CONTAINED' | 'PROTECTED';
export type ConfidenceLabel = 'OBSERVED' | 'SUSPICIOUS' | 'LIKELY' | 'HIGH CONFIDENCE';
export type EdgeState = 'OBSERVED' | 'SUSPICIOUS' | 'ATTACK';
export type EventType =
  | 'external_recon'
  | 'initial_access'
  | 'command_and_control'
  | 'discovery'
  | 'lateral_movement'
  | 'crown_jewel_access'
  | 'exfiltration'
  | 'suspicious_connection';

export type AnalysisStateName =
  | 'UPLOADING'
  | 'VALIDATING'
  | 'RUNNING_ZEEK'
  | 'RUNNING_SURICATA'
  | 'NORMALIZING'
  | 'CORRELATING'
  | 'BUILDING_GRAPH'
  | 'COMPLETE'
  | 'FAILED';

export interface Asset {
  id: string;
  ip: string;
  hostname: string | null;
  display_name: string;
  role: string;
  asset_type: AssetType;
  labels: string[];
  importance: number;
  internal: boolean;
  crown_jewel: boolean;
  crown_jewel_reason: string | null;
  first_seen: number;
  last_seen: number;
  state: AssetState;
  services: string[];
}

export interface ScoreReason {
  signal: string;
  points: number;
  text: string;
}

export interface TechniqueMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  reason: string;
  confidence: number;
  url: string;
}

export interface StateChange {
  asset_id: string;
  from_state: AssetState;
  to_state: AssetState;
}

export interface IncidentEvent {
  id: string;
  timestamp: number;
  end_timestamp: number;
  source_asset_id: string | null;
  destination_asset_id: string | null;
  target_asset_ids: string[];
  event_type: EventType;
  phase: string;
  title: string;
  description: string;
  severity: string;
  confidence: number;
  confidence_label: ConfidenceLabel;
  reasons: ScoreReason[];
  technique_id: string | null;
  technique_name: string | null;
  technique_reason: string | null;
  technique_confidence: number | null;
  technique: TechniqueMapping | null;
  evidence_ids: string[];
  detection_ids: string[];
  protocol: string | null;
  service: string | null;
  destination_port: number | null;
  identity: string | null;
  edge_id: string | null;
  on_primary_path: boolean;
  state_changes: StateChange[];
  tags: string[];
}

export interface IncidentEdge {
  id: string;
  source_asset_id: string;
  destination_asset_id: string;
  first_seen: number;
  last_seen: number;
  protocols: string[];
  services: string[];
  ports: number[];
  event_ids: string[];
  evidence_ids: string[];
  connection_count: number;
  bytes_total: number;
  confidence: number;
  state: EdgeState;
  on_primary_path: boolean;
}

export interface Detection {
  id: string;
  timestamp: number;
  source: 'zeek' | 'suricata';
  signature: string;
  signature_id: string;
  category: string;
  severity: number;
  source_ip: string | null;
  destination_ip: string | null;
  source_port?: number | null;
  destination_port: number | null;
  source_asset_id: string | null;
  destination_asset_id: string | null;
  evidence_ids: string[];
}

export interface IncidentSummary {
  assets_observed: number;
  assets_in_incident: number;
  affected_assets: number;
  suspicious_assets: number;
  high_confidence_events: number;
  incident_events: number;
  critical_detections: number;
  detections: number;
  evidence_records: number;
  crown_jewel_reached: boolean;
  crown_jewel_reached_at: number | null;
  phases: string[];
  techniques: string[];
  identities: string[];
  path_duration_seconds: number | null;
  headline: string;
}

export interface Incident {
  id: string;
  name: string;
  source_type: string;
  demo: boolean;
  showcase: boolean;
  started_at: number | null;
  ended_at: number | null;
  duration_seconds: number;
  capture_started_at: number | null;
  capture_ended_at: number | null;
  assets: Asset[];
  events: IncidentEvent[];
  edges: IncidentEdge[];
  detections: Detection[];
  crown_jewels: string[];
  summary: IncidentSummary;
  primary_attack_path: string[];
  primary_attack_edges: string[];
  incident_found: boolean;
  metadata: Record<string, unknown>;
}

export interface NetworkEvidence {
  id: string;
  timestamp: number;
  source: 'zeek' | 'suricata';
  log_type: string;
  source_record_id: string | null;
  source_asset_id: string | null;
  destination_asset_id: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  service: string | null;
  event_type: string;
  summary: string;
  metadata: Record<string, unknown>;
}

export interface AnalysisStep {
  state: AnalysisStateName;
  label: string;
  status: 'pending' | 'running' | 'done' | 'failed' | 'skipped';
  detail: string | null;
  started_at: number | null;
  finished_at: number | null;
}

export interface AnalysisStatus {
  incident_id: string;
  state: AnalysisStateName;
  steps: AnalysisStep[];
  demo: boolean;
  showcase: boolean;
  filename: string | null;
  error_code: string | null;
  error_title: string | null;
  error_message: string | null;
  error_detail: string | null;
  created_at: number;
  updated_at: number;
  stats: Record<string, unknown>;
}

export type ControlType = 'isolate_asset' | 'block_edge' | 'block_port' | 'block_protocol' | 'segment_assets' | 'disable_identity';
export type Activation = 'preventive' | 'first_detection' | 'custom';

export interface ContainmentControl {
  id?: string | null;
  control_type: ControlType;
  asset_id?: string | null;
  edge_id?: string | null;
  protocol?: string | null;
  port?: number | null;
  identity?: string | null;
  segment_asset_ids?: string[];
  activation?: Activation;
  activation_timestamp?: number | null;
}

export type EventOutcome = 'OCCURRED' | 'INTERRUPTED' | 'NOT_REACHED';

export interface SimulatedEvent {
  event_id: string;
  outcome: EventOutcome;
  blocked_by: string | null;
  reason: string;
  state_changes: StateChange[];
}

export interface ControlActivation {
  control_id: string;
  timestamp: number;
  label: string;
  contained_asset_ids: string[];
}

export interface SimulationMetrics {
  assets_reached: number;
  affected_assets: number;
  crown_jewel_reached: boolean;
  path_complete: boolean;
  path_length: number;
  path_duration_seconds: number | null;
}

export interface SimulationResult {
  id: string;
  incident_id: string;
  controls: ContainmentControl[];
  interrupted_event_id: string | null;
  interrupted_edge_id: string | null;
  interrupted_at: number | null;
  reachable_before: string[];
  reachable_after: string[];
  crown_jewel_before: boolean;
  crown_jewel_after: boolean;
  observed_path_length: number;
  simulated_path_length: number;
  observed_assets_reached: number;
  simulated_assets_reached: number;
  observed: SimulationMetrics;
  simulated: SimulationMetrics;
  event_outcomes: SimulatedEvent[];
  activations: ControlActivation[];
  final_states: Record<string, AssetState>;
  protected_assets: string[];
  contained_assets: string[];
  explanation: string;
  disclaimer: string;
}

export interface ServiceStatus {
  service: string;
  showcase_mode: boolean;
  public_mode: boolean;
  uploads_enabled: boolean;
  max_upload_mb: number;
  analyzers: Record<string, string>;
}

export interface ApiErrorDetail {
  code: string;
  title: string;
  message: string;
}
